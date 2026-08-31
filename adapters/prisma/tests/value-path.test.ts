/**
 * L1: the value path. What the coverage matrix claims, asserted.
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import {
  FieldsealConfigurationError,
  FieldsealNotSupported,
  FieldsealUnindexable,
  fieldsealExtension,
  tenantScope,
} from "../src/index.ts";
import { fieldsealFieldMap } from "./fixture/generated/fieldseal-map.ts";
import { clearDb, keyProvider, loose, makeClient, rawColumn, setColumn, SUITE } from "./helpers.ts";

const { base, prisma } = makeClient();
const lp = loose(prisma);

beforeEach(async () => {
  await clearDb(base);
});
afterAll(async () => {
  await base.$disconnect();
});

const patient = (over: Record<string, unknown> = {}) => ({
  email: "ada@example.com",
  note: "a note",
  age: 36,
  plainName: "Ada",
  ...over,
});

describe("write then read", () => {
  it("round-trips the plaintext through create and findUnique", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    expect(row.email).toBe("ada@example.com");

    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.email).toBe("ada@example.com");
    expect(back?.note).toBe("a note");
  });

  it("stores an envelope in the database, never the plaintext", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    const stored = await rawColumn(base, "Patient", "email", row.id);

    expect(stored).toBeInstanceOf(Uint8Array);
    const bytes = Buffer.from(stored as Uint8Array);
    expect(bytes.length).toBeGreaterThan("ada@example.com".length);
    expect(bytes.toString("utf8")).not.toContain("ada@example.com");
    expect(bytes.toString("latin1")).not.toContain("ada@example.com");
  });

  it("writes a different envelope every time for the same value (spec §4.4)", async () => {
    // Fresh nonce and msg_seed on every write, including UPDATEs. No test-mode
    // injection is armed, so this exercises the real CSPRNG path.
    const a = await lp["patient"]!["create"]!({ data: patient() });
    const b = await lp["patient"]!["create"]!({ data: patient() });

    const ea = Buffer.from((await rawColumn(base, "Patient", "email", a.id)) as Uint8Array);
    const eb = Buffer.from((await rawColumn(base, "Patient", "email", b.id)) as Uint8Array);
    expect(ea.equals(eb)).toBe(false);
  });

  it("re-encrypts on update, so an UPDATE also gets a fresh envelope", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    const first = Buffer.from((await rawColumn(base, "Patient", "email", row.id)) as Uint8Array);

    await lp["patient"]!["update"]!({
      where: { id: row.id },
      data: { email: "ada@example.com" },
    });
    const second = Buffer.from((await rawColumn(base, "Patient", "email", row.id)) as Uint8Array);

    expect(first.equals(second)).toBe(false);
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.email).toBe("ada@example.com");
  });

  it("accepts the { set: value } update form", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    await lp["patient"]!["update"]!({
      where: { id: row.id },
      data: { note: { set: "replaced" } },
    });
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.note).toBe("replaced");
  });

  it("round-trips a non-ASCII value byte-for-byte", async () => {
    // The codec's UTF-8 choice is an adapter decision no core test can see; an
    // ASCII-only test would pass under a wrong encoding.
    const value = "日本語とEmoji 🔐";
    const row = await lp["patient"]!["create"]!({ data: patient({ note: value }) });
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.note).toBe(value);
  });

  it("treats the empty string as a value, not an absence", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient({ note: "" }) });
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.note).toBe("");
    expect(await rawColumn(base, "Patient", "note", row.id)).not.toBeNull();
  });

  it("encrypts through createMany and updateMany", async () => {
    await lp["patient"]!["createMany"]!({
      data: [patient({ plainName: "A" }), patient({ plainName: "B" })],
    });
    const rows = await prisma.patient.findMany({ orderBy: { plainName: "asc" } });
    expect(rows.map((r) => r.email)).toEqual(["ada@example.com", "ada@example.com"]);

    await lp["patient"]!["updateMany"]!({ where: { plainName: "A" }, data: { note: "bulk" } });
    const a = await prisma.patient.findFirst({ where: { plainName: "A" } });
    expect(a?.note).toBe("bulk");
  });

  it("encrypts a nested relation write reached through the schema", async () => {
    const row = await lp["patient"]!["create"]!({
      data: { ...patient(), visits: { create: [{ reason: "checkup" }] } },
    });
    const withVisits = await prisma.patient.findUnique({
      where: { id: row.id },
      include: { visits: true },
    });
    expect(withVisits?.visits[0]?.reason).toBe("checkup");

    const raw = await rawColumn(base, "Visit", "reason", withVisits!.visits[0]!.id);
    expect(Buffer.from(raw as Uint8Array).toString("utf8")).not.toContain("checkup");
  });
});

describe("undefined in a payload", () => {
  it("touches nothing: not the value, and not the sibling", async () => {
    // Prisma's contract for `undefined` is "do not touch this field". Reading
    // it as NULL would null the sibling while the ciphertext stays -- a
    // desynced index whose every later lookup silently misses.
    const row = await lp["patient"]!["create"]!({ data: patient() });
    const sibBefore = Buffer.from(
      (await rawColumn(base, "Patient", "emailBidx", row.id)) as Uint8Array,
    );
    const envBefore = Buffer.from(
      (await rawColumn(base, "Patient", "email", row.id)) as Uint8Array,
    );

    await lp["patient"]!["update"]!({
      where: { id: row.id },
      data: { email: undefined, note: "still updates other fields" },
    });

    const sibAfter = Buffer.from(
      (await rawColumn(base, "Patient", "emailBidx", row.id)) as Uint8Array,
    );
    const envAfter = Buffer.from(
      (await rawColumn(base, "Patient", "email", row.id)) as Uint8Array,
    );
    expect(sibAfter.equals(sibBefore)).toBe(true);
    expect(envAfter.equals(envBefore)).toBe(true);
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.email).toBe("ada@example.com");
    expect(back?.note).toBe("still updates other fields");
  });
});

describe("every declared `as:` type round-trips as itself", () => {
  it("int comes back as a number", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient({ age: 36 }) });
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.age).toBe(36);
  });

  it("datetime accepts a bare Date and returns a Date", async () => {
    // The natural write form -- not `{ set: … }`. A Date is a value, not an
    // atomic-operation wrapper, and the visitor must not confuse the two.
    const born = new Date("1990-12-02T10:20:30.000Z");
    const row = await lp["patient"]!["create"]!({ data: patient({ born }) });
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.born).toBeInstanceOf(Date);
    expect((back?.born as unknown as Date).getTime()).toBe(born.getTime());
  });

  it("boolean and float come back as themselves", async () => {
    const row = await lp["patient"]!["create"]!({
      data: patient({ active: true, score: 1.5 }),
    });
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.active).toBe(true);
    expect(back?.score).toBe(1.5);
  });

  it("bytes come back byte-for-byte", async () => {
    const blob = Buffer.from([0, 1, 2, 254, 255]);
    const row = await lp["patient"]!["create"]!({ data: patient({ blob }) });
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(Buffer.from(back?.blob as Uint8Array).equals(blob)).toBe(true);
  });

  it("a wrong-typed object gets the codec's refusal, naming the type it saw", async () => {
    // A Date written to an `as: "string"` column is a type mismatch, and the
    // error must say so -- not misread the Date as an arithmetic update.
    await expect(
      lp["patient"]!["create"]!({ data: patient({ note: new Date() }) }),
    ).rejects.toThrow(/declared `as: "string"`/);
  });
});

describe("reaching Patient through the undeclared Referral model", () => {
  it("a nested write is still encrypted", async () => {
    const ref = await lp["referral"]!["create"]!({
      data: { source: "web", patient: { create: patient() } },
    });
    const withPatient = await prisma.referral.findUnique({
      where: { id: ref.id },
      include: { patient: true },
    });
    const raw = await rawColumn(base, "Patient", "email", withPatient!.patient.id);
    expect(Buffer.from(raw as Uint8Array).toString("utf8")).not.toContain("ada@example.com");
  });

  it("an included read is still decrypted", async () => {
    const ref = await lp["referral"]!["create"]!({
      data: { source: "web", patient: { create: patient() } },
    });
    const back = await prisma.referral.findUnique({
      where: { id: ref.id },
      include: { patient: true },
    });
    expect(back?.patient.email).toBe("ada@example.com");
  });
});

describe("a stored value that is not an envelope (spec §10.3)", () => {
  const plantLegacyNickname = async (): Promise<string> => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    // A pre-migration row: the *plaintext* sits in the base64 column.
    await setColumn(base, "Patient", "nickname", row.id as string, "Ada");
    return row.id as string;
  };

  it("strict mode raises the core's NOT_CIPHERTEXT, never returns it", async () => {
    const id = await plantLegacyNickname();
    await expect(prisma.patient.findUnique({ where: { id } })).rejects.toThrow(
      /ciphertext|envelope/i,
    );
  });

  it("permissive mode returns the actual legacy value, not its base64 decode", async () => {
    // The migration scenario base64 storage exists for. Decoding the stored
    // string as base64 first would hand back mojibake while the hook reports a
    // clean plaintext read.
    const id = await plantLegacyNickname();
    const seen: string[] = [];
    const { base: b2, prisma: permissive } = makeClient({
      readMode: "permissive",
      onPlaintextRead: (model, field) => seen.push(`${model}.${field}`),
    });
    const back = await permissive.patient.findUnique({ where: { id } });
    expect(back?.nickname).toBe("Ada");
    expect(seen).toContain("Patient.nickname");
    await b2.$disconnect();
  });

  it("a stored type that contradicts the declaration is a configuration error", async () => {
    // Prisma's own row deserializer refuses a BLOB in a TEXT column (P2023)
    // before the read pass ever sees it, so on a real query this branch is
    // defence in depth. It is still asserted directly, because the read pass
    // must not depend on a Prisma implementation detail to avoid handing back
    // the stored representation as if it were the value.
    const ext = fieldsealExtension({
      fieldMap: fieldsealFieldMap,
      keyProvider: keyProvider(),
      allowedSuites: [SUITE],
      writeSuite: SUITE,
      armProvisionalSuites: true,
      unindexableOverride: [
        { model: "Person", field: "legalName", reason: "test", approvedBy: "test", date: "2026-08-27" },
      ],
      onWarning: () => {},
    });
    await expect(
      ext.query.$allOperations({
        model: "Patient",
        operation: "findUnique",
        args: { where: { id: "x" } },
        query: async () => ({ id: "x", nickname: Buffer.from([1, 2, 3]) }),
      }),
    ).rejects.toThrow(FieldsealConfigurationError);
  });
});

describe("unindexable values (docs/09 §7.2)", () => {
  it("refuse mode raises FieldsealUnindexable carrying the code point and offset", async () => {
    // U+0378 is unassigned in every published Unicode version.
    const err = await lp["patient"]!["create"]!({
      data: patient({ email: "a͸@example.com" }),
    }).then(
      () => null,
      (e) => e as FieldsealUnindexable,
    );
    expect(err).toBeInstanceOf(FieldsealUnindexable);
    expect(err?.detail.codePoint).toBe("U+0378");
    expect(err?.message).toMatch(/cannot index yet/);
  });

  it("bucket mode stores the real value and derives the reserved marker", async () => {
    const row = await lp["person"]!["create"]!({ data: { legalName: "X͸Y" } });
    const back = await prisma.person.findUnique({ where: { id: row.id } });
    expect(back?.legalName).toBe("X͸Y"); // encrypt does not normalize
    const sibling = await rawColumn(base, "Person", "legalNameBidx", row.id);
    expect(sibling).not.toBeNull(); // the §7.2 marker's index, not the value's
  });
});

describe("the index sibling", () => {
  it("is derived on write and is ceil(b/8) bytes", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    const bidx = await rawColumn(base, "Patient", "emailBidx", row.id);
    // truncate_bits: 15 -> ceil(15/8) = 2 bytes.
    expect(Buffer.from(bidx as Uint8Array).length).toBe(2);
  });

  it("is deterministic for the same value, unlike the envelope", async () => {
    const a = await lp["patient"]!["create"]!({ data: patient() });
    const b = await lp["patient"]!["create"]!({ data: patient() });
    const ia = Buffer.from((await rawColumn(base, "Patient", "emailBidx", a.id)) as Uint8Array);
    const ib = Buffer.from((await rawColumn(base, "Patient", "emailBidx", b.id)) as Uint8Array);
    expect(ia.equals(ib)).toBe(true);
  });

  it("folds case, because the declared normalizer does (spec §7.5)", async () => {
    const lower = await lp["patient"]!["create"]!({ data: patient({ email: "ada@example.com" }) });
    const upper = await lp["patient"]!["create"]!({ data: patient({ email: "Ada@Example.COM" }) });
    const a = Buffer.from((await rawColumn(base, "Patient", "emailBidx", lower.id)) as Uint8Array);
    const b = Buffer.from((await rawColumn(base, "Patient", "emailBidx", upper.id)) as Uint8Array);
    expect(a.equals(b)).toBe(true);
  });

  it("is stripped from returned objects unless exposeIndexColumns is set", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    expect(row).not.toHaveProperty("emailBidx");

    const { base: b2, prisma: exposed } = makeClient({ exposeIndexColumns: true });
    const back = await exposed.patient.findUnique({ where: { id: row.id } });
    expect(back).toHaveProperty("emailBidx");
    await b2.$disconnect();
  });

  it("refuses a hand-written index value", async () => {
    await expect(
      lp["patient"]!["create"]!({
        data: { ...patient(), emailBidx: Buffer.from([0, 0]) },
      }),
    ).rejects.toThrow(FieldsealNotSupported);
    await expect(
      lp["patient"]!["create"]!({
        data: { ...patient(), emailBidx: Buffer.from([0, 0]) },
      }),
    ).rejects.toThrow(/derived, not.*written/s);
  });
});

describe("NULL", () => {
  it("stays NULL rather than becoming an envelope", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient({ nickname: null }) });
    expect(await rawColumn(base, "Patient", "nickname", row.id)).toBeNull();
    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.nickname).toBeNull();
  });

  it("an absent column is left absent, not written as an envelope", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    expect(await rawColumn(base, "Patient", "nickname", row.id)).toBeNull();
  });
});

describe("base64 storage (spec §3.3)", () => {
  it("round-trips through a String column holding ASCII", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient({ nickname: "Ada" }) });
    const stored = await rawColumn(base, "Patient", "nickname", row.id);

    expect(typeof stored).toBe("string");
    // Base64 alphabet only -- if this were raw envelope bytes it would not be.
    expect(stored as string).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(stored as string).not.toContain("Ada");

    const back = await prisma.patient.findUnique({ where: { id: row.id } });
    expect(back?.nickname).toBe("Ada");
  });

  it("costs about a third more than binary, as documented", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient({ nickname: "Ada" }) });
    const b64 = (await rawColumn(base, "Patient", "nickname", row.id)) as string;
    const bin = Buffer.from((await rawColumn(base, "Patient", "email", row.id)) as Uint8Array);
    // Both envelopes wrap short values, so their binary lengths are close;
    // the base64 one is ~4/3 of its own binary length by construction.
    expect(b64.length).toBeGreaterThan(bin.length);
    expect(b64.length).toBeLessThanOrEqual(Math.ceil((bin.length + 8) / 3) * 4);
  });
});

describe("tenant binding (spec §10, L3)", () => {
  it("refuses the write when no tenant is resolvable", async () => {
    await expect(lp["tenantDoc"]!["create"]!({ data: { body: "secret" } })).rejects.toThrow(
      /tenant_bound and no tenant is resolvable/,
    );
  });

  it("writes and reads inside a tenantScope", async () => {
    await tenantScope("tenant-0001", async () => {
      const row = await lp["tenantDoc"]!["create"]!({ data: { body: "secret" } });
      const back = await prisma.tenantDoc.findUnique({ where: { id: row.id } });
      expect(back?.body).toBe("secret");
    });
  });

  it("cannot be read under a different tenant -- the binding is cryptographic", async () => {
    const id = await tenantScope("tenant-0001", async () => {
      const row = await lp["tenantDoc"]!["create"]!({ data: { body: "secret" } });
      return row.id;
    });
    await tenantScope("tenant-0002", async () => {
      // Spec §6.3 binds the context into the derived key, so a wrong tenant is
      // indistinguishable from a wrong key and surfaces as COMMITMENT_INVALID
      // rather than AAD_MISMATCH, which never fires on the 0xFF01 path.
      await expect(prisma.tenantDoc.findUnique({ where: { id } })).rejects.toThrow(
        /COMMITMENT_INVALID|commitment/i,
      );
    });
  });
});

describe("tamper", () => {
  it("raises rather than returning garbage", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    const stored = Buffer.from((await rawColumn(base, "Patient", "email", row.id)) as Uint8Array);
    stored[stored.length - 1] = (stored[stored.length - 1]! ^ 0xff) & 0xff;
    await setColumn(base, "Patient", "email", row.id as string, stored);
    await expect(prisma.patient.findUnique({ where: { id: row.id } })).rejects.toThrow();
  });
});
