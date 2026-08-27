/**
 * L1: the value path. What the coverage matrix claims, asserted.
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { FieldsealNotSupported, tenantScope } from "../src/index.ts";
import { clearDb, loose, makeClient, rawColumn } from "./helpers.ts";

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
    await base.$executeRawUnsafe(
      `UPDATE "Patient" SET "email" = ? WHERE "id" = ?`,
      stored,
      row.id,
    );
    await expect(prisma.patient.findUnique({ where: { id: row.id } })).rejects.toThrow();
  });
});
