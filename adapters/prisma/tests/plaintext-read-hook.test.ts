/**
 * `onPlaintextRead` is the per-field form of the core's plaintext-read count
 * (spec §10.3, `docs/13` §3), and `tools/backfill/PROCEDURE.md` §8's cut-over
 * gate relies on it. So it must agree with the core read for read (#293).
 *
 * The core's own count is taken from inside the extension, not from a second
 * client: the core emits a `"plaintext-read"` warning at the point it counts
 * (`Fieldseal.decrypt`, beside `metrics.plaintextReads`), and the extension
 * passes `onWarning` through to it. Every assertion below sets the hook's count
 * beside that one.
 *
 * Before #293 the hook fired before `buildContext` and `decrypt`, with no check
 * of the read mode, so each "none" row below except the envelope read counted
 * one (measured 2026-11-18, Prisma 7.10.0, SQLite and Postgres alike).
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import {
  KeyUnavailableError,
  NotCiphertextError,
  StaticKeyProvider,
  UnknownFormatVersionError,
  type KeyProvider,
  type ReadMode,
  type Warning,
} from "@fieldseal/core";

import { FieldsealConfigurationError, FieldsealNotSupported, type FieldsealExtensionOptions } from "../src/index.ts";
import { clearDb, DEK, INDEX_KEY, KEY_ID, loose, makeClient, setColumn } from "./helpers.ts";

const { base, prisma } = makeClient();
const lp = loose(prisma);

beforeEach(async () => {
  await clearDb(base);
});
afterAll(async () => {
  await base.$disconnect();
});

/** A client in `readMode` that records the hook and the core's count. */
function counted(readMode: ReadMode, over: Partial<FieldsealExtensionOptions> = {}) {
  const hook: string[] = [];
  let core = 0;
  const { base: b, prisma: p } = makeClient({
    ...over,
    readMode,
    onPlaintextRead: (model, field) => hook.push(`${model}.${field}`),
    onWarning: (w: Warning) => {
      if (w.kind === "plaintext-read") core += 1;
    },
  });
  return {
    prisma: p,
    hook,
    core: () => core,
    close: () => b.$disconnect(),
  };
}

const patient = (over: Record<string, unknown> = {}) => ({
  email: "ada@example.com",
  note: "a note",
  age: 36,
  plainName: "Ada",
  ...over,
});

/** A Patient written through the extension, then one column overwritten raw. */
async function plant(column: string, value: unknown): Promise<string> {
  const row = await lp["patient"]!["create"]!({ data: patient() });
  await setColumn(base, "Patient", column, row.id as string, value);
  return row.id as string;
}

/** `0x02` and 110 zero bytes: a reserved `fmt_ver` at a registered length (spec §3.4). */
const RESERVED_VERSION = Buffer.concat([Buffer.from([0x02]), Buffer.alloc(110)]);

const PASS_THROUGH: ReadMode[] = ["permissive", "readonly"];
const ALL: ReadMode[] = ["strict", ...PASS_THROUGH];

describe("onPlaintextRead agrees with the core's plaintext-read count (#293)", () => {
  describe.each([
    { column: "note", storage: "binary", legacy: Buffer.from("a legacy note", "utf8"), value: "a legacy note" },
    { column: "nickname", storage: "base64", legacy: "Ada", value: "Ada" },
  ])("plaintext in a $storage column (Patient.$column)", ({ column, legacy, value }) => {
    it("strict: NOT_CIPHERTEXT, and neither the hook nor the core counts", async () => {
      const id = await plant(column, legacy);
      const c = counted("strict");
      try {
        await expect(c.prisma.patient.findUnique({ where: { id } })).rejects.toBeInstanceOf(
          NotCiphertextError,
        );
        expect(c.hook).toEqual([]);
        expect(c.core()).toBe(0);
      } finally {
        await c.close();
      }
    });

    it.each(PASS_THROUGH)("%s: the value is returned, and the hook and the core count one", async (mode) => {
      const id = await plant(column, legacy);
      const c = counted(mode);
      try {
        const back = await c.prisma.patient.findUnique({ where: { id } });
        expect((back as Record<string, unknown> | null)?.[column]).toBe(value);
        expect(c.hook).toEqual([`Patient.${column}`]);
        expect(c.core()).toBe(1);
      } finally {
        await c.close();
      }
    });
  });

  it.each(ALL)(
    "%s: a reserved version in a binary column raises, and neither counts",
    async (mode) => {
      // `isCiphertext` calls this non-ciphertext, but `decrypt` refuses it with
      // UNKNOWN_FORMAT_VERSION in every mode rather than passing it through.
      const id = await plant("note", RESERVED_VERSION);
      const c = counted(mode);
      try {
        await expect(c.prisma.patient.findUnique({ where: { id } })).rejects.toBeInstanceOf(
          UnknownFormatVersionError,
        );
        expect(c.hook).toEqual([]);
        expect(c.core()).toBe(0);
      } finally {
        await c.close();
      }
    },
  );

  it.each(PASS_THROUGH)(
    "%s: plaintext in a tenant-bound column, read with no tenant, is refused before the core and not counted",
    async (mode) => {
      const row = await base.tenantDoc.create({ data: { body: Buffer.from("legacy body", "utf8") } });
      const c = counted(mode);
      try {
        await expect(c.prisma.tenantDoc.findUnique({ where: { id: row.id } })).rejects.toBeInstanceOf(
          FieldsealConfigurationError,
        );
        expect(c.hook).toEqual([]);
        expect(c.core()).toBe(0);
      } finally {
        await c.close();
      }
    },
  );

  it.each(ALL)("%s: an envelope is not a plaintext read", async (mode) => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    const c = counted(mode);
    try {
      const back = await c.prisma.patient.findUnique({ where: { id: row.id } });
      expect(back?.note).toBe("a note");
      expect(c.hook).toEqual([]);
      expect(c.core()).toBe(0);
    } finally {
      await c.close();
    }
  });

  it.each(PASS_THROUGH)("%s: one count per value read, over several rows", async (mode) => {
    await plant("note", Buffer.from("legacy one", "utf8"));
    await plant("note", Buffer.from("legacy two", "utf8"));
    const legacyBoth = await plant("note", Buffer.from("legacy three", "utf8"));
    await setColumn(base, "Patient", "nickname", legacyBoth, "Ada");
    await lp["patient"]!["create"]!({ data: patient({ nickname: "Bea" }) });

    const c = counted(mode);
    try {
      const rows = await c.prisma.patient.findMany({});
      expect(rows).toHaveLength(4);
      expect([...c.hook].sort()).toEqual([
        "Patient.nickname",
        "Patient.note",
        "Patient.note",
        "Patient.note",
      ]);
      expect(c.core()).toBe(4);
    } finally {
      await c.close();
    }
  });

  it.each(PASS_THROUGH)(
    "%s: a passed-through value the codec then refuses is still one plaintext read",
    async (mode) => {
      // The core passed it through and counted it before the adapter renders
      // it; the codec's refusal of three bytes as `as: "int"` comes after.
      const id = await plant("age", Buffer.from("abc", "utf8"));
      const c = counted(mode);
      try {
        await expect(c.prisma.patient.findUnique({ where: { id } })).rejects.toBeInstanceOf(
          FieldsealNotSupported,
        );
        expect(c.hook).toEqual(["Patient.age"]);
        expect(c.core()).toBe(1);
      } finally {
        await c.close();
      }
    },
  );

  it.each(ALL)(
    "%s: a reserved version in a base64 column is the stored text, passed through like any legacy text",
    async (mode) => {
      // The base64 branch hands the core the stored string's own bytes when its
      // decode is not an envelope, and a reserved version is not one. So the
      // core sees ordinary non-envelope input: NOT_CIPHERTEXT in strict, and
      // otherwise the stored text returned and counted. The Django adapter
      // does the same (`test_legacy_base64_column.py`).
      const stored = RESERVED_VERSION.toString("base64");
      const id = await plant("nickname", stored);
      const c = counted(mode);
      try {
        if (mode === "strict") {
          await expect(c.prisma.patient.findUnique({ where: { id } })).rejects.toBeInstanceOf(
            NotCiphertextError,
          );
          expect(c.hook).toEqual([]);
          expect(c.core()).toBe(0);
        } else {
          const back = await c.prisma.patient.findUnique({ where: { id } });
          expect(back?.nickname).toBe(stored);
          expect(c.hook).toEqual(["Patient.nickname"]);
          expect(c.core()).toBe(1);
        }
      } finally {
        await c.close();
      }
    },
  );

  it.each(PASS_THROUGH)("%s: a legacy value reached through include counts under its own model", async (mode) => {
    const row = await lp["patient"]!["create"]!({ data: patient() });
    const visit = await lp["visit"]!["create"]!({ data: { patientId: row.id, reason: "checkup" } });
    await setColumn(base, "Visit", "reason", visit.id as string, Buffer.from("legacy reason", "utf8"));
    const c = counted(mode);
    try {
      const back = await c.prisma.patient.findUnique({
        where: { id: row.id as string },
        include: { visits: true },
      });
      expect(back?.visits[0]?.reason).toBe("legacy reason");
      expect(c.hook).toEqual(["Visit.reason"]);
      expect(c.core()).toBe(1);
    } finally {
      await c.close();
    }
  });

  it("permissive: a read retried after a key miss (L4) counts again, in the hook and the core alike", async () => {
    // `runPass` rolls the pass back and runs it again after `warm()`, so a
    // legacy value decrypted before the miss is passed through twice. Both
    // counts see both, which is what agreement means; neither is "reads" here,
    // and docs/13 §3 says so. The error only ever raises the count.
    const row = await lp["patient"]!["create"]!({ data: patient() });
    await setColumn(base, "Patient", "email", row.id as string, Buffer.from("legacy@example.com", "utf8"));
    const inner = new StaticKeyProvider({ dek: DEK, indexKey: INDEX_KEY, keyId: KEY_ID });
    let cold = true;
    let warms = 0;
    const provider: KeyProvider = {
      encryptionKey: (ctx) => inner.encryptionKey(ctx),
      decryptionKeys: (header) => {
        if (cold) throw new KeyUnavailableError(header.keyId, "staged: cold");
        return inner.decryptionKeys(header);
      },
      warm: async () => {
        warms += 1;
        cold = false;
      },
    };
    const c = counted("permissive", { keyProvider: provider });
    try {
      const back = await c.prisma.patient.findUnique({ where: { id: row.id as string } });
      expect(back?.email).toBe("legacy@example.com");
      expect(back?.note).toBe("a note");
      expect(warms).toBe(1);
      expect(c.hook).toEqual(["Patient.email", "Patient.email"]);
      expect(c.core()).toBe(2);
    } finally {
      await c.close();
    }
  });
});
