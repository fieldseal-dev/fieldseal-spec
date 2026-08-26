/**
 * Gates: what a vector proves an operation *does*, these prove an operation
 * *refuses* (docs/17 §5 item 3).
 *
 *   spec §4.8   provisional-suite arming on ciphertext-producing operations,
 *               and its deliberate absence on decrypt / blindIndex / isCiphertext
 *   spec §10.3  read modes on both axes
 *   docs/08 §6  determinism-injection arming gate; production encrypt takes
 *               no caller-supplied seed or nonce in any form
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ARM_PROVISIONAL_ENV, ModeViolationError, SUITE_FF01, SuiteProvisionalError, indexRegistryKey, validateIndexDeclaration, type ValidatedIndex, type Warning } from "../src/index.ts";
import { INTERNALS } from "../src/internal.ts";
import { encrypt_with_materials, TestModeNotArmedError } from "../src/testing/index.ts";
import { bytes, codeOf, CTX, makeClient, messageOf, withEnv } from "./helpers.ts";

const PT = bytes("123456789");
const SEED = new Uint8Array(32).fill(0x41);
const NONCE = new Uint8Array(12).fill(0x02);
const IDX_CTX = { ...CTX, purpose: "index:exact" };
const INDEX = { tableUuid: CTX.tableUuid, columnUuid: CTX.columnUuid, idf: "hmac-sha512" as const, normalize: "identity" as const, truncateBits: 15, projectedPopulation: 65536 };

describe("spec §4.8 provisional-suite gate", () => {
  const armed = makeClient({ indexes: [INDEX] });
  const envelope = armed.encrypt(PT, CTX);

  it("refuses encrypt() when not armed, naming the suite and the arming mechanism", () => {
    const unarmed = withEnv(ARM_PROVISIONAL_ENV, undefined, () => makeClient({}, {}));
    expect(codeOf(() => unarmed.encrypt(PT, CTX))).toBe("SUITE_PROVISIONAL");
    const msg = messageOf(() => unarmed.encrypt(PT, CTX));
    expect(msg).toContain("0xFF01");
    expect(msg).toContain(ARM_PROVISIONAL_ENV);
    expect(msg).toContain("armProvisionalSuites");
    expect(() => unarmed.encrypt(PT, CTX)).toThrow(SuiteProvisionalError);
  });

  it("refuses rotate() when not armed (rotate is an encrypt for this purpose)", () => {
    const unarmed = withEnv(ARM_PROVISIONAL_ENV, undefined, () => makeClient({}, {}));
    expect(codeOf(() => unarmed.rotate(envelope, CTX))).toBe("SUITE_PROVISIONAL");
  });

  it("refuses before key acquisition", () => {
    let asked = 0;
    const unarmed = withEnv(ARM_PROVISIONAL_ENV, undefined, () =>
      makeClient(
        {
          keyProvider: {
            encryptionKey: () => {
              asked++;
              throw new Error("should not be called");
            },
            decryptionKeys: () => [],
          },
        },
        {},
      ),
    );
    expect(codeOf(() => unarmed.encrypt(PT, CTX))).toBe("SUITE_PROVISIONAL");
    expect(asked).toBe(0);
  });

  it("does NOT gate decrypt(): reading data one has already written needs no arming", () => {
    const unarmed = withEnv(ARM_PROVISIONAL_ENV, undefined, () => makeClient({}, {}));
    expect(Buffer.from(unarmed.decrypt(envelope, CTX)).equals(Buffer.from(PT))).toBe(true);
  });

  it("does NOT gate blindIndex() or isCiphertext()", () => {
    const unarmed = withEnv(ARM_PROVISIONAL_ENV, undefined, () => makeClient({ indexes: [INDEX] }, {}));
    expect(unarmed.blindIndex(PT, IDX_CTX).length).toBe(2);
    expect(unarmed.isCiphertext(envelope)).toBe(true);
  });

  it("arms via the environment variable", () => {
    const c = withEnv(ARM_PROVISIONAL_ENV, "1", () => makeClient({}, {}));
    expect(c.provisionalArmed).toBe(true);
    expect(c.encrypt(PT, CTX).length).toBe(120);
  });

  it("arms via the second constructor argument", () => {
    const c = withEnv(ARM_PROVISIONAL_ENV, undefined, () => makeClient({}, { armProvisionalSuites: true }));
    expect(c.provisionalArmed).toBe(true);
  });

  it("is NOT satisfiable from inside the ordinary config object", () => {
    // A copied config carrying allowedSuites/writeSuite must not inherit arming.
    const c = withEnv(ARM_PROVISIONAL_ENV, undefined, () =>
      makeClient({ armProvisionalSuites: true } as unknown as Record<string, never>, {}),
    );
    expect(c.provisionalArmed).toBe(false);
    expect(codeOf(() => c.encrypt(PT, CTX))).toBe("SUITE_PROVISIONAL");
  });

  it("only an env value of exactly '1' arms", () => {
    for (const v of ["true", "yes", "0", ""]) {
      const c = withEnv(ARM_PROVISIONAL_ENV, v, () => makeClient({}, {}));
      expect(c.provisionalArmed, `env=${JSON.stringify(v)}`).toBe(false);
    }
  });
});

describe("spec §10.3 read modes", () => {
  const writer = makeClient();
  const envelope = writer.encrypt(PT, CTX);
  const plaintextInput = bytes("unmigrated plaintext value");

  it("strict: non-envelope input raises NOT_CIPHERTEXT; writes permitted", () => {
    const c = makeClient({ readMode: "strict" });
    expect(codeOf(() => c.decrypt(plaintextInput, CTX))).toBe("NOT_CIPHERTEXT");
    expect(c.encrypt(PT, CTX).length).toBe(120);
    expect(c.rotate(envelope, CTX).length).toBe(120);
  });

  it("permissive: non-envelope input is returned as-is, with a warning and a metric; writes permitted", () => {
    const warnings: Warning[] = [];
    let plaintextReads = 0;
    const c = makeClient({ readMode: "permissive", metrics: { plaintextReads: () => plaintextReads++ } }, undefined, warnings);
    expect(warnings.map((w) => w.kind)).toContain("permissive-mode");
    const out = c.decrypt(plaintextInput, CTX);
    expect(Buffer.from(out).equals(Buffer.from(plaintextInput))).toBe(true);
    expect(plaintextReads).toBe(1);
    expect(warnings.map((w) => w.kind)).toContain("plaintext-read");
    expect(c.encrypt(PT, CTX).length).toBe(120);
    // A valid envelope still decrypts.
    expect(Buffer.from(c.decrypt(envelope, CTX)).equals(Buffer.from(PT))).toBe(true);
  });

  it("readonly: encrypt() and rotate() raise MODE_VIOLATION naming operation and mode", () => {
    const warnings: Warning[] = [];
    const c = makeClient({ readMode: "readonly", indexes: [INDEX] }, undefined, warnings);
    expect(warnings.map((w) => w.kind)).toContain("readonly-mode");
    for (const [op, fn] of [
      ["encrypt", () => c.encrypt(PT, CTX)],
      ["rotate", () => c.rotate(envelope, CTX)],
    ] as const) {
      expect(codeOf(fn)).toBe("MODE_VIOLATION");
      const m = messageOf(fn);
      expect(m).toContain(`'${op}'`);
      expect(m).toContain("'readonly'");
      expect(fn).toThrow(ModeViolationError);
    }
  });

  it("readonly: MODE_VIOLATION comes before SUITE_PROVISIONAL and before key acquisition", () => {
    let asked = 0;
    const c = withEnv(ARM_PROVISIONAL_ENV, undefined, () =>
      makeClient(
        {
          readMode: "readonly",
          keyProvider: {
            encryptionKey: () => {
              asked++;
              throw new Error("no");
            },
            decryptionKeys: () => [],
          },
        },
        {},
      ),
    );
    expect(codeOf(() => c.encrypt(PT, CTX))).toBe("MODE_VIOLATION");
    expect(asked).toBe(0);
  });

  it("readonly: the positive controls -- decrypt of a valid envelope, non-envelope pass-through, blindIndex", () => {
    const c = makeClient({ readMode: "readonly", indexes: [INDEX] });
    expect(Buffer.from(c.decrypt(envelope, CTX)).equals(Buffer.from(PT))).toBe(true);
    expect(Buffer.from(c.decrypt(plaintextInput, CTX)).equals(Buffer.from(plaintextInput))).toBe(true);
    const idx = c.blindIndex(PT, IDX_CTX);
    expect(idx.length).toBe(2);
    expect(Buffer.from(idx).equals(Buffer.from(makeClient({ indexes: [INDEX] }).blindIndex(PT, IDX_CTX)))).toBe(true);
    expect(c.isCiphertext(envelope)).toBe(true);
  });

  it("mode is a construction-time property (the client is immutable)", () => {
    const c = makeClient({ readMode: "readonly" });
    expect(Object.isFrozen(c)).toBe(true);
    expect(() => {
      (c as unknown as { readMode: string }).readMode = "strict";
    }).toThrow();
    expect(c.readMode).toBe("readonly");
  });
});

describe("docs/08 §6 determinism injection", () => {
  const c = makeClient();

  it("encrypt_with_materials throws unless FIELDSEAL_TEST_MODE=1 (checked at call time)", () => {
    withEnv("FIELDSEAL_TEST_MODE", undefined, () => {
      expect(() => encrypt_with_materials(c, PT, CTX, SEED, NONCE)).toThrow(TestModeNotArmedError);
      expect(codeOf(() => encrypt_with_materials(c, PT, CTX, SEED, NONCE))).toBe("CONFIGURATION_ERROR");
      expect(messageOf(() => encrypt_with_materials(c, PT, CTX, SEED, NONCE))).toContain("non-conformant");
    });
    withEnv("FIELDSEAL_TEST_MODE", "0", () => {
      expect(() => encrypt_with_materials(c, PT, CTX, SEED, NONCE)).toThrow(TestModeNotArmedError);
    });
  });

  it("the registered seam itself is gated, not only the testing/ wrapper", () => {
    // Defense in depth: even code that reaches the WeakMap-registered
    // closure directly (bypassing encrypt_with_materials) must find the
    // docs/08 §6 gate at the pipeline, in an unarmed process.
    const seam = INTERNALS.get(c)!;
    withEnv("FIELDSEAL_TEST_MODE", undefined, () => {
      expect(codeOf(() => seam.encryptWithMaterials(PT, CTX, SEED, NONCE))).toBe("CONFIGURATION_ERROR");
      expect(messageOf(() => seam.encryptWithMaterials(PT, CTX, SEED, NONCE))).toContain("FIELDSEAL_TEST_MODE");
    });
    withEnv("FIELDSEAL_TEST_MODE", "1", () => {
      expect(seam.encryptWithMaterials(PT, CTX, SEED, NONCE).length).toBe(120);
    });
  });

  it("armed, it is deterministic and runs the full pipeline (including the §4.8 and §10.3 gates)", () => {
    withEnv("FIELDSEAL_TEST_MODE", "1", () => {
      const a = encrypt_with_materials(c, PT, CTX, SEED, NONCE);
      const b = encrypt_with_materials(c, PT, CTX, SEED, NONCE);
      expect(a.equals(b)).toBe(true);
      expect(Buffer.from(a.subarray(19, 51)).equals(Buffer.from(SEED))).toBe(true);
      expect(Buffer.from(a.subarray(51, 63)).equals(Buffer.from(NONCE))).toBe(true);
      expect(Buffer.from(c.decrypt(a, CTX)).equals(Buffer.from(PT))).toBe(true);
      const ro = makeClient({ readMode: "readonly" });
      expect(codeOf(() => encrypt_with_materials(ro, PT, CTX, SEED, NONCE))).toBe("MODE_VIOLATION");
      const unarmed = withEnv(ARM_PROVISIONAL_ENV, undefined, () => makeClient({}, {}));
      expect(codeOf(() => encrypt_with_materials(unarmed, PT, CTX, SEED, NONCE))).toBe("SUITE_PROVISIONAL");
    });
  });

  it("production encrypt() is fresh on every call, even with FIELDSEAL_TEST_MODE=1, even on an UPDATE of the same value", () => {
    withEnv("FIELDSEAL_TEST_MODE", "1", () => {
      const a = c.encrypt(PT, CTX);
      const b = c.encrypt(PT, CTX);
      expect(a.equals(b)).toBe(false);
      expect(Buffer.from(a.subarray(19, 51)).equals(Buffer.from(b.subarray(19, 51)))).toBe(false); // msg_seed
      expect(Buffer.from(a.subarray(51, 63)).equals(Buffer.from(b.subarray(51, 63)))).toBe(false); // nonce
    });
  });

  it("production encrypt() accepts no seed or nonce in any form: extra positional arguments are ignored", () => {
    const enc = c.encrypt as unknown as (...a: unknown[]) => Buffer;
    expect(c.encrypt.length).toBe(2);
    const out = enc.call(c, PT, CTX, SEED, NONCE);
    expect(Buffer.from(out.subarray(19, 51)).equals(Buffer.from(SEED))).toBe(false);
    expect(Buffer.from(out.subarray(51, 63)).equals(Buffer.from(NONCE))).toBe(false);
    const out2 = enc.call(c, PT, CTX, { msgSeed: SEED, nonce: NONCE });
    expect(Buffer.from(out2.subarray(19, 51)).equals(Buffer.from(SEED))).toBe(false);
  });

  it("the main entry never reaches testing/ or exposes the internal seam (static import-graph walk)", () => {
    const srcDir = resolve(dirname(fileURLToPath(import.meta.url)), "../src");
    const seen = new Set<string>();
    const walk = (file: string): void => {
      if (seen.has(file)) return;
      seen.add(file);
      const text = readFileSync(file, "utf-8");
      for (const m of text.matchAll(/from\s+"(\.[^"]+)"/g)) {
        const target = resolve(dirname(file), m[1]!);
        if (statSync(target, { throwIfNoEntry: false })) walk(target);
      }
    };
    walk(join(srcDir, "index.ts"));
    for (const f of seen) expect(f.replace(/\\/g, "/"), f).not.toContain("/src/testing/");
    // internal.ts is imported by api.ts (to register the seam) and by
    // testing/ only; index.ts does not re-export anything from it.
    expect(readFileSync(join(srcDir, "index.ts"), "utf-8")).not.toContain("internal");
    const pkg = JSON.parse(readFileSync(join(srcDir, "../package.json"), "utf-8")) as { exports: Record<string, unknown> };
    expect(Object.keys(pkg.exports).sort()).toEqual([".", "./testing"]);
    // And every source file is accounted for (no stray module that might leak).
    const all = readdirSync(srcDir, { recursive: true, withFileTypes: true })
      .filter((d) => d.isFile() && d.name.endsWith(".ts"))
      .map((d) => join(d.parentPath, d.name));
    const unreached = all.filter((f) => !seen.has(f)).map((f) => f.replace(/\\/g, "/").split("/src/")[1]);
    expect(unreached.sort()).toEqual(["testing/index.ts"]);
  });
});

describe("spec §6.1 unbounded context fields", () => {
  // canonical_context is HKDF's `info` (§5.3, §7.2). Node's built-in HKDF
  // caps `info` at 1024 bytes; an implementation built on it cannot derive
  // the key for a context another core can write once tenant_id + row_id
  // pass ~930 bytes. src/kdf.ts implements RFC 5869 over createHmac so that
  // no context a caller can express is refused by the primitive.
  const c = makeClient({ indexes: [INDEX] });

  it("encrypt / decrypt / rotate / blindIndex accept a context whose canonical encoding exceeds 1024 bytes", () => {
    for (const [tenantLen, rowLen] of [
      [950, 0],
      [2000, 0],
      [0, 2000],
      [4096, 4096],
      [70_000, 0],
    ] as const) {
      const ctx = {
        ...CTX,
        tenantId: new Uint8Array(tenantLen).map((_, i) => i & 0xff),
        rowId: rowLen ? new Uint8Array(rowLen).fill(0x5a) : null,
      };
      const env = c.encrypt(PT, ctx);
      expect(env.length).toBe(111 + PT.length);
      expect(Buffer.from(c.decrypt(env, ctx)).equals(Buffer.from(PT))).toBe(true);
      expect(Buffer.from(c.decrypt(c.rotate(env, ctx), ctx)).equals(Buffer.from(PT))).toBe(true);
      expect(c.blindIndex(PT, { ...ctx, purpose: "index:exact" }).length).toBe(2);
    }
  });

  it("a large tenant_id still binds: a one-byte change in it is COMMITMENT_INVALID, not a quiet success", () => {
    const tenantId = new Uint8Array(3000).fill(0x41);
    const env = c.encrypt(PT, { ...CTX, tenantId });
    const altered = new Uint8Array(tenantId);
    altered[2999] = 0x40; // 'A' with bit 0 cleared
    expect(codeOf(() => c.decrypt(env, { ...CTX, tenantId: altered }))).toBe("COMMITMENT_INVALID");
  });
});

describe("docs/09 §2 configuration reflection (G18)", () => {
  const ARGON = {
    tableUuid: CTX.tableUuid,
    columnUuid: CTX.columnUuid,
    idf: "argon2id" as const,
    normalize: "nfc-casefold-v1" as const,
    truncateBits: 15,
    projectedPopulation: 65536,
  };

  it("reports back what construction validated", () => {
    const fs = makeClient({ indexes: [INDEX] });
    expect(fs.readMode).toBe("strict");
    expect(fs.writeSuite).toBe(SUITE_FF01);
    expect([...fs.allowedSuites]).toEqual([SUITE_FF01]);
    expect(fs.provisionalArmed).toBe(true);
    // The carve-out is the point of stating the rule as a principle: a
    // reflected handle to the object holding key material is a larger surface
    // than any consumer of this needs.
    expect("keyProvider" in fs).toBe(false);
  });

  it("returns the index registry resolved, not as declared", () => {
    const fs = makeClient({ indexes: [ARGON] });
    const key = indexRegistryKey(CTX.tableUuid, CTX.columnUuid, "exact");
    expect([...fs.indexes.keys()]).toEqual([key]);
    const v = fs.indexes.get(key) as ValidatedIndex;
    // Absent in the declaration, filled in from the §7.3 minima. Comparing
    // as-declared inputs would let two declarations that agree textually and
    // differ operationally register as a match — the failure #62 was.
    expect(v.argon2).toEqual({ timeCost: 3, memoryKib: 32 * 1024 });
    expect(v.indexId).toBe("exact");
    expect(v.onUnindexable).toBe("refuse");
    // The public validation entry point resolves a declaration to exactly what
    // the client holds, which is what makes an exact-match check writable from
    // outside the core at all.
    expect(validateIndexDeclaration(ARGON)).toEqual(v);
  });

  it("hands out a registry that cannot mutate the client", () => {
    const fs = makeClient({ indexes: [INDEX] });
    const key = [...fs.indexes.keys()][0] as string;
    // `ReadonlyMap` is a type, not a runtime guarantee; the copy is.
    (fs.indexes as Map<string, ValidatedIndex>).clear();
    expect(fs.indexes.size).toBe(1);
    // And the declarations are frozen, so a caller holding one cannot rewrite
    // the truncation length of a live index either.
    const v = fs.indexes.get(key) as { truncateBits: number };
    expect(Object.isFrozen(v)).toBe(true);
    expect(() => {
      "use strict";
      v.truncateBits = 32;
    }).toThrow(TypeError);
    expect(fs.indexes.get(key)?.truncateBits).toBe(15);
  });

  it("hands out an allow-list that cannot mutate the client", () => {
    // `allowedSuites` predates G18 but the §2 anti-mutation clause now covers
    // it, and it is the only other collection on the reflected surface —
    // readMode/writeSuite/provisionalArmed are primitives. The getter used to
    // return `#cfg.allowedSuites` itself, which is the same Set the decrypt
    // path consults, so a caller could change what the client will decrypt
    // through an accessor documented as read-only.
    const fs = makeClient({ indexes: [INDEX] });
    const envelope = fs.encrypt(PT, CTX);
    (fs.allowedSuites as Set<number>).delete(SUITE_FF01);
    (fs.allowedSuites as Set<number>).add(0xff02);
    expect([...fs.allowedSuites]).toEqual([SUITE_FF01]);
    // The proof that the copy matters: without it this decrypt raises
    // SUITE_NOT_ALLOWED on an envelope the client wrote moments earlier.
    expect(fs.decrypt(envelope, CTX).equals(Buffer.from(PT))).toBe(true);
  });

  it("reports an empty registry rather than nothing when no index is declared", () => {
    // An adapter comparing registries must be able to tell "no indexes
    // declared" from "this core cannot say", and only one of those is a state.
    expect(makeClient({}).indexes.size).toBe(0);
  });
});
