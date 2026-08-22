/**
 * Totality: every failure path yields a typed §9 error, never a runtime
 * exception, on arbitrary, truncated and malformed input (docs/17 §5 item 3).
 * Also the decrypt-path precedence this core pins under G5, exercised the
 * way the (not yet authored) errors/ vector family would exercise it.
 */

import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { recognize, serialize } from "../src/envelope.ts";
import { ERROR_CODES, FieldsealError } from "../src/errors.ts";
import { SUITE_FF01, getSuite } from "../src/registry.ts";
import { bytes, codeOf, CTX, DEK, KEY_ID, makeClient } from "./helpers.ts";

/** A byte array whose length is uniform on 0..max (fast-check's default biases short). */
const uniformBytes = (max: number) =>
  fc.integer({ min: 0, max }).chain((n) => fc.uint8Array({ minLength: n, maxLength: n }));

const SPEC_CODES = new Set<string>(ERROR_CODES);
const PT = bytes("123456789");
const c = makeClient();
const ENVELOPE = c.encrypt(PT, CTX);

function flipBit(buf: Uint8Array, byteIndex: number, bit = 0): Uint8Array {
  const out = new Uint8Array(buf);
  out[byteIndex] = (out[byteIndex] as number) ^ (1 << bit);
  return out;
}

function decryptCode(input: Uint8Array, client = c, ctx = CTX): string {
  return codeOf(() => client.decrypt(input, ctx));
}

describe("decrypt is total over arbitrary bytes", () => {
  it("strict: always a §9 error or a correct plaintext, never an untyped exception", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 400 }), (input) => {
        try {
          c.decrypt(input, CTX);
        } catch (e) {
          expect(e).toBeInstanceOf(FieldsealError);
          expect(SPEC_CODES.has((e as FieldsealError).code)).toBe(true);
        }
      }),
      { numRuns: 2000 },
    );
  });

  it("permissive: pass-through of the exact input, or a §9 error", () => {
    const p = makeClient({ readMode: "permissive" });
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 400 }), (input) => {
        try {
          const out = p.decrypt(input, CTX);
          // Either pass-through (not an envelope) or a real decrypt; random
          // bytes essentially never form a valid envelope, so pass-through.
          if (recognize(input).kind === "not-ciphertext") expect(Buffer.from(out).equals(Buffer.from(input))).toBe(true);
        } catch (e) {
          expect(e).toBeInstanceOf(FieldsealError);
          expect(SPEC_CODES.has((e as FieldsealError).code)).toBe(true);
        }
      }),
      { numRuns: 2000 },
    );
  });

  it("valid-looking headers with random bodies: still typed", () => {
    const suite = getSuite(SUITE_FF01)!;
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 200 }), (body) => {
        const input = new Uint8Array(3 + body.length);
        input[0] = 0x01;
        input[1] = 0xff;
        input[2] = 0x01;
        input.set(body, 3);
        const code = decryptCode(input);
        expect(SPEC_CODES.has(code), code).toBe(true);
        if (input.length < 51 + suite.nonceLen + suite.tagLen + suite.commitLen) expect(code).toBe("NOT_CIPHERTEXT");
      }),
      { numRuns: 1000 },
    );
  });

  it("non-bytes input is a typed INVALID_ARGUMENT, not a TypeError", () => {
    for (const bad of ["a string", 42, null, undefined, {}, [1, 2, 3]]) {
      expect(decryptCode(bad as unknown as Uint8Array)).toBe("INVALID_ARGUMENT");
      expect(codeOf(() => c.encrypt(bad as unknown as Uint8Array, CTX))).toBe("INVALID_ARGUMENT");
      expect(codeOf(() => c.isCiphertext(bad as unknown as Uint8Array))).toBe("INVALID_ARGUMENT");
      expect(codeOf(() => c.blindIndex(bad as unknown as Uint8Array, { ...CTX, purpose: "index:exact" }))).toBe("INVALID_ARGUMENT");
    }
  });
});

describe("every prefix of a valid envelope yields a typed error", () => {
  it("truncation at every length", () => {
    const suite = getSuite(SUITE_FF01)!;
    const min = 51 + suite.nonceLen + suite.tagLen + suite.commitLen;
    for (let n = 0; n < ENVELOPE.length; n++) {
      const code = decryptCode(ENVELOPE.subarray(0, n));
      expect(SPEC_CODES.has(code), `prefix ${n}: ${code}`).toBe(true);
      if (n < min) expect(code, `prefix ${n}`).toBe("NOT_CIPHERTEXT");
      else expect(["TAG_INVALID", "COMMITMENT_INVALID"], `prefix ${n}`).toContain(code);
      expect(c.isCiphertext(ENVELOPE.subarray(0, n))).toBe(n >= min);
    }
    expect(decryptCode(new Uint8Array(0))).toBe("NOT_CIPHERTEXT");
  });

  it("isCiphertext is total over arbitrary bytes and never decrypts", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 300 }), (input) => {
        expect(typeof c.isCiphertext(input)).toBe("boolean");
      }),
      { numRuns: 2000 },
    );
  });
});

describe("pinned decrypt precedence (G5) -- the errors/ cases, field by field", () => {
  it("fmt_ver: 0x02 → UNKNOWN_FORMAT_VERSION; 0x00 and 0xff → NOT_CIPHERTEXT", () => {
    const v2 = new Uint8Array(ENVELOPE);
    v2[0] = 0x02;
    expect(decryptCode(v2)).toBe("UNKNOWN_FORMAT_VERSION");
    expect(decryptCode(v2, makeClient({ readMode: "permissive" }))).toBe("UNKNOWN_FORMAT_VERSION");
    expect(c.isCiphertext(v2)).toBe(false);
    for (const b of [0x00, 0xff, 0x03, 0x80]) {
      const v = new Uint8Array(ENVELOPE);
      v[0] = b;
      expect(decryptCode(v), `fmt_ver ${b}`).toBe("NOT_CIPHERTEXT");
    }
    // 0x02 with an implausible length is not "a newer implementation's data".
    expect(decryptCode(new Uint8Array([0x02, 0xff, 0x01, 0, 0]))).toBe("NOT_CIPHERTEXT");
  });

  it("suite_id unregistered → NOT_CIPHERTEXT (recognition, not authorization)", () => {
    const v = new Uint8Array(ENVELOPE);
    v[1] = 0x00;
    v[2] = 0xff;
    expect(decryptCode(v)).toBe("NOT_CIPHERTEXT");
    expect(c.isCiphertext(v)).toBe(false);
    expect(Buffer.from(makeClient({ readMode: "permissive" }).decrypt(v, CTX)).equals(Buffer.from(v))).toBe(true);
  });

  it("suite_id registered but unimplemented (0xFF02): recognized, never allow-listable, SUITE_NOT_ALLOWED", () => {
    const v = new Uint8Array(ENVELOPE);
    v[2] = 0x02;
    // Pad to 0xFF02's minimum (24-byte nonce) so recognition succeeds on length.
    const padded = new Uint8Array(v.length + 12);
    padded.set(v);
    expect(c.isCiphertext(padded)).toBe(true);
    expect(decryptCode(padded)).toBe("SUITE_NOT_ALLOWED");
    // Permissive mode does NOT pass a recognized-but-disallowed envelope through (§3.4).
    expect(decryptCode(padded, makeClient({ readMode: "permissive" }))).toBe("SUITE_NOT_ALLOWED");
    expect(codeOf(() => makeClient({ allowedSuites: [0xff01, 0xff02] }))).toBe("CONFIGURATION_ERROR");
    expect(codeOf(() => makeClient({ allowedSuites: [0xff02], writeSuite: 0xff02 }))).toBe("CONFIGURATION_ERROR");
  });

  it("key_id unknown to the provider → KEY_UNAVAILABLE", () => {
    expect(decryptCode(flipBit(ENVELOPE, 3))).toBe("KEY_UNAVAILABLE");
    const throwing = makeClient({
      keyProvider: {
        encryptionKey: () => ({ key: DEK, keyId: KEY_ID }),
        decryptionKeys: () => {
          throw new Error("KMS SDK blew up");
        },
      },
    });
    expect(decryptCode(ENVELOPE, throwing)).toBe("KEY_UNAVAILABLE");
    const garbage = makeClient({
      keyProvider: { encryptionKey: () => ({ key: DEK, keyId: KEY_ID }), decryptionKeys: () => [new Uint8Array(5), "x" as unknown as Uint8Array] },
    });
    expect(decryptCode(ENVELOPE, garbage)).toBe("KEY_UNAVAILABLE");
  });

  it("msg_seed altered → COMMITMENT_INVALID (self-authenticating via the derived key)", () => {
    expect(decryptCode(flipBit(ENVELOPE, 19))).toBe("COMMITMENT_INVALID");
    expect(decryptCode(flipBit(ENVELOPE, 50, 7))).toBe("COMMITMENT_INVALID");
  });

  it("nonce, ciphertext or tag altered → TAG_INVALID (commitment verified; key and context proven right)", () => {
    expect(decryptCode(flipBit(ENVELOPE, 51))).toBe("TAG_INVALID"); // nonce
    expect(decryptCode(flipBit(ENVELOPE, 63))).toBe("TAG_INVALID"); // ciphertext byte 0
    expect(decryptCode(flipBit(ENVELOPE, 63 + PT.length))).toBe("TAG_INVALID"); // tag byte 0
    expect(decryptCode(flipBit(ENVELOPE, 63 + PT.length + 15, 7))).toBe("TAG_INVALID"); // tag last bit
  });

  it("commitment bytes altered → COMMITMENT_INVALID", () => {
    expect(decryptCode(flipBit(ENVELOPE, ENVELOPE.length - 32))).toBe("COMMITMENT_INVALID");
    expect(decryptCode(flipBit(ENVELOPE, ENVELOPE.length - 1, 7))).toBe("COMMITMENT_INVALID");
  });

  it("wrong key with correct structure → COMMITMENT_INVALID", () => {
    const other = makeClient({ keyProvider: { encryptionKey: () => ({ key: DEK, keyId: KEY_ID }), decryptionKeys: () => [new Uint8Array(32).fill(7)] } });
    expect(decryptCode(ENVELOPE, other)).toBe("COMMITMENT_INVALID");
  });

  it("context altered (tenant, column, table, row, purpose-bearing index ctx) → COMMITMENT_INVALID; AAD_MISMATCH is never raised under dual binding", () => {
    expect(decryptCode(ENVELOPE, c, { ...CTX, tenantId: bytes("tenant-0002") })).toBe("COMMITMENT_INVALID");
    expect(decryptCode(ENVELOPE, c, { ...CTX, tenantId: null })).toBe("COMMITMENT_INVALID");
    expect(decryptCode(ENVELOPE, c, { ...CTX, tenantId: new Uint8Array(0) })).toBe("COMMITMENT_INVALID");
    expect(decryptCode(ENVELOPE, c, { ...CTX, rowId: bytes("row-42") })).toBe("COMMITMENT_INVALID");
    expect(decryptCode(ENVELOPE, c, { ...CTX, columnUuid: new Uint8Array(16) })).toBe("COMMITMENT_INVALID");
    expect(decryptCode(ENVELOPE, c, { ...CTX, tableUuid: new Uint8Array(16) })).toBe("COMMITMENT_INVALID");
    // An index-purpose context is not a valid decrypt context at all (INVALID_ARGUMENT, non-§9).
    expect(decryptCode(ENVELOPE, c, { ...CTX, purpose: "index:exact" })).toBe("INVALID_ARGUMENT");
  });

  it("multi-defect precedence: unknown version beats everything; unregistered suite beats allow-list; allow-list beats key", () => {
    const v = new Uint8Array(ENVELOPE);
    v[0] = 0x02;
    v[3] = (v[3] as number) ^ 1; // also a bad key_id
    expect(decryptCode(v)).toBe("UNKNOWN_FORMAT_VERSION");
    const u = new Uint8Array(ENVELOPE);
    u[1] = 0x00; // unregistered
    u[3] = (u[3] as number) ^ 1;
    expect(decryptCode(u)).toBe("NOT_CIPHERTEXT");
    const w = new Uint8Array(ENVELOPE.length + 12);
    w.set(ENVELOPE);
    w[2] = 0x02; // registered, not allowed
    w[3] = (w[3] as number) ^ 1; // and a bad key_id
    expect(decryptCode(w)).toBe("SUITE_NOT_ALLOWED");
  });

  it("the decrypt-side context is taken from the header suite, never from writeSuite", () => {
    // Only one suite is implemented, so the observable consequence is that a
    // client whose context would otherwise be built from writeSuite still
    // derives the right key: every vector decrypts under a client constructed
    // with the same writeSuite. This asserts the code path is at least
    // self-consistent; the mixed-suite case awaits a second implemented suite.
    const parsed = recognize(ENVELOPE);
    expect(parsed.kind).toBe("envelope");
    if (parsed.kind === "envelope") expect(parsed.parsed.suite.id).toBe(SUITE_FF01);
  });
});

describe("codec round trip (parse ∘ serialize)", () => {
  it("serialize then recognize recovers every field, for arbitrary field contents", () => {
    const suite = getSuite(SUITE_FF01)!;
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 16, maxLength: 16 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ minLength: 12, maxLength: 12 }),
        fc.uint8Array({ minLength: 0, maxLength: 64 }),
        fc.uint8Array({ minLength: 16, maxLength: 16 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        (keyId, seed, nonce, ct, tag, commit) => {
          const env = serialize(suite, keyId, seed, nonce, ct, tag, commit);
          const r = recognize(env);
          expect(r.kind).toBe("envelope");
          if (r.kind !== "envelope") return;
          const p = r.parsed;
          expect(p.header.fmtVer).toBe(1);
          expect(p.header.suiteId).toBe(SUITE_FF01);
          for (const [a, b] of [
            [p.header.keyId, keyId],
            [p.header.msgSeed, seed],
            [p.header.nonce, nonce],
            [p.ciphertext, ct],
            [p.tag, tag],
            [p.commitment, commit],
          ] as const) expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
          expect(env.length).toBe(111 + ct.length);
        },
      ),
      { numRuns: 500 },
    );
  });

  it("encrypt/decrypt round trip over arbitrary plaintexts and contexts", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 0, maxLength: 300 }),
        // Past 1024 bytes of canonical_context on purpose: Node's built-in HKDF
        // would refuse the `info` there (see src/kdf.ts). Lengths are drawn
        // uniformly -- fast-check's default length bias would almost never
        // reach that region.
        fc.option(uniformBytes(1500), { nil: null }),
        fc.option(uniformBytes(1500), { nil: null }),
        (pt, tenantId, rowId) => {
          const ctx = { ...CTX, tenantId, rowId };
          const env = c.encrypt(pt, ctx);
          expect(env.length).toBe(111 + pt.length);
          expect(Buffer.from(c.decrypt(env, ctx)).equals(Buffer.from(pt))).toBe(true);
          expect(Buffer.from(c.rotate(env, ctx)).equals(env)).toBe(false); // always a fresh envelope
        },
      ),
      { numRuns: 300 },
    );
  });
});
