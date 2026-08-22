/**
 * Primitive-layer checks against external, already-published known answers
 * (docs/08 §7), so that agreement with the pinned vectors is not the only
 * evidence the primitives are right:
 *
 *   HKDF        RFC 5869 §A.1 test case 1 (SHA-256; the RFC has no SHA-512 vectors,
 *               so the SHA-512 path is cross-checked against a hand-rolled expand)
 *   AES-256-GCM The GCM specification's test cases 13 and 14 (McGrew–Viega),
 *               which NIST's CAVP GCM suite also contains
 *   Argon2id    RFC 9106 §5.3 -- reproducible on THIS stack because node:crypto
 *               accepts the vector's secret and associated data
 *   truncate    the worked example in spec §7.2
 *   casefold    Unicode full case folding behaviors the platform's toLowerCase lacks
 */

import { argon2Sync, createHmac, hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { gcmOpen, gcmSeal } from "../src/aead/gcm.ts";
import { ARGON2_P, ARGON2_VERSION, truncateBits } from "../src/blindindex.ts";
import { hkdfSha512 } from "../src/kdf.ts";
import { caseFoldFull, normalize, CASEFOLD_UNICODE_VERSION } from "../src/normalize.ts";
import { bytes, hex } from "./helpers.ts";

describe("HKDF", () => {
  it("RFC 5869 A.1 test case 1 (SHA-256) -- argument order of hkdfSync", () => {
    const okm = new Uint8Array(
      hkdfSync("sha256", hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), hex("000102030405060708090a0b0c"), hex("f0f1f2f3f4f5f6f7f8f9"), 42),
    );
    expect(Buffer.from(okm).toString("hex")).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("hkdfSha512 equals a hand-rolled RFC 5869 extract-then-expand over createHmac", () => {
    const hand = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Uint8Array => {
      const prk = createHmac("sha512", salt).update(ikm).digest();
      const out: Buffer[] = [];
      let t = Buffer.alloc(0);
      for (let i = 1; out.reduce((n, b) => n + b.length, 0) < len; i++) {
        t = createHmac("sha512", prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
        out.push(t);
      }
      return new Uint8Array(Buffer.concat(out).subarray(0, len));
    };
    for (const [ikm, salt, info, len] of [
      [bytes("ikm"), new Uint8Array(0), bytes("fieldseal-commit-v1"), 32],
      [new Uint8Array(32).fill(1), new Uint8Array(48).fill(2), new Uint8Array(90).fill(3), 32],
      [new Uint8Array(32), bytes("fieldseal-index-v1"), bytes("x"), 100],
      [bytes("k"), new Uint8Array(0), bytes("fieldseal-argon2-salt-v1"), 16],
    ] as const) {
      expect(Buffer.from(hkdfSha512(ikm, salt, info, len)).equals(Buffer.from(hand(ikm, salt, info, len)))).toBe(true);
    }
  });

  it('salt = "" and salt = 64 zero bytes are the same HMAC key (RFC 5869 §2.2)', () => {
    const a = hkdfSha512(bytes("ikm"), new Uint8Array(0), bytes("info"), 32);
    const b = hkdfSha512(bytes("ikm"), new Uint8Array(64), bytes("info"), 32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });
});

describe("AES-256-GCM", () => {
  const K = new Uint8Array(32);
  const IV = new Uint8Array(12);
  it("GCM spec test case 13: empty plaintext, empty AAD", () => {
    const { ciphertext, tag } = gcmSeal(K, IV, new Uint8Array(0), new Uint8Array(0));
    expect(ciphertext.length).toBe(0);
    expect(Buffer.from(tag).toString("hex")).toBe("530f8afbc74536b9a963b4f1c4cb738b");
  });
  it("GCM spec test case 14: one zero block", () => {
    const { ciphertext, tag } = gcmSeal(K, IV, new Uint8Array(16), new Uint8Array(0));
    expect(Buffer.from(ciphertext).toString("hex")).toBe("cea7403d4d606b6e074ec5d3baf39d18");
    expect(Buffer.from(tag).toString("hex")).toBe("d0d1c8a799996bf0265b98b5d48ab919");
    expect(Buffer.from(gcmOpen(K, IV, ciphertext, tag, new Uint8Array(0))!).equals(Buffer.alloc(16))).toBe(true);
  });
  it("open returns null (never throws) on any tag or AAD alteration", () => {
    const { ciphertext, tag } = gcmSeal(K, IV, bytes("hello"), bytes("aad"));
    const badTag = new Uint8Array(tag);
    badTag[0] = (badTag[0] as number) ^ 1;
    expect(gcmOpen(K, IV, ciphertext, badTag, bytes("aad"))).toBeNull();
    expect(gcmOpen(K, IV, ciphertext, tag, bytes("aad!"))).toBeNull();
    expect(gcmOpen(K, IV, ciphertext, tag.subarray(0, 12), bytes("aad"))).toBeNull();
    expect(Buffer.from(gcmOpen(K, IV, ciphertext, tag, bytes("aad"))!).toString()).toBe("hello");
  });
});

describe("Argon2id (node:crypto backend)", () => {
  it("reproduces RFC 9106 §5.3 exactly (v=0x13, m=32 KiB, t=3, p=4, with the RFC's secret and associated data)", () => {
    // This is the external known-answer check docs/08 §7 and MANIFEST.held_out
    // say is unreproducible "on this stack" -- it is on the Node stack,
    // because node:crypto takes `secret` (K) and `associatedData` (X). The
    // Fieldseal invocation itself forbids both; this verifies the primitive,
    // not the invocation.
    const out = argon2Sync("argon2id", {
      message: new Uint8Array(32).fill(1),
      nonce: new Uint8Array(16).fill(2),
      secret: new Uint8Array(8).fill(3),
      associatedData: new Uint8Array(12).fill(4),
      parallelism: 4,
      tagLength: 32,
      memory: 32,
      passes: 3,
    });
    expect(Buffer.from(out).toString("hex")).toBe("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
  });
  it("the backend constants match spec §7.3", () => {
    expect(ARGON2_VERSION).toBe(0x13);
    expect(ARGON2_P).toBe(1);
  });
});

describe("truncate(raw, b) -- spec §7.2", () => {
  it("worked example: truncate(0xABCD…, 12 bits) = 0xABC0", () => {
    expect(Buffer.from(truncateBits(hex("abcdef0123"), 12)).toString("hex")).toBe("abc0");
  });
  it("length is exactly ⌈b/8⌉ and trailing bits are zero, MSB-first", () => {
    const raw = new Uint8Array(64).fill(0xff);
    for (const [b, want] of [
      [1, "80"],
      [7, "fe"],
      [8, "ff"],
      [9, "ff80"],
      [12, "fff0"],
      [15, "fffe"],
      [16, "ffff"],
      [21, "fffff8"],
      [30, "fffffffc"],
    ] as const) {
      expect(Buffer.from(truncateBits(raw, b)).toString("hex"), `b=${b}`).toBe(want);
    }
    expect(() => truncateBits(raw, 0)).toThrow();
    expect(() => truncateBits(raw, 513)).toThrow();
  });
  it("does not alias the input", () => {
    const raw = new Uint8Array(64).fill(0xff);
    const t = truncateBits(raw, 16);
    t[0] = 0;
    expect(raw[0]).toBe(0xff);
  });
});

describe("normalizers", () => {
  it(`nfc-casefold-v1 uses a vendored full case folding table (Unicode ${CASEFOLD_UNICODE_VERSION})`, () => {
    expect(caseFoldFull("Straße")).toBe("strasse"); // ß → ss (F mapping); toLowerCase keeps ß
    expect(caseFoldFull("İ")).toBe("i̇"); // U+0130 → i + combining dot (F), no Turkic special case
    expect(caseFoldFull("ΣΑΣ")).toBe("σασ"); // no final-sigma context rule in folding
    expect(caseFoldFull("Ꭰ")).toBe("Ꭰ"); // Cherokee: uppercase is the folded form (C maps AB70 → 13A0)
    expect(caseFoldFull("ꭰ")).toBe("Ꭰ");
    expect(caseFoldFull("ǅ")).toBe("ǆ");
    expect(Buffer.from(normalize("nfc-casefold-v1", bytes("grüße@example.com"))).toString("hex")).toBe(
      Buffer.from("grüsse@example.com").toString("hex"),
    );
  });
  it("nfc-casefold-v1 composes to NFC before folding", () => {
    const decomposed = "ü"; // ü as u + combining diaeresis
    expect(Buffer.from(normalize("nfc-casefold-v1", bytes(decomposed))).equals(Buffer.from("ü"))).toBe(true);
  });
  it("nfc-casefold-v1 refuses invalid UTF-8 with a typed error", () => {
    expect(() => normalize("nfc-casefold-v1", new Uint8Array([0xff, 0xfe]))).toThrow(/valid UTF-8/);
  });
  it("digits-only-v1 strips every non-digit byte", () => {
    expect(Buffer.from(normalize("digits-only-v1", bytes("+1 (555) 010-2345"))).toString()).toBe("15550102345");
    expect(normalize("digits-only-v1", bytes("abc")).length).toBe(0);
  });
  it("identity returns the bytes unchanged", () => {
    const b = bytes("AbC");
    expect(normalize("identity", b)).toBe(b);
  });
});
