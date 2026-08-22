/**
 * Primitive-layer checks against external, already-published known answers
 * (docs/08 §7), so that agreement with the pinned vectors is not the only
 * evidence the primitives are right:
 *
 *   HKDF        RFC 5869 §A.1-A.3 (SHA-256; the RFC has no SHA-512 vectors, so the
 *               SHA-512 path is cross-checked against node:crypto.hkdfSync where
 *               that accepts the input, and against a hand-rolled expand beyond
 *               hkdfSync's 1024-byte info ceiling)
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
import { InvalidArgumentError } from "../src/errors.ts";
import { HKDF_SHA512_MAX_LEN, hkdf, hkdfSha512 } from "../src/kdf.ts";
import { caseFoldFull, normalize, CASEFOLD_UNICODE_VERSION } from "../src/normalize.ts";
import { bytes, hex } from "./helpers.ts";

describe("HKDF", () => {
  // RFC 5869 Appendix A. The algorithm is implemented over createHmac in
  // src/kdf.ts (Node's hkdfSync and Web Crypto deriveBits both cap `info` at
  // 1024 bytes, which canonical_context can exceed), so it is pinned to the
  // RFC's published answers directly rather than to Node's implementation.
  const A1 = {
    ikm: hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    salt: hex("000102030405060708090a0b0c"),
    info: hex("f0f1f2f3f4f5f6f7f8f9"),
    len: 42,
    okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
  };
  const A2 = {
    ikm: new Uint8Array(80).map((_, i) => i),
    salt: new Uint8Array(80).map((_, i) => 0x60 + i),
    info: new Uint8Array(80).map((_, i) => 0xb0 + i),
    len: 82,
    okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
  };
  const A3 = {
    ikm: hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    salt: new Uint8Array(0),
    info: new Uint8Array(0),
    len: 42,
    okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
  };

  it("RFC 5869 A.1, A.2 (multi-block, 80-byte inputs), A.3 (empty salt and info) -- SHA-256", () => {
    for (const v of [A1, A2, A3]) {
      expect(Buffer.from(hkdf("sha256", 32, v.ikm, v.salt, v.info, v.len)).toString("hex")).toBe(v.okm);
    }
  });

  it("RFC 5869 A.1 -- argument order of node:crypto.hkdfSync, the oracle used below", () => {
    const okm = new Uint8Array(hkdfSync("sha256", A1.ikm, A1.salt, A1.info, A1.len));
    expect(Buffer.from(okm).toString("hex")).toBe(A1.okm);
  });

  it("hkdfSha512 equals node:crypto.hkdfSync on every input hkdfSync accepts (info <= 1024 bytes)", () => {
    for (const [ikm, salt, info, len] of [
      [bytes("ikm"), new Uint8Array(0), bytes("fieldseal-commit-v1"), 32],
      [new Uint8Array(32).fill(1), new Uint8Array(48).fill(2), new Uint8Array(90).fill(3), 32],
      [new Uint8Array(32), bytes("fieldseal-index-v1"), bytes("x"), 100],
      [bytes("k"), new Uint8Array(0), bytes("fieldseal-argon2-salt-v1"), 16],
      [new Uint8Array(32).fill(7), new Uint8Array(64).fill(8), new Uint8Array(1024).fill(9), 64], // hkdfSync's ceiling
      [new Uint8Array(32).fill(7), new Uint8Array(64).fill(8), new Uint8Array(1024).fill(9), 200], // four blocks
    ] as const) {
      const expected = new Uint8Array(hkdfSync("sha512", ikm, salt, info, len));
      expect(Buffer.from(hkdfSha512(ikm, salt, info, len)).equals(Buffer.from(expected))).toBe(true);
    }
  });

  it("hkdfSha512 accepts info longer than 1024 bytes (canonical_context is unbounded, spec §6.1)", () => {
    // hkdfSync refuses this input; the reference is an independently written
    // RFC 5869 expand over createHmac, so the two implementations share only
    // the primitive.
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
    for (const infoLen of [1025, 2082, 70_000]) {
      const ikm = new Uint8Array(32).fill(0x11);
      const salt = new Uint8Array(48).fill(0x22);
      const info = new Uint8Array(infoLen).map((_, i) => i & 0xff);
      expect(() => hkdfSync("sha512", ikm, salt, info, 32)).toThrow(/1024/);
      expect(Buffer.from(hkdfSha512(ikm, salt, info, 32)).equals(Buffer.from(hand(ikm, salt, info, 32)))).toBe(true);
    }
  });

  it("output length is bounded by RFC 5869 §2.3 (L <= 255 * HashLen) with a typed error", () => {
    expect(hkdfSha512(bytes("ikm"), new Uint8Array(0), bytes("info"), HKDF_SHA512_MAX_LEN).length).toBe(HKDF_SHA512_MAX_LEN);
    for (const bad of [0, -1, 1.5, HKDF_SHA512_MAX_LEN + 1]) {
      expect(() => hkdfSha512(bytes("ikm"), new Uint8Array(0), bytes("info"), bad)).toThrow(InvalidArgumentError);
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
