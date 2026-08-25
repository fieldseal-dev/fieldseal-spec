/**
 * The vendored Unicode tables (docs/09 §7).
 *
 * `nfc-casefold-v1` is pinned to Unicode 17.0.0 and this core reads vendored
 * tables rather than the platform's. docs/09 §7 permits a core to take NFC
 * from the platform only when the platform's version is at least the pin
 * *and* the core proves agreement exhaustively in its own tests. This core
 * does not take that route, but it runs the proof anyway: if the vendored
 * NFC and a platform whose ICU is new enough ever disagreed, one of them
 * would be wrong, and finding out here is much cheaper than finding out from
 * a blind index that silently stops matching.
 *
 * Test data is derived from the tables themselves rather than pasted in, so
 * these checks stay meaningful when the pin is bumped.
 */

import { describe, expect, it } from "vitest";
import {
  ASSIGNED_RANGE_COUNT,
  CASEFOLD_ENTRY_COUNT,
  DECOMPOSITION_COUNT,
  UNICODE_VERSION,
  caseFoldFull,
  firstUnassigned,
  nfc,
} from "../src/unicode/index.ts";
import { normalize } from "../src/normalize.ts";
import { InvalidArgumentError } from "../src/errors.ts";

const dec = new TextDecoder();
const enc = new TextEncoder();
/** Through the bytes path: the caller encodes, which is the lossy route. */
const N = (s: string): string => dec.decode(normalize("nfc-casefold-v1", enc.encode(s)));
/** Through the text path: the normalizer sees the string (docs/09 §7.1 clause 5). */
const NT = (s: string): string => dec.decode(normalize("nfc-casefold-v1", s));
const hex = (s: string): string =>
  [...s].map((c) => "U+" + c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")).join(" ");

/** The platform is only a valid cross-check when its Unicode is at least the pin. */
const platformVersion = process.versions.unicode ?? "0";
const cmp = (a: string, b: string): number => {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
};
const platformQualifies = cmp(platformVersion, UNICODE_VERSION) >= 0;

describe("vendored Unicode tables", () => {
  it("carries the pinned version and the expected table sizes", () => {
    expect(UNICODE_VERSION).toBe("17.0.0");
    expect(CASEFOLD_ENTRY_COUNT).toBe(1585);
    expect(ASSIGNED_RANGE_COUNT).toBe(743);
    expect(DECOMPOSITION_COUNT).toBe(2081);
  });

  it("folds fully (C+F), not simply, and without the Turkic mappings", () => {
    expect(caseFoldFull("Straße")).toBe("strasse"); // ß → ss is the F mapping
    expect(caseFoldFull("İ")).toBe("i̇"); // U+0130 → i + U+0307, no Turkic special case
    expect(caseFoldFull("ΣΑΣ")).toBe("σασ"); // folding has no final-sigma context rule
    expect(caseFoldFull("ǅ")).toBe("ǆ");
    expect(caseFoldFull("ꭰ")).toBe("Ꭰ"); // Cherokee: the C mapping folds to the uppercase form
  });

  it("recognises code points the pin does not define", () => {
    expect(firstUnassigned("plain ascii")).toBeUndefined();
    expect(firstUnassigned("͸")).toBe(0x378); // unassigned in every version so far
    expect(firstUnassigned("﷐")).toBe(0xfdd0); // noncharacter
    expect(firstUnassigned("a\uD800b")).toBe(0xd800); // lone surrogate: no UTF-8 form
    expect(firstUnassigned("\u{16EA0}")).toBeUndefined(); // Beria Erfe, added in 17.0
  });
});

describe("nfc-casefold-v1 collides case variants", () => {
  // The reason there is a second NFC after the fold. Folding a precomposed
  // character can produce a decomposed sequence, so one letter in two cases
  // would otherwise land on two index values.
  const pairs: ReadonlyArray<readonly [string, string, string]> = [
    ["ΐ", "Ϊ́", "iota with dialytika and tonos"],
    ["ΰ", "Ϋ́", "upsilon with dialytika and tonos"],
    ["ΐ", "Ϊ́", "U+1FD3 shares U+0390's decomposition"],
    ["ΰ", "Ϋ́", "U+1FE3 shares U+03B0's decomposition"],
    ["ǰ", "ǰ", "j with caron, precomposed vs decomposed"],
    ["straße", "STRASSE", "ß folds to ss"],
    ["ẖ", "ẖ", "h with line below"],
  ];

  for (const [a, b, why] of pairs) {
    it(`${hex(a)} == ${hex(b)} (${why})`, () => {
      expect(N(a)).toBe(N(b));
    });
  }

  it("U+0390 normalises to itself rather than to a decomposed sequence", () => {
    // Without the post-fold NFC this would be U+03B9 U+0308 U+0301.
    expect(hex(N("ΐ"))).toBe("U+0390");
    expect(hex(N("Ϊ́"))).toBe("U+0390");
  });

  it("is idempotent", () => {
    for (const [a] of pairs) expect(N(N(a))).toBe(N(a));
  });

  it("refuses invalid UTF-8 rather than folding it through U+FFFD", () => {
    expect(() => normalize("nfc-casefold-v1", new Uint8Array([0xff, 0xfe]))).toThrow(InvalidArgumentError);
  });

  it("refuses code points the pin does not define", () => {
    expect(() => N("͸")).toThrow(InvalidArgumentError);
  });

  it("the bytes path still cannot see a lone surrogate -- the platform destroys it first", () => {
    // Unchanged platform fact, and the whole reason the text path exists.
    // WHATWG Encoding requires `TextEncoder` to substitute U+FFFD for an
    // unpaired surrogate rather than to fail, and U+FFFD is an assigned
    // character, so a caller who encodes first hands over well-formed UTF-8
    // in which two distinct values have already become one.
    expect(enc.encode("a\uD800b")).toEqual(enc.encode("a�b"));
    expect(enc.encode("a\uD800b")).toEqual(enc.encode("a\uDC00b"));
    // ...and the normalizer, seeing only those bytes, has nothing to object to.
    expect(N("a\uD800b")).toBe(N("a\uDC00b"));
  });

  it("the text path refuses lone surrogates, and refuses them distinguishably", () => {
    // docs/09 §7.1 clause 5 / G16 part A: the refusal has to happen where the
    // information still exists. Both are rejected -- and, the point of the
    // pair, they are rejected as *different* code points, so no two distinct
    // malformed values can share an index.
    expect(() => NT("a\uD800b")).toThrow(InvalidArgumentError);
    expect(() => NT("a\uDC00b")).toThrow(InvalidArgumentError);
    expect(firstUnassigned("a\uD800b")).toBe(0xd800);
    expect(firstUnassigned("a\uDC00b")).toBe(0xdc00);
    expect(firstUnassigned("a\uD800b")).not.toBe(firstUnassigned("a\uDC00b"));
  });

  it("a legitimate U+FFFD is ordinary text, not an error", () => {
    // The alternative considered and declined in G16 part A was rejecting
    // U+FFFD outright. It is an assigned character; refusing it would turn a
    // false match into an unindexable row, which is the other failure mode.
    expect(NT("a�b")).toBe("a�b");
    expect(NT("a�b")).toBe(N("a�b"));
  });

  it("text and bytes agree wherever both are well formed", () => {
    // Widening the input type must not fork the function. Anything encodable
    // has to normalize identically down either path, or the boundary itself
    // becomes a portability seam.
    for (const s of ["ALICE@example.com", "José", "grüße", "ǰ", "ΐ", "İstanbul", "😀 mixed", ""]) {
      expect(NT(s), s).toBe(N(s));
    }
  });
});

describe("vendored NFC against the platform", () => {
  it(`platform is Unicode ${platformVersion}; pin is ${UNICODE_VERSION}`, () => {
    expect(platformVersion).not.toBe("0");
  });

  it.skipIf(!platformQualifies)("agrees on every single code point", () => {
    const disagree: number[] = [];
    for (let cp = 0; cp < 0x110000; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const ch = String.fromCodePoint(cp);
      if (nfc(ch) !== ch.normalize("NFC")) disagree.push(cp);
    }
    expect(disagree.map((c) => c.toString(16))).toEqual([]);
  });

  it.skipIf(!platformQualifies)("agrees on combining-mark sequences", () => {
    // Ordering and composition are where a hand-rolled NFC goes wrong, so
    // exercise every base that has a canonical decomposition against a
    // spread of combining classes.
    const marks = [0x0300, 0x0301, 0x0308, 0x030c, 0x0327, 0x0342, 0x0345, 0x0316, 0x1ab0];
    const disagree: string[] = [];
    for (let cp = 0; cp < 0x3000; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const base = String.fromCodePoint(cp);
      for (const m of marks) {
        for (const m2 of [0x0301, 0x0316]) {
          const s = base + String.fromCodePoint(m) + String.fromCodePoint(m2);
          if (nfc(s) !== s.normalize("NFC")) disagree.push(hex(s));
        }
      }
    }
    expect(disagree.slice(0, 10)).toEqual([]);
  });

  it.skipIf(!platformQualifies)("agrees on Hangul, which composes algorithmically", () => {
    const disagree: string[] = [];
    for (let cp = 0xac00; cp < 0xd7a4; cp += 7) {
      const ch = String.fromCodePoint(cp);
      const decomposed = ch.normalize("NFD");
      if (nfc(decomposed) !== ch) disagree.push(hex(ch));
    }
    // and jamo sequences that should compose into syllables
    for (let l = 0x1100; l < 0x1113; l++) {
      for (let v = 0x1161; v < 0x1176; v += 3) {
        const s = String.fromCodePoint(l, v);
        if (nfc(s) !== s.normalize("NFC")) disagree.push(hex(s));
      }
    }
    expect(disagree.slice(0, 10)).toEqual([]);
  });
});
