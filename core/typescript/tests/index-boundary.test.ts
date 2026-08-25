/**
 * The index boundary takes text as well as bytes (docs/09 §7.1; G16 part A).
 *
 * `blindIndex` is the one entry point where the difference between a string
 * and its encoding is observable, because `TextEncoder` is required by WHATWG
 * Encoding to substitute U+FFFD for an unpaired surrogate rather than to fail.
 * A caller who encodes first therefore hands over bytes in which two distinct
 * values have already collapsed into one — silently, since U+FFFD is an
 * ordinary assigned character. That is a false match manufactured inside the
 * feature whose entire purpose is to prevent false matches.
 *
 * These tests pin three things: that text and bytes agree wherever both are
 * well formed (widening the type must not fork the function), that the text
 * path refuses what the bytes path cannot see, and that it refuses
 * *distinguishably* — two malformed values must not share a fate any more
 * than they may share an index.
 */

import { describe, expect, it } from "vitest";
import { codeOf, CTX, makeClient } from "./helpers.ts";

const IDX = {
  tableUuid: CTX.tableUuid,
  columnUuid: CTX.columnUuid,
  idf: "hmac-sha512" as const,
  normalize: "nfc-casefold-v1" as const,
  truncateBits: 15,
  projectedPopulation: 65536,
};
const IDX_CTX = { ...CTX, purpose: "index:exact" };

const c = makeClient({ indexes: [IDX] });
const enc = new TextEncoder();
const idxOf = (v: string | Uint8Array): string => Buffer.from(c.blindIndex(v, IDX_CTX)).toString("hex");

describe("blindIndex accepts text as well as bytes", () => {
  it("a string and its own encoding give the same index", () => {
    for (const s of ["alice@example.com", "ALICE@example.com", "José", "grüße", "😀", ""]) {
      expect(idxOf(s), s).toBe(idxOf(enc.encode(s)));
    }
  });

  it("case folding still works through the text path", () => {
    expect(idxOf("ALICE@EXAMPLE.COM")).toBe(idxOf("alice@example.com"));
    // Full folding, not `toLowerCase`: ß folds to ss.
    expect(idxOf("grüße")).toBe(idxOf("GRÜSSE"));
  });

  it("neither text nor bytes is an argument error", () => {
    for (const bad of [42, null, undefined, {}, [1, 2, 3]]) {
      expect(codeOf(() => c.blindIndex(bad as unknown as Uint8Array, IDX_CTX))).toBe("INVALID_ARGUMENT");
    }
  });
});

describe("the false match the text path exists to close", () => {
  it("encoding first collapses two distinct values into one index", () => {
    // The defect, stated as a test rather than as prose. This is what every
    // caller of the old bytes-only signature was being told to do.
    const viaEncoder = (s: string): string => idxOf(enc.encode(s));
    expect(viaEncoder("a\uD800b")).toBe(viaEncoder("a\uDC00b"));
    expect(viaEncoder("a\uD800b")).toBe(viaEncoder("a�b"));
  });

  it("passing the string refuses both, and refuses them differently", () => {
    expect(codeOf(() => c.blindIndex("a\uD800b", IDX_CTX))).toBe("INVALID_ARGUMENT");
    expect(codeOf(() => c.blindIndex("a\uDC00b", IDX_CTX))).toBe("INVALID_ARGUMENT");

    const message = (s: string): string => {
      try {
        c.blindIndex(s, IDX_CTX);
      } catch (e) {
        return (e as Error).message;
      }
      throw new Error("expected a refusal");
    };
    // Same outcome, different diagnosis: a shared error message would leave
    // the two values indistinguishable in exactly the way the index must not.
    expect(message("a\uD800b")).toContain("D800");
    expect(message("a\uDC00b")).toContain("DC00");
    expect(message("a\uD800b")).not.toBe(message("a\uDC00b"));
  });

  it("truncation is the realistic cause, not an attacker", () => {
    // The ordinary way to cap a string's length in JavaScript splits surrogate
    // pairs, which is most emoji and every supplementary-plane script.
    const cut = "😀😀".slice(0, 1);
    expect(cut.length).toBe(1);
    expect(codeOf(() => c.blindIndex(cut, IDX_CTX))).toBe("INVALID_ARGUMENT");
    // Through the encoder it would have indexed cleanly, as U+FFFD.
    expect(idxOf(enc.encode(cut))).toBe(idxOf("�"));
  });

  it("a legitimate U+FFFD indexes normally", () => {
    // Rejecting U+FFFD outright was the alternative declined in G16 part A:
    // it would convert this false match into an unindexable row, which is the
    // other failure mode, and it would still miss truncation that lands on
    // valid text.
    expect(idxOf("a�b")).toBe(idxOf(enc.encode("a�b")));
  });
});

describe("encrypt stays bytes-only, deliberately", () => {
  it("a string is an argument error there", () => {
    // The asymmetry is the point, not an oversight: normalization is a text
    // operation and encryption is not, so `encrypt` has no reason to know
    // about strings and no lossy conversion to protect against.
    expect(codeOf(() => c.encrypt("a string" as unknown as Uint8Array, CTX))).toBe("INVALID_ARGUMENT");
  });
});
