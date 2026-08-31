/**
 * The closed, versioned normalizer set (docs/09 §7). Normalizers affect stored
 * index values and are therefore portability surface: every core ships
 * exactly these, identically.
 *
 *   identity          bytes unchanged
 *   nfc-casefold-v1   UTF-8 decode → Unicode NFC → full case folding → UTF-8 encode
 *   digits-only-v1    strip every byte that is not an ASCII digit
 *
 * `nfc-casefold-v1` is pinned to Unicode 17.0.0 for both steps, from tables
 * vendored under `unicode/` rather than from the platform: folding via
 * `toLowerCase` would be locale-sensitive and is not full folding (it maps
 * "ß" to "ß", where full folding maps it to "ss"), and NFC via
 * `String.prototype.normalize` would follow whatever ICU the runtime was
 * built against. Either dependency turns a Node upgrade into a silent change
 * of stored index values.
 */

import { InvalidArgumentError } from "./errors.ts";
import { UNICODE_VERSION, caseFoldFull, firstUnassigned, nfc } from "./unicode/index.ts";

export const NORMALIZER_IDS = ["identity", "nfc-casefold-v1", "digits-only-v1"] as const;
export type NormalizerId = (typeof NORMALIZER_IDS)[number];

export function isNormalizerId(s: string): s is NormalizerId {
  return (NORMALIZER_IDS as readonly string[]).includes(s);
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const utf8Encoder = new TextEncoder();

/**
 * UTF-8 encode, refusing an unpaired surrogate instead of substituting for it.
 *
 * `TextEncoder` is required by WHATWG Encoding to emit U+FFFD for an unpaired
 * surrogate rather than to fail, so `encode("a\uD800b")` and `encode("a\uDC00b")`
 * are the same three code points and the same five bytes. Two distinct values,
 * one index: a false-match primitive in the feature built to prevent false
 * matches (docs/09 §7.1, G16 part A).
 *
 * The realistic source is not an attacker. It is fixed-length truncation of a
 * JavaScript string, whose naive form splits surrogate pairs — which is most
 * emoji and every supplementary-plane script.
 */
export function encodeUtf8Strict(text: string): Uint8Array {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = text.charCodeAt(i + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) {
        throw new InvalidArgumentError(
          `value contains an unpaired high surrogate U+${unit.toString(16).toUpperCase()} at index ${i}; ` +
            "it has no UTF-8 encoding, and encoding it as U+FFFD would give distinct values the same index",
        );
      }
      i++; // a well-formed pair; skip its low half
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new InvalidArgumentError(
        `value contains an unpaired low surrogate U+${unit.toString(16).toUpperCase()} at index ${i}; ` +
          "it has no UTF-8 encoding, and encoding it as U+FFFD would give distinct values the same index",
      );
    }
  }
  return utf8Encoder.encode(text);
}

export function normalizeNfcCasefoldV1(input: string | Uint8Array): Uint8Array {
  let text: string;
  if (typeof input === "string") {
    // A text-typed input reaches clause 1 directly (docs/09 §7.1 clause 5).
    // Nothing has been lost yet, so the lone-surrogate case is still visible:
    // `firstUnassigned` counts surrogates as unassigned, and reports *which*
    // one, so two distinct malformed values stay distinguishable.
    text = input;
  } else {
    try {
      text = utf8Decoder.decode(input);
    } catch {
      // Decoding with replacement characters would map distinct malformed
      // inputs onto one index value, which is a false-match primitive rather
      // than a leniency (docs/09 §7).
      throw new InvalidArgumentError("nfc-casefold-v1 requires valid UTF-8 input; refusing to normalize undecodable bytes");
    }
  }
  const stray = firstUnassigned(text);
  if (stray !== undefined) {
    // A code point the pinned version does not define has no fixed
    // normalization yet, so a core built against a later UCD would index it
    // differently. Refusing is visible; disagreeing is not.
    throw new InvalidArgumentError(
      `value contains U+${stray.codePoint.toString(16).toUpperCase().padStart(4, "0")}, which is not assigned in ` +
        `Unicode ${UNICODE_VERSION}; \`nfc-casefold-v1\` is pinned to that version and cannot index a ` +
        "character it does not define",
    );
  }
  // docs/09 §7: NFC, full case folding, NFC again, then UTF-8.
  //
  // The second NFC is what makes this a caseless-matching function rather
  // than merely a deterministic one. Folding a precomposed character can
  // yield a decomposed sequence, so without it the same letter in two cases
  // lands on two index values: U+0390 folds to U+03B9 U+0308 U+0301, while
  // its uppercase spelling U+03AA U+0301 folds to U+03CA U+0301 -- one
  // lookup to a user, two blind indexes to the database.
  //
  // This is not Unicode's canonical caseless match, which is
  // NFD(toCasefold(NFD(X))) and outputs NFD; this outputs NFC, which is
  // shorter as a stored value.
  return utf8Encoder.encode(nfc(caseFoldFull(nfc(text))));
}

export function normalizeDigitsOnlyV1(input: string | Uint8Array): Uint8Array {
  const bytes = typeof input === "string" ? encodeUtf8Strict(input) : input;
  let n = 0;
  for (const b of bytes) if (b >= 0x30 && b <= 0x39) n++;
  const out = new Uint8Array(n);
  let o = 0;
  for (const b of bytes) if (b >= 0x30 && b <= 0x39) out[o++] = b;
  return out;
}

export function normalize(id: NormalizerId, input: string | Uint8Array): Uint8Array {
  switch (id) {
    case "identity":
      // `identity` is byte-transparent, so text is simply its UTF-8 encoding —
      // but strictly, since substituting for an unpaired surrogate here would
      // reintroduce the collision `nfc-casefold-v1` refuses (docs/09 §7.1).
      return typeof input === "string" ? encodeUtf8Strict(input) : input;
    case "nfc-casefold-v1":
      return normalizeNfcCasefoldV1(input);
    case "digits-only-v1":
      return normalizeDigitsOnlyV1(input);
  }
}

export { UNICODE_VERSION, caseFoldFull, firstUnassigned, nfc };
export type { Unassigned } from "./unicode/index.ts";

/** @deprecated the pin now covers normalization as well as folding; use
 * `UNICODE_VERSION`. Kept so the conformance harness keeps building across
 * the G15 closure. */
export const CASEFOLD_UNICODE_VERSION = UNICODE_VERSION;
