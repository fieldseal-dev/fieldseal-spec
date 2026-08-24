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

export function normalizeNfcCasefoldV1(input: Uint8Array): Uint8Array {
  let text: string;
  try {
    text = utf8Decoder.decode(input);
  } catch {
    // Decoding with replacement characters would map distinct malformed
    // inputs onto one index value, which is a false-match primitive rather
    // than a leniency (docs/09 §7).
    throw new InvalidArgumentError("nfc-casefold-v1 requires valid UTF-8 input; refusing to normalize undecodable bytes");
  }
  const stray = firstUnassigned(text);
  if (stray !== undefined) {
    // A code point the pinned version does not define has no fixed
    // normalization yet, so a core built against a later UCD would index it
    // differently. Refusing is visible; disagreeing is not.
    throw new InvalidArgumentError(
      `value contains U+${stray.toString(16).toUpperCase().padStart(4, "0")}, which is not assigned in ` +
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

export function normalizeDigitsOnlyV1(input: Uint8Array): Uint8Array {
  let n = 0;
  for (const b of input) if (b >= 0x30 && b <= 0x39) n++;
  const out = new Uint8Array(n);
  let o = 0;
  for (const b of input) if (b >= 0x30 && b <= 0x39) out[o++] = b;
  return out;
}

export function normalize(id: NormalizerId, input: Uint8Array): Uint8Array {
  switch (id) {
    case "identity":
      return input;
    case "nfc-casefold-v1":
      return normalizeNfcCasefoldV1(input);
    case "digits-only-v1":
      return normalizeDigitsOnlyV1(input);
  }
}

export { UNICODE_VERSION, caseFoldFull, firstUnassigned, nfc };

/** @deprecated the pin now covers normalization as well as folding; use
 * `UNICODE_VERSION`. Kept so the conformance harness keeps building across
 * the G15 closure. */
export const CASEFOLD_UNICODE_VERSION = UNICODE_VERSION;
