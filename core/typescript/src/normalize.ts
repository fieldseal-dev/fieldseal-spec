/**
 * The closed, versioned normalizer set (docs/09 §7). Normalizers affect stored
 * index values and are therefore portability surface: every core ships
 * exactly these, identically.
 *
 *   identity          bytes unchanged
 *   nfc-casefold-v1   UTF-8 decode → Unicode NFC → full case folding → UTF-8 encode
 *   digits-only-v1    strip every byte that is not an ASCII digit
 *
 * `nfc-casefold-v1` is pinned to a vendored Unicode 17.0.0 CaseFolding.txt
 * (statuses C + F, no Turkic special case) rather than to the platform's
 * `toLowerCase`, which is locale-sensitive and not full folding (it maps
 * "ß" to "ß", where full folding maps it to "ss"; see the non-ascii blind
 * index vector). NFC itself still comes from the platform (`String.prototype
 * .normalize`), whose Unicode version is recorded in the conformance report
 * environment; Unicode's normalization stability policy keeps NFC fixed for
 * assigned characters, so drift there is confined to characters newer than
 * the platform's ICU, which this core documents rather than solves.
 */

import { InvalidArgumentError } from "./errors.ts";
import { CASEFOLD_UNICODE_VERSION, caseFoldTable } from "./unicode/casefold-17.0.0.ts";

export const NORMALIZER_IDS = ["identity", "nfc-casefold-v1", "digits-only-v1"] as const;
export type NormalizerId = (typeof NORMALIZER_IDS)[number];

export function isNormalizerId(s: string): s is NormalizerId {
  return (NORMALIZER_IDS as readonly string[]).includes(s);
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const utf8Encoder = new TextEncoder();

/** Full case folding (Unicode CaseFolding.txt C+F) applied per code point. */
export function caseFoldFull(s: string): string {
  const table = caseFoldTable();
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    const folded = table.get(cp);
    out += folded === undefined ? ch : folded;
  }
  return out;
}

export function normalizeNfcCasefoldV1(input: Uint8Array): Uint8Array {
  let text: string;
  try {
    text = utf8Decoder.decode(input);
  } catch {
    // The spec does not say what nfc-casefold-v1 does with invalid UTF-8.
    // Fail closed: an index derived from a replacement-character rendering
    // would silently collide distinct invalid inputs. Recorded in the
    // divergence report as a specification gap.
    throw new InvalidArgumentError("nfc-casefold-v1 requires valid UTF-8 input; refusing to normalize undecodable bytes");
  }
  // docs/09 §7 literally: NFC, then full case folding, then UTF-8 encode.
  // No second NFC after folding -- Unicode §3.13 notes that toCasefold(X) is
  // not necessarily normalized (which is why canonical caseless matching is
  // defined as NFD(toCasefold(NFD(X)))), so whether a post-fold
  // normalization belongs here is a question for the spec, recorded in the
  // divergence report rather than answered by this core.
  const folded = caseFoldFull(text.normalize("NFC"));
  return utf8Encoder.encode(folded);
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

export { CASEFOLD_UNICODE_VERSION };
