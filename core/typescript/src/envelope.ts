/**
 * Envelope codec: parse, serialize, recognize (spec §3.1, §3.4; docs/09 §4).
 *
 * Layout (suite 0xFF01 sizes):
 *   fmt_ver(1) ‖ suite_id(2, BE) ‖ key_id(16) ‖ msg_seed(32) ‖ nonce(12) ‖ ciphertext(var) ‖ tag(16) ‖ commitment(32)
 *
 * Recognition is a pure function of the registry and never of the allow-list
 * (§3.4): an envelope under a registered-but-retired suite is ciphertext, and
 * misclassifying it as plaintext is the double-encryption failure §3.4
 * describes.
 */

import { InvalidArgumentError } from "./errors.ts";
import {
  FMT_VER,
  HEADER_FIXED_LEN,
  KEY_ID_LEN,
  MSG_SEED_LEN,
  fixedOverhead,
  getSuite,
  minRegisteredEnvelopeLen,
  type Suite,
} from "./registry.ts";

/** Exactly what `KeyProvider.decryptionKeys` receives (spec §8, docs/09 §4). */
export interface EnvelopeHeader {
  readonly fmtVer: number;
  readonly suiteId: number;
  readonly keyId: Uint8Array;
  readonly msgSeed: Uint8Array;
  readonly nonce: Uint8Array;
}

export interface ParsedEnvelope {
  readonly header: EnvelopeHeader;
  readonly suite: Suite;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
  readonly commitment: Uint8Array;
}

export type Recognition =
  | { readonly kind: "envelope"; readonly parsed: ParsedEnvelope }
  | { readonly kind: "not-ciphertext"; readonly detail: string }
  | { readonly kind: "unknown-format-version"; readonly fmtVer: number };

/**
 * Format-version values this core treats as "reserved, known future" for the
 * purpose of raising UNKNOWN_FORMAT_VERSION rather than NOT_CIPHERTEXT.
 *
 * PINNED UNDER G5 (declared in the conformance report). The spec does not
 * define such a set; docs/09 §3.2's footnote and docs/08 §4.6 propose that
 * only a reserved-known-future byte with a plausible length earns the code
 * (their example: 0x02), while 0x00 and 0xFF are NOT_CIPHERTEXT. This core
 * pins the set to exactly {0x02} -- the one value any document names -- on
 * the reasoning that "data written by a newer implementation" (§9) is
 * overwhelmingly the *next* version, and that a first byte of 0x37 is far
 * more likely to be unmigrated plaintext than format version 55. A wider
 * range is defensible and would change which code 0x03..0x7F produce; the
 * divergence report flags this as a specification gap.
 */
export const RESERVED_FUTURE_FMT_VERS: ReadonlySet<number> = new Set([0x02]);

export function recognize(input: Uint8Array): Recognition {
  if (!(input instanceof Uint8Array)) {
    throw new InvalidArgumentError("input must be a Uint8Array (strings are never accepted; encoding is the adapter's job)");
  }
  if (input.length < 3) {
    return { kind: "not-ciphertext", detail: `${input.length} byte(s) is too short to carry fmt_ver and suite_id` };
  }
  const fmtVer = input[0] as number;
  if (fmtVer !== FMT_VER) {
    if (RESERVED_FUTURE_FMT_VERS.has(fmtVer) && input.length >= minRegisteredEnvelopeLen()) {
      return { kind: "unknown-format-version", fmtVer };
    }
    return { kind: "not-ciphertext", detail: `fmt_ver 0x${fmtVer.toString(16).padStart(2, "0")} is not a recognized version` };
  }
  const suiteId = ((input[1] as number) << 8) | (input[2] as number);
  const suite = getSuite(suiteId);
  if (suite === undefined) {
    return { kind: "not-ciphertext", detail: `suite_id 0x${suiteId.toString(16).padStart(4, "0")} is not a registered suite` };
  }
  const min = fixedOverhead(suite);
  if (input.length < min) {
    return {
      kind: "not-ciphertext",
      detail: `${input.length} bytes is shorter than the ${min}-byte minimum envelope for suite 0x${suiteId.toString(16)}`,
    };
  }
  let o = 3;
  const keyId = input.subarray(o, o + KEY_ID_LEN);
  o += KEY_ID_LEN;
  const msgSeed = input.subarray(o, o + MSG_SEED_LEN);
  o += MSG_SEED_LEN;
  const nonce = input.subarray(o, o + suite.nonceLen);
  o += suite.nonceLen;
  const ctLen = input.length - min;
  const ciphertext = input.subarray(o, o + ctLen);
  o += ctLen;
  const tag = input.subarray(o, o + suite.tagLen);
  o += suite.tagLen;
  const commitment = input.subarray(o, o + suite.commitLen);
  return {
    kind: "envelope",
    parsed: {
      header: { fmtVer, suiteId, keyId, msgSeed, nonce },
      suite,
      ciphertext,
      tag,
      commitment,
    },
  };
}

/** Spec §3.4 / docs/09 §3.4: registry-only, never decrypts, never trial-decrypts. */
export function isCiphertext(input: Uint8Array): boolean {
  return recognize(input).kind === "envelope";
}

export function serialize(
  suite: Suite,
  keyId: Uint8Array,
  msgSeed: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  commitment: Uint8Array,
): Buffer {
  if (keyId.length !== KEY_ID_LEN) throw new Error("internal: key_id length");
  if (msgSeed.length !== MSG_SEED_LEN) throw new Error("internal: msg_seed length");
  if (nonce.length !== suite.nonceLen) throw new Error("internal: nonce length");
  if (tag.length !== suite.tagLen) throw new Error("internal: tag length");
  if (commitment.length !== suite.commitLen) throw new Error("internal: commitment length");
  // Buffer.alloc, never allocUnsafe/from: this Buffer is returned to the
  // caller by encrypt(), and a pool-backed allocation would hand out a view
  // whose `.buffer` is Node's shared pool -- unrelated allocations, visible
  // (docs/11 §5 aliasing rule).
  const out = Buffer.alloc(fixedOverhead(suite) + ciphertext.length);
  let o = 0;
  out[o++] = FMT_VER;
  out[o++] = (suite.id >>> 8) & 0xff;
  out[o++] = suite.id & 0xff;
  out.set(keyId, o);
  o += KEY_ID_LEN;
  out.set(msgSeed, o);
  o += MSG_SEED_LEN;
  if (o !== HEADER_FIXED_LEN) throw new Error("internal: header length");
  out.set(nonce, o);
  o += nonce.length;
  out.set(ciphertext, o);
  o += ciphertext.length;
  out.set(tag, o);
  o += tag.length;
  out.set(commitment, o);
  return out;
}
