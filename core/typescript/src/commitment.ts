/**
 * Key commitment for suite 0xFF01 (spec §4.6 [PROVISIONAL -- G1]).
 *
 * What this file implements, and where it comes from, is worth being precise
 * about because the specification text itself does not state a formula.
 * §4.6 settles the *requirement* (32-byte explicit commitment derived from
 * the key) and marks the *construction* provisional under G1. docs/07 §1 item
 * 3 says a provisionally adopted gap's "proposed direction in each issue
 * draft becomes normative spec text" -- and the issue draft
 * (docs/issues/G01-key-commitment-construction.md) proposes:
 *
 *   commitment = HKDF-SHA-512(ikm = record_key, salt = "", info = "fieldseal-commit-v1", length = 32)
 *
 * verified with a constant-time compare before AEAD open. That is what is
 * implemented. The absence of this formula from §4.6 itself is recorded in
 * the M2 divergence report as a specification gap (an implementer reading
 * only the spec cannot compute the envelope's last 32 bytes).
 *
 * Note on `salt = ""`: RFC 5869 §2.2 says an absent salt is HashLen zero
 * bytes; HMAC zero-pads keys shorter than the block size, so an empty salt
 * and a 64-zero-byte salt are the same HMAC key. There is no ambiguity to
 * resolve between "" and "unset".
 */

import { timingSafeEqual } from "node:crypto";
import { hkdfSha512 } from "./kdf.ts";

export const COMMIT_INFO = new TextEncoder().encode("fieldseal-commit-v1");
export const COMMIT_LEN = 32;

export function computeCommitment(recordKey: Uint8Array): Uint8Array {
  return hkdfSha512(recordKey, new Uint8Array(0), COMMIT_INFO, COMMIT_LEN);
}

/**
 * Constant-time verification. `timingSafeEqual` throws on a length mismatch;
 * the envelope parser has already fixed the commitment field at
 * `suite.commitLen`, so a mismatch here can only mean an internal error, and
 * the lengths being compared are public (they are the suite's constants).
 */
export function verifyCommitment(recordKey: Uint8Array, expected: Uint8Array): boolean {
  const actual = computeCommitment(recordKey);
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}
