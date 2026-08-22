/**
 * AES-256-GCM backend for suite 0xFF01 over `node:crypto` (docs/11 §2).
 *
 * Tag length is fixed at 16 bytes (spec §4.5: 128 bits, truncation MUST NOT
 * be supported). The tag is carried separately from the ciphertext because
 * the envelope layout (spec §3.1) places it as its own field.
 */

import { createCipheriv, createDecipheriv } from "node:crypto";

export const GCM_KEY_LEN = 32;
export const GCM_NONCE_LEN = 12;
export const GCM_TAG_LEN = 16;

export interface Sealed {
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

export function gcmSeal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Sealed {
  assertLens(key, nonce);
  const c = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: GCM_TAG_LEN });
  c.setAAD(aad, { plaintextLength: plaintext.length });
  const a = c.update(plaintext);
  const b = c.final();
  const ciphertext = b.length === 0 ? new Uint8Array(a) : concat(a, b);
  return { ciphertext, tag: new Uint8Array(c.getAuthTag()) };
}

/**
 * Returns the plaintext, or `null` on authentication failure. The caller maps
 * `null` to the §9 code the pinned decrypt order assigns (TAG_INVALID once
 * the commitment has verified -- docs/09 §3.2 step 6). Nothing else is
 * thrown here for a well-formed (key, nonce) pair.
 */
export function gcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  assertLens(key, nonce);
  if (tag.length !== GCM_TAG_LEN) return null;
  const d = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: GCM_TAG_LEN });
  d.setAuthTag(tag);
  d.setAAD(aad, { plaintextLength: ciphertext.length });
  const a = d.update(ciphertext);
  let b: Buffer;
  try {
    b = d.final();
  } catch {
    return null;
  }
  return b.length === 0 ? new Uint8Array(a) : concat(a, b);
}

function assertLens(key: Uint8Array, nonce: Uint8Array): void {
  // These are internal invariants (the registry fixes both), not input
  // validation: a violation is a bug in this core, not a property of data.
  if (key.length !== GCM_KEY_LEN) throw new Error(`internal: AES-256-GCM key must be ${GCM_KEY_LEN} bytes`);
  if (nonce.length !== GCM_NONCE_LEN) throw new Error(`internal: AES-256-GCM nonce must be ${GCM_NONCE_LEN} bytes`);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
