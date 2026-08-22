/**
 * Record-key and index-key derivation (spec §5.3, §7.2) over HKDF-SHA-512.
 *
 * HKDF is implemented here as RFC 5869 extract-then-expand over
 * `node:crypto.createHmac` rather than through `hkdfSync` / Web Crypto
 * `deriveBits`. Both of Node's built-in HKDF entry points reject an `info`
 * longer than 1024 bytes (`ERR_OUT_OF_RANGE`), and this library's `info` is
 * `canonical_context` (spec §6.2), which carries caller-supplied `tenant_id`
 * and `row_id` of unbounded length (§6.1). A core that cannot derive the key
 * for a context another core can write is the central claim failing, so the
 * primitive must accept whatever `canonical_context` produces. The primitive
 * test pins this implementation to RFC 5869's published vectors and to
 * `hkdfSync` on every input the latter accepts.
 */

import { createHmac } from "node:crypto";
import { canonicalContext, type ResolvedContext } from "./context.ts";
import { InvalidArgumentError } from "./errors.ts";
import { KEY_ID_LEN, MSG_SEED_LEN, type Suite } from "./registry.ts";

const SHA512_LEN = 64;

/** RFC 5869 §2.3: `L <= 255 * HashLen`. */
export const HKDF_SHA512_MAX_LEN = 255 * SHA512_LEN;

/**
 * RFC 5869 HKDF over `digest`. `hashLen` is the digest's output length in
 * bytes; it is taken as an argument rather than computed so that the
 * expand loop cannot silently change shape with the digest.
 */
export function hkdf(digest: string, hashLen: number, ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 1 || length > 255 * hashLen) {
    throw new InvalidArgumentError(`HKDF output length must be an integer in 1..${255 * hashLen}, got ${length}`);
  }
  // Extract. RFC 5869 §2.2: an absent salt is HashLen zero bytes; HMAC pads a
  // shorter key with zeros, so an empty salt yields the same PRK.
  const prk = createHmac(digest, salt).update(ikm).digest();
  // Expand. T(0) = "", T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i), OKM = T(1) ‖ T(2) ‖ …
  const okm = new Uint8Array(length);
  let t: Uint8Array = new Uint8Array(0);
  const counter = new Uint8Array(1);
  for (let i = 1, filled = 0; filled < length; i++) {
    counter[0] = i;
    t = createHmac(digest, prk).update(t).update(info).update(counter).digest();
    const take = Math.min(t.length, length - filled);
    okm.set(t.subarray(0, take), filled);
    filled += take;
  }
  prk.fill(0);
  t.fill(0);
  return okm;
}

export function hkdfSha512(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return hkdf("sha512", SHA512_LEN, ikm, salt, info, length);
}

/** Spec §7.2 fixed salt for index-key derivation. */
export const INDEX_KEY_SALT = new TextEncoder().encode("fieldseal-index-v1");

/**
 * record_key = HKDF(ikm = tenant_dek, salt = key_id ‖ msg_seed, info = canonical_context(ctx), length = suite.key_length)
 * with purpose = "encrypt" (spec §5.3).
 */
export function deriveRecordKey(
  suite: Suite,
  tenantDek: Uint8Array,
  keyId: Uint8Array,
  msgSeed: Uint8Array,
  cc: Uint8Array,
): Uint8Array {
  if (keyId.length !== KEY_ID_LEN) throw new InvalidArgumentError(`key_id must be ${KEY_ID_LEN} bytes`);
  if (msgSeed.length !== MSG_SEED_LEN) throw new InvalidArgumentError(`msg_seed must be ${MSG_SEED_LEN} bytes`);
  const salt = new Uint8Array(KEY_ID_LEN + MSG_SEED_LEN);
  salt.set(keyId, 0);
  salt.set(msgSeed, KEY_ID_LEN);
  return hkdfSha512(tenantDek, salt, cc, suite.keyLen);
}

/**
 * index_key = HKDF(ikm = tenant_index_key, salt = "fieldseal-index-v1",
 *                  info = canonical_context(ctx with purpose = "index:<id>", row_id = null), length = 32)
 * (spec §7.2). `row_id` is forced absent here regardless of what the caller
 * passed: an index value must not depend on the row it is stored in, or it
 * could never be queried.
 */
export function deriveIndexKey(tenantIndexKey: Uint8Array, ctx: ResolvedContext): Uint8Array {
  const forced: ResolvedContext = { ...ctx, rowId: null };
  return hkdfSha512(tenantIndexKey, INDEX_KEY_SALT, canonicalContext(forced), 32);
}
