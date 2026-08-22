/**
 * Record-key and index-key derivation (spec §5.3, §7.2) over HKDF-SHA-512.
 *
 * `node:crypto`'s `hkdfSync(digest, ikm, salt, info, keylen)` returns an
 * `ArrayBuffer` (argument order and return type confirmed against Node 24 --
 * docs/11 §2 [VERIFY] resolved; the primitive test also checks the result
 * against a hand-rolled RFC 5869 expand over `createHmac`, so an argument
 * transposition would fail loudly rather than silently derive the wrong key).
 */

import { hkdfSync } from "node:crypto";
import { canonicalContext, type ResolvedContext } from "./context.ts";
import { InvalidArgumentError } from "./errors.ts";
import { KEY_ID_LEN, MSG_SEED_LEN, type Suite } from "./registry.ts";

export function hkdfSha512(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return new Uint8Array(hkdfSync("sha512", ikm, salt, info, length));
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
