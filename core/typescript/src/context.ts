/**
 * FieldContext, canonical_context and AAD (spec §6.1-§6.3).
 *
 * `canonical_context` is only ever produced and recomputed, never parsed
 * (§6.2), so there is no decoder here and no decoder obligation on the
 * reserved presence bits beyond writing them as zero.
 */

import { InvalidArgumentError } from "./errors.ts";
import { FMT_VER, KEY_ID_LEN, MSG_SEED_LEN } from "./registry.ts";

export const UUID_LEN = 16;

/**
 * The tuple supplied to every core operation (spec §6.1).
 *
 * `suiteId` is deliberately absent: docs/09 §12 fixes that the *core* fills
 * the suite_id member -- from `writeSuite` on encrypt and from the parsed,
 * allow-listed header on decrypt (docs/09 §3.2 step 4) -- never the caller.
 * A caller-supplied suite would be a per-call algorithm parameter, which §4.1
 * forbids.
 */
export interface FieldContext {
  readonly tableUuid: Uint8Array;
  readonly columnUuid: Uint8Array;
  readonly tenantId?: Uint8Array | null;
  readonly rowId?: Uint8Array | null;
  readonly purpose: string;
}

/** The fully-resolved context the core derives keys from: FieldContext plus the suite the core chose. */
export interface ResolvedContext extends FieldContext {
  readonly suiteId: number;
}

// Spec §6.1 ABNF: purpose = "encrypt" / ("index:" index-id); index-id = 1*32( %x61-7A / %x30-39 / "-" )
const INDEX_ID_RE = /^[a-z0-9-]{1,32}$/;
export const PURPOSE_ENCRYPT = "encrypt";
export const INDEX_PURPOSE_PREFIX = "index:";

export function isValidIndexId(id: string): boolean {
  // The grammar is byte-oriented ASCII; a JS string that matches [a-z0-9-]
  // is necessarily single-byte UTF-8, so length in UTF-16 units == bytes.
  return INDEX_ID_RE.test(id);
}

export function isValidPurpose(p: string): boolean {
  if (p === PURPOSE_ENCRYPT) return true;
  if (!p.startsWith(INDEX_PURPOSE_PREFIX)) return false;
  return isValidIndexId(p.slice(INDEX_PURPOSE_PREFIX.length));
}

/** Returns the index-id from an "index:<id>" purpose, or undefined for any other purpose. */
export function indexIdOf(purpose: string): string | undefined {
  if (!purpose.startsWith(INDEX_PURPOSE_PREFIX)) return undefined;
  const id = purpose.slice(INDEX_PURPOSE_PREFIX.length);
  return isValidIndexId(id) ? id : undefined;
}

function isBytes(v: unknown): v is Uint8Array {
  return v instanceof Uint8Array;
}

/**
 * Validates the caller-supplied shape of a FieldContext (docs/09 §3.1 step 2).
 * Raises a typed, non-§9 error: this is a programming error in the adapter,
 * not a property of any envelope.
 */
export function validateFieldContext(ctx: FieldContext, expectedPurpose?: "encrypt" | "index"): void {
  if (ctx === null || typeof ctx !== "object") {
    throw new InvalidArgumentError("context must be an object");
  }
  if (!isBytes(ctx.tableUuid) || ctx.tableUuid.length !== UUID_LEN) {
    throw new InvalidArgumentError(`context.tableUuid must be exactly ${UUID_LEN} bytes (spec §6.1)`);
  }
  if (!isBytes(ctx.columnUuid) || ctx.columnUuid.length !== UUID_LEN) {
    throw new InvalidArgumentError(`context.columnUuid must be exactly ${UUID_LEN} bytes (spec §6.1)`);
  }
  if (ctx.tenantId !== undefined && ctx.tenantId !== null && !isBytes(ctx.tenantId)) {
    throw new InvalidArgumentError("context.tenantId must be bytes, null, or absent (spec §6.1)");
  }
  if (ctx.rowId !== undefined && ctx.rowId !== null && !isBytes(ctx.rowId)) {
    throw new InvalidArgumentError("context.rowId must be bytes, null, or absent (spec §6.1)");
  }
  if (typeof ctx.purpose !== "string" || !isValidPurpose(ctx.purpose)) {
    throw new InvalidArgumentError(
      'context.purpose must be "encrypt" or "index:<index-id>" with index-id matching [a-z0-9-]{1,32} (spec §6.1)',
    );
  }
  if (expectedPurpose === "encrypt" && ctx.purpose !== PURPOSE_ENCRYPT) {
    throw new InvalidArgumentError(`this operation requires context.purpose = "encrypt" (spec §5.3); got an index purpose`);
  }
  if (expectedPurpose === "index" && ctx.purpose === PURPOSE_ENCRYPT) {
    throw new InvalidArgumentError('blindIndex requires context.purpose = "index:<index-id>" (spec §7.2)');
  }
}

function u64be(n: number): Uint8Array {
  // Lengths here are JS array lengths, so n < 2^53; the high 32 bits are
  // still written properly rather than assumed zero.
  const out = new Uint8Array(8);
  const dv = new DataView(out.buffer);
  dv.setBigUint64(0, BigInt(n), false);
  return out;
}

function lp(field: Uint8Array): Uint8Array[] {
  return [u64be(field.length), field];
}

function concat(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const ascii = (s: string): Uint8Array => {
  // purpose is a protocol string constrained to ASCII by the §6.1 grammar.
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
};

/**
 * canonical_context(ctx) per spec §6.2 [PROVISIONAL -- G4]:
 *
 *   u8(presence)
 *   ‖ u64be(len(suite_id))   ‖ suite_id          (2 bytes, big-endian)
 *   ‖ u64be(len(table_uuid)) ‖ table_uuid
 *   ‖ u64be(len(column_uuid))‖ column_uuid
 *   ‖ [ u64be(len(tenant_id))‖ tenant_id ]       iff presence & 0x01
 *   ‖ [ u64be(len(row_id))   ‖ row_id ]          iff presence & 0x02
 *   ‖ u64be(len(purpose))    ‖ purpose
 *
 * An absent optional field contributes nothing; a present field contributes
 * its length prefix and bytes even when zero-length. `undefined` and `null`
 * both mean absent (the spec's `bytes | null`; TypeScript adds `undefined`
 * for an omitted property and there is no reason to make the two differ).
 */
export function canonicalContext(ctx: ResolvedContext): Uint8Array {
  const tenantPresent = ctx.tenantId !== undefined && ctx.tenantId !== null;
  const rowPresent = ctx.rowId !== undefined && ctx.rowId !== null;
  const presence = (tenantPresent ? 0x01 : 0) | (rowPresent ? 0x02 : 0);

  const suite = new Uint8Array([(ctx.suiteId >>> 8) & 0xff, ctx.suiteId & 0xff]);
  const parts: Uint8Array[] = [new Uint8Array([presence])];
  parts.push(...lp(suite), ...lp(ctx.tableUuid), ...lp(ctx.columnUuid));
  if (tenantPresent) parts.push(...lp(ctx.tenantId as Uint8Array));
  if (rowPresent) parts.push(...lp(ctx.rowId as Uint8Array));
  parts.push(...lp(ascii(ctx.purpose)));
  return concat(parts);
}

/**
 * AAD(header, ctx) per spec §6.2:
 *   u64be(len(fmt_ver)) ‖ fmt_ver ‖ u64be(len(key_id)) ‖ key_id ‖ u64be(len(msg_seed)) ‖ msg_seed ‖ canonical_context(ctx)
 */
export function aad(fmtVer: number, keyId: Uint8Array, msgSeed: Uint8Array, cc: Uint8Array): Uint8Array {
  if (keyId.length !== KEY_ID_LEN) throw new InvalidArgumentError(`key_id must be ${KEY_ID_LEN} bytes`);
  if (msgSeed.length !== MSG_SEED_LEN) throw new InvalidArgumentError(`msg_seed must be ${MSG_SEED_LEN} bytes`);
  return concat([...lp(new Uint8Array([fmtVer & 0xff])), ...lp(keyId), ...lp(msgSeed), cc]);
}

export { FMT_VER };
