/**
 * Blind indexes (spec §7): index derivation functions, the bit-exact
 * truncation of §7.2, and index declarations with their construction-time
 * gates (§7.4 band, §7.6 cardinality, §6.1 identifier grammar).
 */

import { argon2, argon2Sync, createHmac } from "node:crypto";
import { isValidIndexId, UUID_LEN } from "./context.ts";
import { ConfigurationError } from "./errors.ts";
import { hkdfSha512 } from "./kdf.ts";
import { isNormalizerId, type NormalizerId } from "./normalize.ts";

export type IdfId = "hmac-sha512" | "argon2id";

/** Spec §7.3 Argon2id invocation constants. Only t and m may be raised by a deployment. */
export const ARGON2_VERSION = 0x13;
export const ARGON2_MIN_T = 3;
export const ARGON2_MIN_M_KIB = 32768;
export const ARGON2_P = 1;
export const ARGON2_OUTPUT_LEN = 64;
export const ARGON2_SALT_LEN = 16;
export const ARGON2_SALT_INFO = new TextEncoder().encode("fieldseal-argon2-salt-v1");

export interface Argon2Params {
  readonly timeCost: number;
  readonly memoryKib: number;
}

/**
 * Abstracts the Argon2id primitive so the backend is swappable without API
 * change (docs/11 §2). The shipped backend is `node:crypto`'s native Argon2
 * (Node ≥ 24.7 with OpenSSL ≥ 3.2), which returns raw output, takes an
 * explicit parallelism, and -- unlike libsodium and argon2-cffi -- accepts
 * the RFC 9106 §5.3 secret and associated data, which is what lets this core
 * check the primitive against that RFC vector even though the Fieldseal
 * invocation forbids both (see tests/primitives).
 *
 * The seam carries both forms because the core ships both: `argon2Sync`
 * blocks the calling thread, `argon2` runs the derivation on the libuv
 * threadpool. Both are required members, not one optional: exactly one
 * implementation exists, and an optional `argon2idAsync` would turn "this
 * backend has no async form" into a silent runtime branch. Spec §11.1
 * forbids the converse shortcut -- the synchronous form MUST NOT be
 * implemented by blocking on the asynchronous one -- so `idf` never routes
 * through `argon2idAsync`, and `tests/async-companions.test.ts` asserts it.
 */
export interface Argon2Backend {
  readonly name: string;
  /**
   * Argument ownership, which the caller relies on to erase the salt: a
   * backend MUST NOT retain a reference to `password` or `salt` past the
   * point its result is available -- the return for the synchronous form,
   * the settling of the promise for the asynchronous one. `idf` and
   * `idfAsync` zero the salt at exactly those points, so a backend that
   * read either buffer lazily afterwards would derive from zeros. The
   * shipped backend copies both synchronously inside the `node:crypto`
   * call (verified on Node 24.16: zeroing `message` and `nonce` on the line
   * after `argon2(...)` still yields the reference tag), which is stricter
   * than this contract requires.
   */
  argon2id(password: Uint8Array, salt: Uint8Array, t: number, mKib: number, p: number, outLen: number): Uint8Array;
  argon2idAsync(
    password: Uint8Array,
    salt: Uint8Array,
    t: number,
    mKib: number,
    p: number,
    outLen: number,
  ): Promise<Uint8Array>;
}

// Deliberately not `Object.freeze`d: the spy in
// `tests/async-companions.test.ts` replaces these two properties to assert
// that neither form routes through the other (spec §11.1).
export const nodeArgon2Backend: Argon2Backend = {
  name: "node:crypto argon2Sync / argon2",
  argon2id(password, salt, t, mKib, p, outLen) {
    // Spec §7.3: K (secret) and X (associatedData) MUST NOT be used. They are
    // deliberately not passed, not passed-as-empty: "not used" and "empty"
    // are the same H0 input in RFC 9106 §3.2 (both contribute LE32(0)), but
    // omitting them keeps the call shape identical to backends that cannot
    // take them at all.
    //
    // There is no `version` parameter: node:crypto's Argon2 is version 0x13
    // only (an undocumented `version` key is silently ignored -- verified on
    // Node 24.16 -- and the RFC 9106 §5.3 vector, which is a version-19
    // vector, reproduces exactly). ARGON2_VERSION is therefore a recorded
    // fact about the backend rather than an argument to it.
    return new Uint8Array(
      argon2Sync("argon2id", {
        message: password,
        nonce: salt,
        parallelism: p,
        tagLength: outLen,
        memory: mKib,
        passes: t,
      }),
    );
  },
  argon2idAsync(password, salt, t, mKib, p, outLen) {
    // Same two invariants as the synchronous form above: `secret` and
    // `associatedData` omitted rather than passed empty, and no `version`
    // key. The callback receives the raw tag; the copy mirrors the sync
    // path, so both forms hand back a buffer the core owns and may zero.
    return new Promise((resolve, reject) => {
      argon2(
        "argon2id",
        {
          message: password,
          nonce: salt,
          parallelism: p,
          tagLength: outLen,
          memory: mKib,
          passes: t,
        },
        (err, out) => {
          if (err) reject(err);
          else resolve(new Uint8Array(out));
        },
      );
    });
  },
};

export function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha512", key).update(data).digest());
}

/** The §7.3 salt: HKDF-SHA-512(ikm = index_key, salt = "", info = "fieldseal-argon2-salt-v1", 16). */
export function argon2Salt(indexKey: Uint8Array): Uint8Array {
  return hkdfSha512(indexKey, new Uint8Array(0), ARGON2_SALT_INFO, ARGON2_SALT_LEN);
}

/**
 * The §7.3 minima, applied where a column declares no Argon2id parameters.
 * One function so `idf`, `idfAsync` and `validateIndexDeclaration` cannot
 * drift in what "unspecified" costs.
 */
export function argon2ParamsOrMinima(params?: Argon2Params): Argon2Params {
  return params ?? { timeCost: ARGON2_MIN_T, memoryKib: ARGON2_MIN_M_KIB };
}

/** IDF(index_key, normalized) per spec §7.3, for either IDF. */
export function idf(
  which: IdfId,
  indexKey: Uint8Array,
  normalized: Uint8Array,
  params?: Argon2Params,
  backend: Argon2Backend = nodeArgon2Backend,
): Uint8Array {
  if (which === "hmac-sha512") return hmacSha512(indexKey, normalized);
  const p = argon2ParamsOrMinima(params);
  const salt = argon2Salt(indexKey);
  try {
    return backend.argon2id(normalized, salt, p.timeCost, p.memoryKib, ARGON2_P, ARGON2_OUTPUT_LEN);
  } finally {
    // The salt is key material, not a public parameter. Spec §7.3: the index
    // key "enters **only** through the salt" and keying "rests entirely on
    // the salt" -- with K and X forbidden, 16 bytes of salt carry the whole
    // strength of the column's index key, so leaving it to GC while zeroing
    // the key it came from protects nothing.
    salt.fill(0);
  }
}

/**
 * `idf` on the libuv threadpool (spec §11.1 companion). Byte-identical
 * output and the same §9 error for the same condition; `idf` is not
 * implemented over it.
 *
 * Everything before the first `await` runs synchronously, salt derivation
 * included, so a caller may zero `indexKey` as soon as this function
 * returns -- it is read before the derivation is handed to the backend,
 * never across it. The salt derived from it is zeroed here, once the
 * derivation has completed rather than once it has been submitted: the
 * `Argon2Backend` contract above only promises the backend is done with its
 * arguments by then, so erasing any earlier would be reaching past what a
 * swappable seam guarantees.
 * The HMAC branch never touches the threadpool: there is nothing to offload,
 * and queueing a microsecond of SHA-512 behind Argon2id derivations would
 * make an HMAC column slower for no gain.
 */
export async function idfAsync(
  which: IdfId,
  indexKey: Uint8Array,
  normalized: Uint8Array,
  params?: Argon2Params,
  backend: Argon2Backend = nodeArgon2Backend,
): Promise<Uint8Array> {
  if (which === "hmac-sha512") return hmacSha512(indexKey, normalized);
  const p = argon2ParamsOrMinima(params);
  const salt = argon2Salt(indexKey);
  try {
    // Called through the property, never destructured: the seam test spies by
    // replacing `backend.argon2idAsync`, which a captured reference would miss.
    // Awaited rather than returned so the erasure below runs on completion
    // and not on submission.
    return await backend.argon2idAsync(normalized, salt, p.timeCost, p.memoryKib, ARGON2_P, ARGON2_OUTPUT_LEN);
  } finally {
    salt.fill(0); // key material, for the reason given in `idf`
  }
}

/**
 * truncate(raw, b) per spec §7.2: keep the first ⌈b/8⌉ bytes, zero the
 * trailing 8·⌈b/8⌉ − b bits of the final byte, bits numbered MSB-first.
 * Output length is exactly ⌈b/8⌉.
 */
export function truncateBits(raw: Uint8Array, b: number): Uint8Array {
  if (!Number.isInteger(b) || b < 1 || b > raw.length * 8) {
    throw new ConfigurationError(`truncation length ${b} bits is outside 1..${raw.length * 8}`);
  }
  const nBytes = Math.ceil(b / 8);
  const out = new Uint8Array(raw.subarray(0, nBytes)); // copy, never alias
  const dropBits = nBytes * 8 - b;
  if (dropBits > 0) {
    const mask = (0xff << dropBits) & 0xff;
    out[nBytes - 1] = (out[nBytes - 1] as number) & mask;
  }
  return out;
}

export interface CardinalityOverride {
  readonly reason: string;
  readonly approvedBy: string;
  readonly date: string;
}

/** docs/09 §7 IndexDeclaration, declared to the client at construction. */
export interface IndexDeclaration {
  readonly tableUuid: Uint8Array;
  readonly columnUuid: Uint8Array;
  /** Defaults to "exact" (spec §7.2). */
  readonly indexId?: string;
  readonly idf: IdfId;
  readonly argon2?: Argon2Params;
  readonly normalize: NormalizerId;
  readonly truncateBits: number;
  /** Projected number of DISTINCT values (spec §7.4), ≥ 16; ≥ 2^10 unless overridden (§7.6). */
  readonly projectedPopulation: number;
  readonly cardinalityOverride?: CardinalityOverride;
  /** Declares the column as heavily skewed (spec §7.6); gated like low cardinality. */
  readonly skewed?: boolean;
  /**
   * What happens to a value the normalizer refuses — one containing a code
   * point the pinned Unicode version does not define (docs/09 §7.2).
   *
   * `"refuse"` (default) propagates `InvalidArgumentError`, so an adapter
   * deriving an index on write fails the write. `"bucket"` returns this
   * column's reserved marker instead, keeping the row findable: the same
   * marker is derived on lookup, and spec §7.5 re-verification narrows the
   * candidates. Storing *no* index is not an option — that is the silent
   * missing row spec §10.2 forbids.
   */
  readonly onUnindexable?: OnUnindexable;
  /** Required when `onUnindexable` is `"bucket"`; same shape §7.6 requires. */
  readonly unindexableOverride?: CardinalityOverride;
}

export type OnUnindexable = "refuse" | "bucket";

/**
 * Normalizers that can refuse an otherwise-storable value (docs/09 §7.2).
 * Only these make `onUnindexable` meaningful: `identity` and `digits-only-v1`
 * consult no Unicode table and have nothing to refuse.
 */
export const REFUSING_NORMALIZERS: ReadonlySet<NormalizerId> = new Set<NormalizerId>(["nfc-casefold-v1"]);

/**
 * docs/09 §7.2. The leading 0xFF can never appear in UTF-8, so no input
 * `nfc-casefold-v1` accepts can normalize to this preimage: the marker cannot
 * collide with a real value by construction rather than by luck.
 */
export const UNINDEXABLE_PREIMAGE: Uint8Array = new Uint8Array([0xff, ...Buffer.from("fieldseal-unindexable-v1", "ascii")]);

export interface ValidatedIndex {
  readonly key: string;
  readonly indexId: string;
  readonly idf: IdfId;
  readonly argon2: Argon2Params | undefined;
  readonly normalize: NormalizerId;
  readonly truncateBits: number;
  readonly projectedPopulation: number;
  readonly overridden: boolean;
  readonly onUnindexable: OnUnindexable;
}

export const CARDINALITY_GATE = 1 << 10;

export function indexRegistryKey(tableUuid: Uint8Array, columnUuid: Uint8Array, indexId: string): string {
  return `${Buffer.from(tableUuid).toString("hex")}/${Buffer.from(columnUuid).toString("hex")}/${indexId}`;
}

/**
 * Construction-time validation (docs/09 §2, §7). Everything here is a
 * `ConfigurationError`: configuration validation sits outside the §9
 * taxonomy (docs/08 §4.3), and a declaration that fails must never reach a
 * key derivation.
 */
export function validateIndexDeclaration(d: IndexDeclaration): ValidatedIndex {
  if (!(d.tableUuid instanceof Uint8Array) || d.tableUuid.length !== UUID_LEN) {
    throw new ConfigurationError(`index declaration: tableUuid must be ${UUID_LEN} bytes`);
  }
  if (!(d.columnUuid instanceof Uint8Array) || d.columnUuid.length !== UUID_LEN) {
    throw new ConfigurationError(`index declaration: columnUuid must be ${UUID_LEN} bytes`);
  }
  const indexId = d.indexId ?? "exact";
  if (typeof indexId !== "string" || !isValidIndexId(indexId)) {
    // Spec §6.1: refused when the index is declared, never at call time.
    throw new ConfigurationError(
      `index declaration: index-id ${JSON.stringify(indexId)} violates the spec §6.1 grammar [a-z0-9-]{1,32}`,
    );
  }
  if (d.idf !== "hmac-sha512" && d.idf !== "argon2id") {
    throw new ConfigurationError(`index declaration ${indexId}: idf must be "hmac-sha512" or "argon2id" (spec §7.3)`);
  }
  let argon2: Argon2Params | undefined;
  if (d.idf === "argon2id") {
    argon2 = argon2ParamsOrMinima(d.argon2);
    if (!Number.isInteger(argon2.timeCost) || argon2.timeCost < ARGON2_MIN_T) {
      throw new ConfigurationError(`index declaration ${indexId}: Argon2id timeCost must be an integer ≥ ${ARGON2_MIN_T} (spec §7.3)`);
    }
    if (!Number.isInteger(argon2.memoryKib) || argon2.memoryKib < ARGON2_MIN_M_KIB) {
      throw new ConfigurationError(`index declaration ${indexId}: Argon2id memoryKib must be an integer ≥ ${ARGON2_MIN_M_KIB} (spec §7.3)`);
    }
  } else if (d.argon2 !== undefined) {
    throw new ConfigurationError(`index declaration ${indexId}: argon2 parameters given for an hmac-sha512 index`);
  }
  if (typeof d.normalize !== "string" || !isNormalizerId(d.normalize)) {
    throw new ConfigurationError(
      `index declaration ${indexId}: normalize must be one of the shipped normalizers (docs/09 §7); custom normalizers are a portability break`,
    );
  }
  const P = d.projectedPopulation;
  if (!Number.isInteger(P) || P < 16) {
    throw new ConfigurationError(`index declaration ${indexId}: projectedPopulation must be an integer ≥ 16 (spec §7.4)`);
  }
  const b = d.truncateBits;
  const rawBits = ARGON2_OUTPUT_LEN * 8; // both IDFs produce 64 bytes
  if (!Number.isInteger(b) || b < 1 || b > rawBits) {
    throw new ConfigurationError(`index declaration ${indexId}: truncateBits must be an integer in 1..${rawBits}`);
  }
  // Spec §7.4: 2 ≤ P × 2^(−b) < √P, b rounded down. A declared b outside the
  // band is a spec violation the core can see at construction, so it is
  // refused here rather than silently accepted.
  const collisions = P / 2 ** b;
  if (!(collisions >= 2 && collisions < Math.sqrt(P))) {
    throw new ConfigurationError(
      `index declaration ${indexId}: truncateBits=${b} is outside the spec §7.4 band for P=${P} (need 2 ≤ P·2^−b < √P; got ${collisions.toFixed(3)})`,
    );
  }
  // Spec §7.6 default-deny gate.
  const gated = P < CARDINALITY_GATE || d.skewed === true;
  let overridden = false;
  if (gated) {
    const o = d.cardinalityOverride;
    if (o === undefined || !o.reason || !o.approvedBy || !o.date) {
      throw new ConfigurationError(
        `index declaration ${indexId}: refused by the spec §7.6 cardinality gate (P=${P}${d.skewed ? ", declared skewed" : ""}); an explicit cardinalityOverride {reason, approvedBy, date} is required`,
      );
    }
    overridden = true;
  }
  // docs/09 §7.2. Relaxing a default-deny rule on a column is a reviewed,
  // recorded act — deliberately the same ceremony §7.6 requires above, so
  // that `bucket` cannot become a setting copied between columns.
  const onUnindexable: OnUnindexable = d.onUnindexable ?? "refuse";
  if (onUnindexable !== "refuse" && onUnindexable !== "bucket") {
    throw new ConfigurationError(
      `index declaration ${indexId}: onUnindexable must be "refuse" or "bucket", got ${JSON.stringify(onUnindexable)}`,
    );
  }
  if (onUnindexable === "bucket") {
    if (!REFUSING_NORMALIZERS.has(d.normalize)) {
      // The setting could never take effect, and accepting it silently would
      // misrepresent the column as protected.
      throw new ConfigurationError(
        `index declaration ${indexId}: onUnindexable="bucket" is meaningless for normalizer "${d.normalize}", which never refuses a value; only ${[...REFUSING_NORMALIZERS].join(", ")} can`,
      );
    }
    const u = d.unindexableOverride;
    if (u === undefined || !u.reason || !u.approvedBy || !u.date) {
      throw new ConfigurationError(
        `index declaration ${indexId}: onUnindexable="bucket" stores unindexable rows under a reserved marker that is distinguishable by frequency (docs/09 §7.2); an explicit unindexableOverride {reason, approvedBy, date} is required`,
      );
    }
  }
  // Frozen because `Fieldseal.indexes` hands these out (docs/09 §2, G18) and
  // `readonly` in the interface is a compile-time claim only: a caller with
  // the value in hand can rewrite `truncateBits` through one `as` cast and
  // change what the client derives. Freezing at validation costs nothing --
  // this runs once per declaration, at construction.
  return Object.freeze({
    key: indexRegistryKey(d.tableUuid, d.columnUuid, indexId),
    indexId,
    idf: d.idf,
    argon2: argon2 === undefined ? undefined : Object.freeze({ ...argon2 }),
    normalize: d.normalize,
    truncateBits: b,
    projectedPopulation: P,
    overridden,
    onUnindexable,
  });
}
