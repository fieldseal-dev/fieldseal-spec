/**
 * KeyProvider interface and the three shipped providers (spec §8; docs/09 §8).
 *
 *   StaticKeyProvider    one key; test/development only; warns outside test configuration
 *   DerivedKeyProvider   tenant DEK and index key derived from a root secret via HKDF; no I/O
 *   EnvelopeKeyProvider  KMS-wrapped DEKs; unwrap happens ONLY in warm(); value path is cache-only
 *
 * The value-path methods (`encryptionKey`, `decryptionKeys`) are synchronous
 * and MUST NOT perform network I/O (spec §11.1). Only `warm` may.
 */

import { DekCache, type CachePolicy, type CacheHooks } from "./cache.ts";
import type { FieldContext, ResolvedContext } from "./context.ts";
import { PURPOSE_ENCRYPT } from "./context.ts";
import type { EnvelopeHeader } from "./envelope.ts";
import { ConfigurationError, KeyUnavailableError } from "./errors.ts";
import { hkdfSha512 } from "./kdf.ts";
import { KEY_ID_LEN } from "./registry.ts";

export interface EncryptionKey {
  /** Tenant DEK for purpose "encrypt"; tenant INDEX key for purpose "index:*" (spec §8). */
  readonly key: Uint8Array;
  /** 16 opaque bytes. Provider-defined structure; the core never interprets it. */
  readonly keyId: Uint8Array;
}

export interface KeyProvider {
  encryptionKey(ctx: ResolvedContext): EncryptionKey;
  /** All currently-valid candidate keys for the header, in preference order (spec §5.6, §8). */
  decryptionKeys(header: EnvelopeHeader): Uint8Array[];
  /** Optional async prefetch (spec §11.2). MUST NOT be required for correctness. */
  warm?(contexts: Iterable<FieldContext>): Promise<void>;
  /** Set by providers that MUST NOT be used outside test/development (StaticKeyProvider). */
  readonly developmentOnly?: boolean;
}

export function isIndexPurpose(ctx: FieldContext): boolean {
  return ctx.purpose !== PURPOSE_ENCRYPT;
}

// ---------------------------------------------------------------------------
// StaticKeyProvider

export interface StaticKeyProviderOptions {
  readonly dek: Uint8Array;
  readonly keyId: Uint8Array;
  /** The sibling tenant index key (spec §5.2). Required only if blind indexes are used. */
  readonly indexKey?: Uint8Array;
}

/**
 * A single key. Spec §8: test and development use only; the client emits the
 * §8 warning through `onWarning` when it sees `developmentOnly`.
 */
export class StaticKeyProvider implements KeyProvider {
  readonly developmentOnly = true as const;
  readonly #dek: Uint8Array;
  readonly #keyId: Uint8Array;
  readonly #indexKey: Uint8Array | undefined;

  constructor(opts: StaticKeyProviderOptions) {
    if (!(opts.dek instanceof Uint8Array) || opts.dek.length !== 32) {
      throw new ConfigurationError("StaticKeyProvider: dek must be 32 bytes");
    }
    if (!(opts.keyId instanceof Uint8Array) || opts.keyId.length !== KEY_ID_LEN) {
      throw new ConfigurationError(`StaticKeyProvider: keyId must be ${KEY_ID_LEN} bytes`);
    }
    if (opts.indexKey !== undefined && (!(opts.indexKey instanceof Uint8Array) || opts.indexKey.length !== 32)) {
      throw new ConfigurationError("StaticKeyProvider: indexKey must be 32 bytes when given");
    }
    if (opts.indexKey !== undefined && Buffer.from(opts.indexKey).equals(Buffer.from(opts.dek))) {
      // Spec §5.2 / §7.2: the index key MUST NOT be the tenant DEK.
      throw new ConfigurationError("StaticKeyProvider: indexKey MUST NOT equal the dek (spec §5.2 sibling-key rule)");
    }
    this.#dek = new Uint8Array(opts.dek);
    this.#keyId = new Uint8Array(opts.keyId);
    this.#indexKey = opts.indexKey === undefined ? undefined : new Uint8Array(opts.indexKey);
  }

  encryptionKey(ctx: ResolvedContext): EncryptionKey {
    if (isIndexPurpose(ctx)) {
      if (this.#indexKey === undefined) {
        throw new KeyUnavailableError(null, "StaticKeyProvider was constructed without an index key");
      }
      return { key: new Uint8Array(this.#indexKey), keyId: new Uint8Array(this.#keyId) };
    }
    return { key: new Uint8Array(this.#dek), keyId: new Uint8Array(this.#keyId) };
  }

  decryptionKeys(header: EnvelopeHeader): Uint8Array[] {
    if (!Buffer.from(header.keyId).equals(Buffer.from(this.#keyId))) return [];
    return [new Uint8Array(this.#dek)];
  }
}

// ---------------------------------------------------------------------------
// DerivedKeyProvider

export interface DerivedKeyProviderOptions {
  /** Root secret, ≥ 32 bytes. Never leaves this object; never returned. */
  readonly rootSecret: Uint8Array;
  /** Simultaneously-decryptable key versions (spec §5.6). Default [1]. */
  readonly versions?: readonly number[];
  /** Exactly one active-for-write version. Default: the highest in `versions`. */
  readonly activeVersion?: number;
}

const DERIVED_SALT = new TextEncoder().encode("fieldseal-derived-provider-v1");
const DERIVED_TAG = new TextEncoder().encode("FSDK"); // 4-byte provider tag in key_id (docs/09 §8.1 layout)

function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
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

/** The DEK scope (spec §5.2): the tenant id, or the empty scope for deployments without tenancy. */
export function scopeOf(ctx: FieldContext): Uint8Array {
  return ctx.tenantId === undefined || ctx.tenantId === null ? new Uint8Array(0) : ctx.tenantId;
}

/**
 * Keys derived from a root secret with HKDF-SHA-512 under distinct labels:
 *
 *   dek(scope, v)   = HKDF(root, salt = "fieldseal-derived-provider-v1", info = "dek"       ‖ u32be(v) ‖ u64be(len) ‖ scope, 32)
 *   index(scope)    = HKDF(root, salt = same,                            info = "index-key" ‖ u64be(len) ‖ scope, 32)
 *   tag(scope)      = HKDF(root, salt = same,                            info = "scope-tag" ‖ u64be(len) ‖ scope, 8)
 *   key_id          = "FSDK" ‖ tag(scope) ‖ u32be(v)
 *
 * The index key is a sibling under a distinct label, never derived from the
 * DEK (spec §5.2); versions are independent derivations, never chained from
 * one another (spec §5.4). `decryptionKeys` resolves the scope from the
 * 8-byte tag through a table populated by `encryptionKey` and `warm`, since
 * the header alone cannot carry a tenant id the core never sees.
 */
export class DerivedKeyProvider implements KeyProvider {
  readonly #root: Uint8Array;
  readonly #versions: readonly number[];
  readonly #active: number;
  readonly #scopes = new Map<string, Uint8Array>(); // tag hex -> scope bytes

  constructor(opts: DerivedKeyProviderOptions) {
    if (!(opts.rootSecret instanceof Uint8Array) || opts.rootSecret.length < 32) {
      throw new ConfigurationError("DerivedKeyProvider: rootSecret must be at least 32 bytes");
    }
    const versions = [...(opts.versions ?? [1])];
    if (versions.length === 0 || !versions.every((v) => Number.isInteger(v) && v >= 0 && v <= 0xffffffff)) {
      throw new ConfigurationError("DerivedKeyProvider: versions must be a non-empty list of integers in 0..2^32-1");
    }
    if (new Set(versions).size !== versions.length) {
      throw new ConfigurationError("DerivedKeyProvider: versions must be distinct");
    }
    const active = opts.activeVersion ?? Math.max(...versions);
    if (!versions.includes(active)) {
      throw new ConfigurationError("DerivedKeyProvider: activeVersion must be one of versions (spec §5.6)");
    }
    this.#root = new Uint8Array(opts.rootSecret);
    this.#versions = versions;
    this.#active = active;
  }

  get activeVersion(): number {
    return this.#active;
  }

  #derive(label: string, scope: Uint8Array, extra: Uint8Array, len: number): Uint8Array {
    const info = concat(new TextEncoder().encode(label), extra, u64be(scope.length), scope);
    return hkdfSha512(this.#root, DERIVED_SALT, info, len);
  }

  #tag(scope: Uint8Array): Uint8Array {
    return this.#derive("scope-tag", scope, new Uint8Array(0), 8);
  }

  keyIdFor(scope: Uint8Array, version: number): Uint8Array {
    return concat(DERIVED_TAG, this.#tag(scope), u32be(version));
  }

  #remember(scope: Uint8Array): Uint8Array {
    const tag = this.#tag(scope);
    this.#scopes.set(Buffer.from(tag).toString("hex"), new Uint8Array(scope));
    return tag;
  }

  encryptionKey(ctx: ResolvedContext): EncryptionKey {
    const scope = scopeOf(ctx);
    const tag = this.#remember(scope);
    const keyId = concat(DERIVED_TAG, tag, u32be(this.#active));
    if (isIndexPurpose(ctx)) {
      return { key: this.#derive("index-key", scope, new Uint8Array(0), 32), keyId };
    }
    return { key: this.#derive("dek", scope, u32be(this.#active), 32), keyId };
  }

  decryptionKeys(header: EnvelopeHeader): Uint8Array[] {
    const id = header.keyId;
    if (id.length !== KEY_ID_LEN || !Buffer.from(id.subarray(0, 4)).equals(Buffer.from(DERIVED_TAG))) return [];
    const scope = this.#scopes.get(Buffer.from(id.subarray(4, 12)).toString("hex"));
    if (scope === undefined) return [];
    const named = new DataView(id.buffer, id.byteOffset + 12, 4).getUint32(0, false);
    // Spec §8: all currently-valid versions. The one the header names goes
    // first, then the active version, then the rest.
    const order = [named, this.#active, ...this.#versions].filter((v, i, a) => this.#versions.includes(v) && a.indexOf(v) === i);
    return order.map((v) => this.#derive("dek", scope, u32be(v), 32));
  }

  async warm(contexts: Iterable<FieldContext>): Promise<void> {
    for (const ctx of contexts) this.#remember(scopeOf(ctx));
  }
}

// ---------------------------------------------------------------------------
// EnvelopeKeyProvider

/** The KMS integration seam (docs/09 §8.2): per-language, pluggable, optional dependency. */
export interface Wrapper {
  unwrap(wrapped: Uint8Array, scope: Uint8Array): Promise<Uint8Array>;
  wrap?(plaintextKey: Uint8Array, scope: Uint8Array): Promise<Uint8Array>;
}

export interface WrappedKeyVersion {
  readonly version: number;
  /** 16 opaque bytes identifying this (scope, version) in envelope headers. */
  readonly keyId: Uint8Array;
  readonly wrappedDek: Uint8Array;
  /** Sibling index key (spec §5.2); optional where no blind index exists. */
  readonly wrappedIndexKey?: Uint8Array;
}

export interface WrappedKeySet {
  readonly scope: Uint8Array;
  readonly versions: readonly WrappedKeyVersion[];
  readonly activeVersion: number;
}

/** Where the deployment keeps its wrapped-key metadata. Lookups are synchronous and local. */
export interface KeyDirectory {
  byScope(scope: Uint8Array): WrappedKeySet | undefined;
  byKeyId(keyId: Uint8Array): { scope: Uint8Array; version: number } | undefined;
}

export class InMemoryKeyDirectory implements KeyDirectory {
  readonly #byScope = new Map<string, WrappedKeySet>();
  readonly #byKeyId = new Map<string, { scope: Uint8Array; version: number }>();

  constructor(sets: readonly WrappedKeySet[]) {
    for (const s of sets) {
      if (!s.versions.some((v) => v.version === s.activeVersion)) {
        throw new ConfigurationError("InMemoryKeyDirectory: activeVersion must be one of the key set's versions (spec §5.6)");
      }
      this.#byScope.set(Buffer.from(s.scope).toString("hex"), s);
      for (const v of s.versions) {
        if (v.keyId.length !== KEY_ID_LEN) throw new ConfigurationError(`InMemoryKeyDirectory: keyId must be ${KEY_ID_LEN} bytes`);
        const k = Buffer.from(v.keyId).toString("hex");
        if (this.#byKeyId.has(k)) throw new ConfigurationError(`InMemoryKeyDirectory: duplicate keyId ${k}`);
        this.#byKeyId.set(k, { scope: s.scope, version: v.version });
      }
    }
  }

  byScope(scope: Uint8Array): WrappedKeySet | undefined {
    return this.#byScope.get(Buffer.from(scope).toString("hex"));
  }

  byKeyId(keyId: Uint8Array): { scope: Uint8Array; version: number } | undefined {
    return this.#byKeyId.get(Buffer.from(keyId).toString("hex"));
  }
}

export interface EnvelopeKeyProviderOptions {
  readonly wrapper: Wrapper;
  readonly directory: KeyDirectory;
  readonly cache: CachePolicy;
  readonly cacheHooks?: CacheHooks;
  /**
   * Spec §8.1 degradation mode, recorded for documentation. On the value path
   * both modes behave identically (docs/09 §8.2): a cache miss is
   * KEY_UNAVAILABLE, because the value path never blocks on the network.
   */
  readonly degradation?: "fail-closed" | "serve-cached";
}

function cacheKey(scope: Uint8Array, version: number, role: "dek" | "index"): string {
  return `${Buffer.from(scope).toString("hex")}/${version}/${role}`;
}

/**
 * The production path: KMS-wrapped DEKs, unwrapped only in `warm()` (or a
 * caller-driven refresh), served from the §5.5 cache on the value path.
 */
export class EnvelopeKeyProvider implements KeyProvider {
  readonly cache: DekCache;
  readonly degradation: "fail-closed" | "serve-cached";
  readonly #wrapper: Wrapper;
  readonly #directory: KeyDirectory;
  readonly #inflight = new Map<string, Promise<void>>(); // single-flight per scope

  constructor(opts: EnvelopeKeyProviderOptions) {
    if (typeof opts.wrapper?.unwrap !== "function") throw new ConfigurationError("EnvelopeKeyProvider: wrapper.unwrap is required");
    if (typeof opts.directory?.byScope !== "function") throw new ConfigurationError("EnvelopeKeyProvider: directory is required");
    this.cache = new DekCache(opts.cache, opts.cacheHooks ?? {});
    this.degradation = opts.degradation ?? "fail-closed";
    this.#wrapper = opts.wrapper;
    this.#directory = opts.directory;
  }

  encryptionKey(ctx: ResolvedContext): EncryptionKey {
    const scope = scopeOf(ctx);
    const set = this.#directory.byScope(scope);
    if (set === undefined) throw new KeyUnavailableError(null, "no key set is registered for this tenant scope");
    const active = set.versions.find((v) => v.version === set.activeVersion) as WrappedKeyVersion;
    const role = isIndexPurpose(ctx) ? "index" : "dek";
    const key = this.cache.get(cacheKey(scope, active.version, role));
    if (key === undefined) {
      throw new KeyUnavailableError(
        active.keyId,
        `${role} key for version ${active.version} is not in the cache (call warm() first; the value path never unwraps)`,
      );
    }
    return { key, keyId: new Uint8Array(active.keyId) };
  }

  decryptionKeys(header: EnvelopeHeader): Uint8Array[] {
    const hit = this.#directory.byKeyId(header.keyId);
    if (hit === undefined) return [];
    const set = this.#directory.byScope(hit.scope);
    if (set === undefined) return [];
    // Named version first, then the active version, then the rest -- all
    // from cache; what is not cached is simply not a candidate ("serve only
    // what the cache can decrypt").
    const order = [hit.version, set.activeVersion, ...set.versions.map((v) => v.version)].filter((v, i, a) => a.indexOf(v) === i);
    const out: Uint8Array[] = [];
    for (const v of order) {
      const k = this.cache.get(cacheKey(hit.scope, v, "dek"));
      if (k !== undefined) out.push(k);
    }
    return out;
  }

  /** Unwraps every version for every scope in `contexts` and loads the cache. Failures are reported, never cached. */
  async warm(contexts: Iterable<FieldContext>): Promise<void> {
    const scopes = new Map<string, Uint8Array>();
    for (const ctx of contexts) {
      const s = scopeOf(ctx);
      scopes.set(Buffer.from(s).toString("hex"), s);
    }
    const errors: unknown[] = [];
    await Promise.all(
      [...scopes.values()].map((scope) =>
        this.#warmScope(scope).catch((e: unknown) => {
          errors.push(e);
        }),
      ),
    );
    if (errors.length > 0) {
      const first = errors[0];
      throw first instanceof Error ? first : new Error(String(first));
    }
  }

  #warmScope(scope: Uint8Array): Promise<void> {
    const k = Buffer.from(scope).toString("hex");
    const existing = this.#inflight.get(k);
    if (existing !== undefined) return existing;
    const p = (async () => {
      const set = this.#directory.byScope(scope);
      if (set === undefined) throw new KeyUnavailableError(null, "no key set is registered for this tenant scope");
      for (const v of set.versions) {
        const dek = await this.#wrapper.unwrap(v.wrappedDek, scope);
        this.cache.put(cacheKey(scope, v.version, "dek"), dek);
        dek.fill(0);
        if (v.wrappedIndexKey !== undefined) {
          const ik = await this.#wrapper.unwrap(v.wrappedIndexKey, scope);
          this.cache.put(cacheKey(scope, v.version, "index"), ik);
          ik.fill(0);
        }
      }
    })();
    this.#inflight.set(k, p);
    return p.finally(() => this.#inflight.delete(k));
  }
}
