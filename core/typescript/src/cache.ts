/**
 * In-memory tenant-DEK cache (spec §5.5; docs/09 §8.3).
 *
 * Eviction on max-age AND max-uses (≤ 2^32) AND capacity (LRU). Evicted
 * material is overwritten with zeros. Max-age is enforced on every read
 * (`get`, `peek`, `has`) and swept on every `put`, so expired material does
 * not linger until its exact key happens to be read again. Uses count per
 * cached entry, incremented per `encryption_key` return (docs/09 §8.3);
 * decrypt-path candidate reads go through `peek` and do not count.
 *
 * Zeroization honesty (docs/11 §5): `fill(0)` overwrites the visible
 * allocation. V8 may have copied the bytes during earlier operations and
 * `node:crypto` may hold internal copies; no `mlock` is available for
 * GC-managed memory. This cache therefore reduces, and cannot eliminate, the
 * exposure of plaintext key material to memory dumps, core files and swap --
 * which is the residual risk spec §5.5 requires every implementation to
 * document. TTL is a security parameter, not a tuning knob.
 */

import { ConfigurationError } from "./errors.ts";

export interface CachePolicy {
  /** Max age of an entry in milliseconds; must be > 0. */
  readonly maxAgeMs: number;
  /** Max returns of an entry before eviction; 1..2^32 (spec §5.5). */
  readonly maxUses: number;
  /** Max entries; least-recently-used eviction beyond it. */
  readonly capacity: number;
}

export type EvictionCause = "max-age" | "max-uses" | "capacity" | "explicit" | "clear";

export interface CacheMetrics {
  hits: number;
  misses: number;
  evictions: Record<EvictionCause, number>;
}

export interface CacheHooks {
  readonly onEvict?: (key: string, cause: EvictionCause) => void;
  /** Injectable clock for tests; defaults to Date.now. */
  readonly now?: () => number;
}

interface Entry {
  material: Uint8Array;
  insertedAt: number;
  uses: number;
}

export const MAX_USES_CEILING = 2 ** 32;

export function validateCachePolicy(p: CachePolicy): void {
  if (!(typeof p.maxAgeMs === "number") || !(p.maxAgeMs > 0) || !Number.isFinite(p.maxAgeMs)) {
    throw new ConfigurationError("cache.maxAgeMs must be a finite number > 0 (spec §5.5)");
  }
  if (!Number.isInteger(p.maxUses) || p.maxUses < 1 || p.maxUses > MAX_USES_CEILING) {
    throw new ConfigurationError(`cache.maxUses must be an integer in 1..2^32 (spec §5.5); got ${p.maxUses}`);
  }
  if (!Number.isInteger(p.capacity) || p.capacity < 1) {
    throw new ConfigurationError("cache.capacity must be an integer ≥ 1");
  }
}

export class DekCache {
  readonly policy: CachePolicy;
  readonly metrics: CacheMetrics = {
    hits: 0,
    misses: 0,
    evictions: { "max-age": 0, "max-uses": 0, capacity: 0, explicit: 0, clear: 0 },
  };
  // Map iteration order is insertion order; re-inserting on access makes it an LRU.
  readonly #entries = new Map<string, Entry>();
  readonly #hooks: CacheHooks;
  readonly #now: () => number;

  constructor(policy: CachePolicy, hooks: CacheHooks = {}) {
    validateCachePolicy(policy);
    this.policy = policy;
    this.#hooks = hooks;
    this.#now = hooks.now ?? Date.now;
  }

  get size(): number {
    return this.#entries.size;
  }

  /** Stores a private copy of `material`; the caller's buffer is never aliased. */
  put(key: string, material: Uint8Array): void {
    // TTL is a security parameter (spec §5.5): expired material must not sit
    // in memory until someone happens to `get` its exact key. Sweeping here
    // keeps eviction off the value path (`put` runs from warm()/refresh) and
    // stops expired entries from consuming capacity evictions of live ones.
    this.#sweepExpired();
    const existing = this.#entries.get(key);
    if (existing !== undefined) this.#drop(key, existing, "explicit", false);
    while (this.#entries.size >= this.policy.capacity) {
      const oldest = this.#entries.keys().next().value as string;
      this.#drop(oldest, this.#entries.get(oldest) as Entry, "capacity", true);
    }
    this.#entries.set(key, { material: new Uint8Array(material), insertedAt: this.#now(), uses: 0 });
  }

  /**
   * Returns a copy of the cached material, or undefined. Counts one use; an
   * entry that reaches max-uses is returned this last time and then evicted,
   * so the threshold is an exact count of returns.
   */
  get(key: string): Uint8Array | undefined {
    const e = this.#entries.get(key);
    if (e === undefined) {
      this.metrics.misses++;
      return undefined;
    }
    if (this.#now() - e.insertedAt >= this.policy.maxAgeMs) {
      this.#drop(key, e, "max-age", true);
      this.metrics.misses++;
      return undefined;
    }
    this.metrics.hits++;
    const out = new Uint8Array(e.material);
    e.uses++;
    if (e.uses >= this.policy.maxUses) {
      this.#drop(key, e, "max-uses", true);
    } else {
      // LRU touch.
      this.#entries.delete(key);
      this.#entries.set(key, e);
    }
    return out;
  }

  /**
   * Returns a copy of the cached material without counting a §5.5 use.
   * docs/09 §8.3: use counting is incremented per `encryption_key` return —
   * a decrypt-path candidate read is not a use of the entry. Max-age is
   * still enforced (an expired key must never be served, counted or not);
   * there is no LRU touch, so peeks do not keep an otherwise-idle entry
   * alive past capacity pressure.
   */
  peek(key: string): Uint8Array | undefined {
    const e = this.#entries.get(key);
    if (e === undefined) {
      this.metrics.misses++;
      return undefined;
    }
    if (this.#now() - e.insertedAt >= this.policy.maxAgeMs) {
      this.#drop(key, e, "max-age", true);
      this.metrics.misses++;
      return undefined;
    }
    this.metrics.hits++;
    return new Uint8Array(e.material);
  }

  has(key: string): boolean {
    const e = this.#entries.get(key);
    if (e === undefined) return false;
    if (this.#now() - e.insertedAt >= this.policy.maxAgeMs) {
      // An expired entry is not "had"; saying otherwise would let a caller
      // act on key material the TTL already retired.
      this.#drop(key, e, "max-age", true);
      return false;
    }
    return true;
  }

  evict(key: string): void {
    const e = this.#entries.get(key);
    if (e !== undefined) this.#drop(key, e, "explicit", true);
  }

  /** Evicts and zeroizes everything (e.g. before a fork, docs/09 §10). */
  clear(): void {
    for (const [k, e] of [...this.#entries]) this.#drop(k, e, "clear", true);
  }

  #sweepExpired(): void {
    const now = this.#now();
    // Entries are in LRU order (get() re-inserts), not insertion-time order,
    // so a full walk is required; n is bounded by `capacity`.
    for (const [k, e] of [...this.#entries]) {
      if (now - e.insertedAt >= this.policy.maxAgeMs) this.#drop(k, e, "max-age", true);
    }
  }

  #drop(key: string, e: Entry, cause: EvictionCause, count: boolean): void {
    e.material.fill(0);
    this.#entries.delete(key);
    if (count) {
      this.metrics.evictions[cause]++;
      this.#hooks.onEvict?.(key, cause);
    }
  }
}
