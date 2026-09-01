/**
 * Key providers, the DEK cache, and construction-time configuration gates
 * (spec §5.5, §5.6, §7.6, §8; docs/09 §2, §7, §8). Out of scope for the
 * vector suite by design (docs/08 §8).
 */

import { describe, expect, it } from "vitest";
import { DekCache } from "../src/cache.ts";
import { DerivedKeyProvider, EnvelopeKeyProvider, InMemoryKeyDirectory, StaticKeyProvider, type EncryptionKey, type KeyProvider, type Wrapper } from "../src/keyprovider.ts";
import type { ResolvedContext } from "../src/context.ts";
import type { EnvelopeHeader } from "../src/envelope.ts";
import { Fieldseal, SUITE_FF01, type Warning } from "../src/index.ts";
import { bytes, codeOf, COLUMN, CTX, DEK, INDEX_KEY, KEY_ID, makeClient, messageOf, TABLE, withEnv } from "./helpers.ts";

const PT = bytes("123456789");

describe("DekCache (spec §5.5)", () => {
  it("validates thresholds: max-age > 0, 1 ≤ max-uses ≤ 2^32, capacity ≥ 1", () => {
    expect(() => new DekCache({ maxAgeMs: 0, maxUses: 1, capacity: 1 })).toThrow(/maxAgeMs/);
    expect(() => new DekCache({ maxAgeMs: 1, maxUses: 0, capacity: 1 })).toThrow(/maxUses/);
    expect(() => new DekCache({ maxAgeMs: 1, maxUses: 2 ** 32 + 1, capacity: 1 })).toThrow(/maxUses/);
    expect(() => new DekCache({ maxAgeMs: 1, maxUses: 2 ** 32, capacity: 1 })).not.toThrow();
    expect(() => new DekCache({ maxAgeMs: 1, maxUses: 1, capacity: 0 })).toThrow(/capacity/);
  });

  it("evicts on max-age and zeroizes", () => {
    let now = 1000;
    const evicted: string[] = [];
    const c = new DekCache({ maxAgeMs: 100, maxUses: 1000, capacity: 10 }, { now: () => now, onEvict: (k, cause) => evicted.push(`${k}:${cause}`) });
    const material = new Uint8Array(32).fill(9);
    c.put("k", material);
    expect(c.get("k")![0]).toBe(9);
    now = 1099;
    expect(c.get("k")).toBeDefined();
    now = 1100;
    expect(c.get("k")).toBeUndefined();
    expect(evicted).toEqual(["k:max-age"]);
    expect(material[0]).toBe(9); // the caller's copy is untouched; the cache held its own
  });

  it("sweeps expired entries on put(), without waiting for their key to be read", () => {
    let now = 0;
    const evicted: string[] = [];
    const c = new DekCache({ maxAgeMs: 100, maxUses: 1000, capacity: 10 }, { now: () => now, onEvict: (k, cause) => evicted.push(`${k}:${cause}`) });
    c.put("a", new Uint8Array(32).fill(1));
    c.put("b", new Uint8Array(32).fill(2));
    now = 100; // both expired; neither is ever get()
    c.put("c", new Uint8Array(32).fill(3));
    expect(c.size).toBe(1);
    expect(evicted.sort()).toEqual(["a:max-age", "b:max-age"]);
  });

  it("has() does not claim an expired entry", () => {
    let now = 0;
    const c = new DekCache({ maxAgeMs: 100, maxUses: 1000, capacity: 10 }, { now: () => now });
    c.put("k", new Uint8Array(32));
    expect(c.has("k")).toBe(true);
    now = 100;
    expect(c.has("k")).toBe(false);
    expect(c.size).toBe(0);
    expect(c.metrics.evictions["max-age"]).toBe(1);
  });

  it("peek() returns a copy without counting a §5.5 use, but still enforces max-age", () => {
    let now = 0;
    const c = new DekCache({ maxAgeMs: 100, maxUses: 2, capacity: 10 }, { now: () => now });
    c.put("k", new Uint8Array(32).fill(7));
    for (let i = 0; i < 50; i++) expect(c.peek("k")![0]).toBe(7); // never depletes max-uses
    const copy = c.peek("k")!;
    copy.fill(0);
    expect(c.peek("k")![0]).toBe(7); // a copy, not the cached material
    expect(c.get("k")).toBeDefined(); // use 1
    expect(c.get("k")).toBeDefined(); // use 2 → evicted
    expect(c.peek("k")).toBeUndefined();
    c.put("k2", new Uint8Array(32));
    now = 100;
    expect(c.peek("k2")).toBeUndefined();
    expect(c.metrics.evictions["max-age"]).toBe(1);
  });

  it("evicts on max-uses exactly, and returns copies (no aliasing)", () => {
    const c = new DekCache({ maxAgeMs: 1e9, maxUses: 3, capacity: 10 });
    c.put("k", new Uint8Array(32).fill(1));
    const a = c.get("k")!;
    a.fill(0xff);
    expect(c.get("k")![0]).toBe(1);
    expect(c.get("k")).toBeDefined(); // third use
    expect(c.get("k")).toBeUndefined();
    expect(c.metrics.evictions["max-uses"]).toBe(1);
  });

  it("evicts least-recently-used beyond capacity", () => {
    const c = new DekCache({ maxAgeMs: 1e9, maxUses: 1e6, capacity: 2 });
    c.put("a", new Uint8Array(32));
    c.put("b", new Uint8Array(32));
    c.get("a"); // a is now most recent
    c.put("c", new Uint8Array(32));
    expect(c.has("a")).toBe(true);
    expect(c.has("b")).toBe(false);
    expect(c.has("c")).toBe(true);
    expect(c.metrics.evictions.capacity).toBe(1);
  });

  it("clear() zeroizes everything", () => {
    const c = new DekCache({ maxAgeMs: 1e9, maxUses: 1e6, capacity: 5 });
    c.put("a", new Uint8Array(32).fill(1));
    c.clear();
    expect(c.size).toBe(0);
    expect(c.metrics.evictions.clear).toBe(1);
  });
});

describe("StaticKeyProvider (spec §8)", () => {
  it("warns through onWarning outside test configuration, and not inside it", () => {
    const w1: Warning[] = [];
    withEnv("FIELDSEAL_TEST_MODE", undefined, () => makeClient({}, undefined, w1));
    expect(w1.map((w) => w.kind)).toContain("static-key-provider");
    const w2: Warning[] = [];
    withEnv("FIELDSEAL_TEST_MODE", "1", () => makeClient({}, undefined, w2));
    expect(w2.map((w) => w.kind)).not.toContain("static-key-provider");
  });
  it("refuses an index key equal to the DEK (spec §5.2 sibling rule)", () => {
    expect(() => new StaticKeyProvider({ dek: DEK, keyId: KEY_ID, indexKey: DEK })).toThrow(/sibling/);
  });
  it("blindIndex without an index key → KEY_UNAVAILABLE", () => {
    const c = makeClient({
      keyProvider: new StaticKeyProvider({ dek: DEK, keyId: KEY_ID }),
      indexes: [{ tableUuid: TABLE, columnUuid: COLUMN, idf: "hmac-sha512", normalize: "identity", truncateBits: 15, projectedPopulation: 65536 }],
    });
    expect(codeOf(() => c.blindIndex(PT, { ...CTX, purpose: "index:exact" }))).toBe("KEY_UNAVAILABLE");
  });
});

describe("DerivedKeyProvider (docs/09 §8.2)", () => {
  const root = new Uint8Array(32).fill(0x5a);
  it("round-trips across tenants, versions, and without a tenant; index key is a sibling", async () => {
    const p = new DerivedKeyProvider({ rootSecret: root, versions: [1, 2], activeVersion: 2 });
    const c = makeClient({ keyProvider: p });
    const ctxA = CTX;
    const ctxB = { ...CTX, tenantId: bytes("tenant-0002") };
    const ctxNone = { ...CTX, tenantId: null };
    for (const ctx of [ctxA, ctxB, ctxNone]) {
      const env = c.encrypt(PT, ctx);
      expect(Buffer.from(c.decrypt(env, ctx)).equals(Buffer.from(PT))).toBe(true);
    }
    // Tenant A's envelope does not decrypt under tenant B's context.
    expect(codeOf(() => c.decrypt(c.encrypt(PT, ctxA), ctxB))).toBe("COMMITMENT_INVALID");
    // key_id carries the version; v1 and v2 differ; index key ≠ dek.
    const ek2 = p.encryptionKey({ ...ctxA, suiteId: SUITE_FF01 });
    expect(ek2.keyId.subarray(12, 16)).toEqual(new Uint8Array([0, 0, 0, 2]));
    const ik = p.encryptionKey({ ...ctxA, suiteId: SUITE_FF01, purpose: "index:exact" });
    expect(Buffer.from(ik.key).equals(Buffer.from(ek2.key))).toBe(false);
    // A v1 envelope (written by an older configuration) still decrypts with v2 active.
    const old = new DerivedKeyProvider({ rootSecret: root, versions: [1], activeVersion: 1 });
    const envV1 = makeClient({ keyProvider: old }).encrypt(PT, ctxA);
    expect(Buffer.from(c.decrypt(envV1, ctxA)).equals(Buffer.from(PT))).toBe(true);
    // A version no longer valid is never a silent fallback. Before warm()
    // the scope itself is unresolved -- KEY_UNAVAILABLE (no candidates).
    // After warm() the scope resolves, the retired v1 is excluded, and the
    // remaining v2 candidate is tried and fails the commitment check --
    // COMMITMENT_INVALID, the candidate loop's honest exhaustion code.
    const onlyV2 = makeClient({ keyProvider: new DerivedKeyProvider({ rootSecret: root, versions: [2] }) });
    expect(codeOf(() => onlyV2.decrypt(envV1, ctxA))).toBe("KEY_UNAVAILABLE");
    await onlyV2.warm([ctxA]);
    expect(codeOf(() => onlyV2.decrypt(envV1, ctxA))).toBe("COMMITMENT_INVALID");
  });
  it("resolves scopes it has not seen only after warm()", async () => {
    const writer = makeClient({ keyProvider: new DerivedKeyProvider({ rootSecret: root }) });
    const env = writer.encrypt(PT, CTX);
    const reader = makeClient({ keyProvider: new DerivedKeyProvider({ rootSecret: root }) });
    expect(codeOf(() => reader.decrypt(env, CTX))).toBe("KEY_UNAVAILABLE");
    await reader.warm([CTX]);
    expect(Buffer.from(reader.decrypt(env, CTX)).equals(Buffer.from(PT))).toBe(true);
  });
  it("validates its options", () => {
    expect(() => new DerivedKeyProvider({ rootSecret: new Uint8Array(16) })).toThrow(/32 bytes/);
    expect(() => new DerivedKeyProvider({ rootSecret: root, versions: [1, 1] })).toThrow(/distinct/);
    expect(() => new DerivedKeyProvider({ rootSecret: root, versions: [1], activeVersion: 2 })).toThrow(/activeVersion/);
  });
});

describe("EnvelopeKeyProvider (docs/09 §8.2)", () => {
  const scope = bytes("tenant-0001");
  const dekPlain = new Uint8Array(32).fill(0x11);
  const ikPlain = new Uint8Array(32).fill(0x22);
  // A toy wrapper: "wrapping" is XOR with 0x55, and every unwrap is counted.
  const unwraps: number[] = [];
  const wrapper: Wrapper = {
    async unwrap(wrapped) {
      unwraps.push(1);
      return wrapped.map((b) => b ^ 0x55);
    },
  };
  const wrap = (k: Uint8Array): Uint8Array => k.map((b) => b ^ 0x55);
  const directory = new InMemoryKeyDirectory([
    { scope, activeVersion: 1, versions: [{ version: 1, keyId: KEY_ID, wrappedDek: wrap(dekPlain), wrappedIndexKey: wrap(ikPlain) }] },
  ]);
  const provider = (): EnvelopeKeyProvider => new EnvelopeKeyProvider({ wrapper, directory, cache: { maxAgeMs: 60_000, maxUses: 1000, capacity: 16 } });

  it("value path is cache-only: KEY_UNAVAILABLE before warm(), works after, never unwraps on the value path", async () => {
    const p = provider();
    const c = makeClient({ keyProvider: p });
    unwraps.length = 0;
    expect(codeOf(() => c.encrypt(PT, CTX))).toBe("KEY_UNAVAILABLE");
    expect(unwraps.length).toBe(0);
    await c.warm([CTX, CTX]);
    expect(unwraps.length).toBe(2); // dek + index key, once each (single-flight)
    const env = c.encrypt(PT, CTX);
    expect(Buffer.from(c.decrypt(env, CTX)).equals(Buffer.from(PT))).toBe(true);
    expect(unwraps.length).toBe(2);
    expect(p.cache.metrics.hits).toBeGreaterThan(0);
  });

  it("an unknown tenant scope is KEY_UNAVAILABLE, and warm() reports it", async () => {
    const c = makeClient({ keyProvider: provider() });
    const other = { ...CTX, tenantId: bytes("nobody") };
    expect(codeOf(() => c.encrypt(PT, other))).toBe("KEY_UNAVAILABLE");
    await expect(c.warm([other])).rejects.toThrow(/scope/);
  });

  it("a failed unwrap never poisons the cache", async () => {
    const failing: Wrapper = {
      async unwrap() {
        throw new Error("KMS unreachable");
      },
    };
    const p = new EnvelopeKeyProvider({ wrapper: failing, directory, cache: { maxAgeMs: 60_000, maxUses: 1000, capacity: 16 } });
    const c = makeClient({ keyProvider: p });
    await expect(c.warm([CTX])).rejects.toThrow(/KMS/);
    expect(p.cache.size).toBe(0);
    expect(codeOf(() => c.encrypt(PT, CTX))).toBe("KEY_UNAVAILABLE");
  });

  it("max-uses eviction takes effect on the value path", async () => {
    const p = new EnvelopeKeyProvider({ wrapper, directory, cache: { maxAgeMs: 60_000, maxUses: 2, capacity: 16 } });
    const c = makeClient({ keyProvider: p });
    await c.warm([CTX]);
    c.encrypt(PT, CTX);
    c.encrypt(PT, CTX);
    expect(codeOf(() => c.encrypt(PT, CTX))).toBe("KEY_UNAVAILABLE");
  });

  it("decrypt-path candidate reads do not deplete §5.5 max-uses (docs/09 §8.3: uses count per encryptionKey return)", async () => {
    const p = new EnvelopeKeyProvider({ wrapper, directory, cache: { maxAgeMs: 60_000, maxUses: 3, capacity: 16 } });
    const c = makeClient({ keyProvider: p });
    await c.warm([CTX]);
    const env = c.encrypt(PT, CTX); // use 1
    for (let i = 0; i < 20; i++) {
      expect(Buffer.from(c.decrypt(env, CTX)).equals(Buffer.from(PT))).toBe(true);
    }
    c.encrypt(PT, CTX); // use 2
    c.encrypt(PT, CTX); // use 3 → evicted on return
    expect(codeOf(() => c.encrypt(PT, CTX))).toBe("KEY_UNAVAILABLE");
  });
});

describe("construction-time configuration gates (docs/09 §2, §7)", () => {
  const base = { keyProvider: new StaticKeyProvider({ dek: DEK, keyId: KEY_ID, indexKey: INDEX_KEY }) };
  const idx = { tableUuid: TABLE, columnUuid: COLUMN, idf: "hmac-sha512" as const, normalize: "identity" as const, truncateBits: 15, projectedPopulation: 65536 };

  it("allow-list: required, non-empty, registered, implemented; writeSuite in allow-list", () => {
    expect(messageOf(() => new Fieldseal({ ...base, allowedSuites: [], writeSuite: SUITE_FF01 }))).toMatch(/non-empty/);
    expect(messageOf(() => new Fieldseal({ ...base, allowedSuites: [0x0001], writeSuite: 0x0001 }))).toMatch(/not a registered suite/);
    expect(messageOf(() => new Fieldseal({ ...base, allowedSuites: [0xff02], writeSuite: 0xff02 }))).toMatch(/G7/);
    expect(messageOf(() => new Fieldseal({ ...base, allowedSuites: [SUITE_FF01], writeSuite: 0xff02 }))).toMatch(/writeSuite/);
    expect(messageOf(() => new Fieldseal({ ...base, allowedSuites: [SUITE_FF01], writeSuite: SUITE_FF01, readMode: "lenient" as never }))).toMatch(/readMode/);
  });

  it("index-id grammar refusals at declaration time (docs/08 §4.3: Exact, é, empty, 33 chars)", () => {
    for (const bad of ["Exact", "é", "", "a".repeat(33), "index:exact", "under_score"]) {
      expect(codeOf(() => makeClient({ indexes: [{ ...idx, indexId: bad }] })), JSON.stringify(bad)).toBe("CONFIGURATION_ERROR");
    }
    for (const good of ["exact", "prefix3", "email-domain", "a".repeat(32), "0"]) {
      expect(() => makeClient({ indexes: [{ ...idx, indexId: good }] }), good).not.toThrow();
    }
    // And at call time a malformed purpose is INVALID_ARGUMENT, never a derivation.
    const c = makeClient({ indexes: [idx] });
    expect(codeOf(() => c.blindIndex(PT, { ...CTX, purpose: "index:Exact" }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(() => c.blindIndex(PT, { ...CTX, purpose: "encrypt" }))).toBe("INVALID_ARGUMENT");
    // An undeclared index fails closed rather than falling back to a default IDF.
    expect(codeOf(() => c.blindIndex(PT, { ...CTX, purpose: "index:other" }))).toBe("CONFIGURATION_ERROR");
  });

  it("spec §7.6 cardinality gate: P < 2^10 or skewed needs a logged override", () => {
    expect(messageOf(() => makeClient({ indexes: [{ ...idx, truncateBits: 7, projectedPopulation: 512 }] }))).toMatch(/§7.6/);
    expect(messageOf(() => makeClient({ indexes: [{ ...idx, skewed: true }] }))).toMatch(/skewed/);
    expect(() =>
      makeClient({ indexes: [{ ...idx, truncateBits: 7, projectedPopulation: 512, cardinalityOverride: { reason: "reviewed", approvedBy: "ciso", date: "2026-08-22" } }] }),
    ).not.toThrow();
    expect(messageOf(() => makeClient({ indexes: [{ ...idx, projectedPopulation: 15, truncateBits: 2 }] }))).toMatch(/≥ 16/);
  });

  it("spec §7.4 band: 2 ≤ P·2^−b < √P", () => {
    expect(messageOf(() => makeClient({ indexes: [{ ...idx, truncateBits: 16, projectedPopulation: 100_000 }] }))).toMatch(/§7.4/); // 1.53 < 2
    expect(() => makeClient({ indexes: [{ ...idx, truncateBits: 15, projectedPopulation: 100_000 }] })).not.toThrow(); // 3.05
    expect(messageOf(() => makeClient({ indexes: [{ ...idx, truncateBits: 8, projectedPopulation: 100_000 }] }))).toMatch(/§7.4/); // 390 ≥ √P
  });

  it("argon2 parameters: minima enforced, forbidden on hmac", () => {
    expect(messageOf(() => makeClient({ indexes: [{ ...idx, idf: "argon2id", argon2: { timeCost: 2, memoryKib: 32768 } }] }))).toMatch(/timeCost/);
    expect(messageOf(() => makeClient({ indexes: [{ ...idx, idf: "argon2id", argon2: { timeCost: 3, memoryKib: 1024 } }] }))).toMatch(/memoryKib/);
    expect(messageOf(() => makeClient({ indexes: [{ ...idx, argon2: { timeCost: 3, memoryKib: 32768 } }] }))).toMatch(/hmac-sha512/);
  });

  it("argon2 cost reaches the derivation: a raised cost is a different index (#62)", () => {
    // The parity half of the gate above. A core that read t and m from a
    // module constant would return the minimum’s value for all three of
    // these and still agree with every shipped vector — the vectors pin the
    // minima — then disagree with this core the first time an operator raised
    // the cost, same column, two index values, lookup finds nothing. This
    // asserts only that the declared parameters are what the primitive is
    // invoked with; whether the primitive agrees with another core’s at a
    // raised cost is a vector obligation, and since suite 0.6.0-provisional
    // blind-index/argon2id.json carries it: raised-cost-t4-b15 and
    // unindexable-marker-t4-b15, both at t = 4.
    const at = (argon2?: { timeCost: number; memoryKib: number }): string =>
      makeClient({ indexes: [{ ...idx, idf: "argon2id" as const, ...(argon2 ? { argon2 } : {}) }] })
        .blindIndex(PT, { ...CTX, purpose: "index:exact" })
        .toString("hex");
    const minimum = at();
    expect(at({ timeCost: 3, memoryKib: 32768 })).toBe(minimum); // absent means the §7.3 minima
    expect(at({ timeCost: 4, memoryKib: 32768 })).not.toBe(minimum);
  });

  it("custom normalizers are refused; duplicate declarations are refused", () => {
    expect(messageOf(() => makeClient({ indexes: [{ ...idx, normalize: "my-normalizer" as never }] }))).toMatch(/portability/);
    expect(messageOf(() => makeClient({ indexes: [idx, idx] }))).toMatch(/duplicate/);
  });

  it("context validation at call time is typed", () => {
    const c = makeClient();
    expect(codeOf(() => c.encrypt(PT, { ...CTX, tableUuid: new Uint8Array(15) }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(() => c.encrypt(PT, { ...CTX, tenantId: "t" as never }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(() => c.encrypt(PT, { ...CTX, purpose: "index:exact" }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(() => c.encrypt(PT, null as never))).toBe("INVALID_ARGUMENT");
  });

  it("a provider returning malformed material is KEY_UNAVAILABLE", () => {
    const c = makeClient({ keyProvider: { encryptionKey: () => ({ key: new Uint8Array(16), keyId: KEY_ID }), decryptionKeys: () => [] } });
    expect(codeOf(() => c.encrypt(PT, CTX))).toBe("KEY_UNAVAILABLE");
    const c2 = makeClient({ keyProvider: { encryptionKey: () => ({ key: DEK, keyId: new Uint8Array(3) }), decryptionKeys: () => [] } });
    expect(codeOf(() => c2.encrypt(PT, CTX))).toBe("KEY_UNAVAILABLE");
  });

  it("a client-level cache policy is refused, not silently dropped", () => {
    const msg = messageOf(() => makeClient({ cache: { maxAgeMs: 60_000, maxUses: 1000, capacity: 16 } } as unknown as Record<string, never>));
    expect(msg).toMatch(/EnvelopeKeyProvider/);
    expect(msg).toMatch(/no effect/);
  });

  it("returned Buffers never alias caller or internal memory", () => {
    const c = makeClient();
    const env = c.encrypt(PT, CTX);
    const pt = c.decrypt(env, CTX);
    pt.fill(0);
    expect(Buffer.from(c.decrypt(env, CTX)).equals(Buffer.from(PT))).toBe(true);
    const copy = new Uint8Array(env);
    env.fill(0);
    expect(Buffer.from(c.decrypt(copy, CTX)).equals(Buffer.from(PT))).toBe(true);
  });

  it("returned Buffers do not alias Node's shared Buffer pool either (docs/11 §5)", () => {
    const c = makeClient({
      readMode: "permissive",
      indexes: [{ tableUuid: TABLE, columnUuid: COLUMN, idf: "hmac-sha512", normalize: "identity", truncateBits: 15, projectedPopulation: 65536 }],
    });
    const env = c.encrypt(PT, CTX);
    const outputs = [env, c.decrypt(env, CTX), c.decrypt(bytes("plain pass-through"), CTX), c.blindIndex(PT, { ...CTX, purpose: "index:exact" })];
    for (const out of outputs) {
      // A pool-backed Buffer is a view into a shared ArrayBuffer larger than
      // itself; an owned allocation's ArrayBuffer is exactly the Buffer.
      expect(out.buffer.byteLength).toBe(out.length);
      expect(out.byteOffset).toBe(0);
    }
  });
});

describe("key-material ownership (docs/09 §8.1; G17, issue #67)", () => {
  const IDX_CTX = { ...CTX, purpose: "index:exact" };
  const INDEX = {
    tableUuid: CTX.tableUuid, columnUuid: CTX.columnUuid,
    idf: "hmac-sha512" as const, normalize: "identity" as const,
    truncateBits: 15, projectedPopulation: 65536,
  };

  /**
   * A provider that hands out references to its own buffers instead of copies.
   * §8.1 permits this -- the three shipped providers return copies, but nothing
   * obliges a custom one to, and returning a reference is the obvious efficient
   * implementation for a provider backed by a key cache it already has.
   *
   * If the core erased what a provider returned, every assertion below would
   * fail against 32 zero bytes, and in a real deployment the damage would
   * surface one operation later as COMMITMENT_INVALID on a read of data
   * written moments earlier -- a decrypt-side error for a write-side memory
   * bug. That is the regression this block exists to hold.
   */
  class BorrowingProvider implements KeyProvider {
    readonly dek = new Uint8Array(DEK);
    readonly indexKey = new Uint8Array(INDEX_KEY);
    readonly keyId = new Uint8Array(KEY_ID);
    encryptionKey(ctx: ResolvedContext): EncryptionKey {
      return { key: ctx.purpose === "encrypt" ? this.dek : this.indexKey, keyId: this.keyId };
    }
    decryptionKeys(_header: EnvelopeHeader): Uint8Array[] {
      return [this.dek];
    }
  }

  it("encrypt() leaves the material encryptionKey returned intact", () => {
    const p = new BorrowingProvider();
    makeClient({ keyProvider: p }).encrypt(PT, CTX);
    expect(p.dek).toEqual(DEK);
    expect(p.keyId).toEqual(KEY_ID);
  });

  it("a second write under the same provider still round-trips", () => {
    // The failure mode is not visible on the write that does the damage.
    const p = new BorrowingProvider();
    const c = makeClient({ keyProvider: p });
    c.encrypt(PT, CTX);
    expect(Buffer.from(c.decrypt(c.encrypt(PT, CTX), CTX)).equals(Buffer.from(PT))).toBe(true);
  });

  it("decrypt() leaves the candidates decryptionKeys returned intact", () => {
    const p = new BorrowingProvider();
    const c = makeClient({ keyProvider: p });
    const env = c.encrypt(PT, CTX);
    expect(Buffer.from(c.decrypt(env, CTX)).equals(Buffer.from(PT))).toBe(true);
    expect(p.dek).toEqual(DEK);
    // ... and the same envelope decrypts again, which it could not if the
    // first read had consumed the key it borrowed.
    expect(Buffer.from(c.decrypt(env, CTX)).equals(Buffer.from(PT))).toBe(true);
  });

  it("blindIndex() leaves the index key intact, and stays deterministic", () => {
    const p = new BorrowingProvider();
    const c = makeClient({ keyProvider: p, indexes: [INDEX] });
    const first = c.blindIndex(PT, IDX_CTX);
    expect(p.indexKey).toEqual(INDEX_KEY);
    expect(c.blindIndex(PT, IDX_CTX)).toEqual(first);
  });

  it("the shipped providers return copies, so a caller's own buffer is never aliased", () => {
    // Not required by §8.1 -- a provider MAY return a reference. It is the
    // reason the pre-G17 `ek.key.fill(0)` never showed up in this suite, and
    // asserting it keeps that accident from being reintroduced as a silent
    // dependency of some other test.
    const p = new StaticKeyProvider({ dek: DEK, keyId: KEY_ID, indexKey: INDEX_KEY });
    const a = p.encryptionKey({ ...CTX, suiteId: SUITE_FF01 });
    expect(a.key).toEqual(DEK);
    expect(a.key).not.toBe(DEK);
    a.key.fill(0);
    expect(DEK).toEqual(new Uint8Array(32).map((_, i) => i));
  });
});
