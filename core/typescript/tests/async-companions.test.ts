/**
 * The asynchronous companions of spec §11.1: `blindIndexAsync` and
 * `unindexableMarkerAsync` (docs/11 §2, decided 2026-08-31 on the two-machine
 * measurement in docs/07 §7).
 *
 * The vector harness runs the whole suite a second time through these methods
 * and asserts identical bytes and identical error codes (docs/08 §5 item 10),
 * which is the larger half of the obligation. This file holds the four
 * properties that pass cannot see, because byte-identical output is exactly
 * what a *wrong* implementation of a companion also produces:
 *
 *   1. The companion actually yields the event loop. A `blindIndexAsync` that
 *      called `argon2Sync` and wrapped the result in `Promise.resolve` would
 *      satisfy every vector in the suite and fix nothing at all — the 352 ms
 *      p99 that decided this feature would still be there.
 *   2. The synchronous form does not route through the companion. Spec §11.1
 *      forbids implementing it by blocking on the async one; a core that did
 *      would still pass the suite, and would deadlock or degrade in exactly
 *      the deployments the sync API exists for.
 *   3. The refusals are rejections, with the same §9 code and the same
 *      precedence. A code that arrives as a synchronous throw from an `async`
 *      method is a code a caller's `.catch()` never sees.
 *   4. Nothing the core does not own is zeroed across the `await`, and the
 *      process-wide unindexable preimage survives being derived from.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { nodeArgon2Backend, UNINDEXABLE_PREIMAGE } from "../src/blindindex.ts";
import type { ResolvedContext } from "../src/context.ts";
import type { EnvelopeHeader } from "../src/envelope.ts";
import { FieldsealError } from "../src/errors.ts";
import { StaticKeyProvider, type EncryptionKey, type KeyProvider } from "../src/keyprovider.ts";
import { bytes, codeOf, codeOfAsync, CTX, DEK, INDEX_KEY, KEY_ID, makeClient } from "./helpers.ts";

const OVERRIDE = { reason: "legal name column; refusing a customer's name is worse", approvedBy: "test", date: "2026-09-04" };

const BASE = {
  tableUuid: CTX.tableUuid,
  columnUuid: CTX.columnUuid,
  normalize: "nfc-casefold-v1" as const,
  truncateBits: 15,
  projectedPopulation: 65536,
};

const COLUMNS = [
  { ...BASE, indexId: "hmac", idf: "hmac-sha512" as const },
  { ...BASE, indexId: "argon", idf: "argon2id" as const },
  { ...BASE, indexId: "raised", idf: "argon2id" as const, argon2: { timeCost: 4, memoryKib: 32768 } },
  { ...BASE, indexId: "bucket", idf: "argon2id" as const, onUnindexable: "bucket" as const, unindexableOverride: OVERRIDE },
  { ...BASE, indexId: "ident", idf: "argon2id" as const, normalize: "identity" as const },
];

const c = makeClient({ indexes: COLUMNS });
const at = (indexId: string): typeof CTX => ({ ...CTX, purpose: `index:${indexId}` });

/** A value with a code point Unicode 17.0 does not assign (docs/09 §7.2). */
const UNPINNED = "a͸b";
const VALUES = ["alice@example.com", "ALICE@example.com", "José", "grüße", "😀", ""];

afterEach(() => {
  vi.restoreAllMocks();
});

describe("byte identity (spec §11.1)", () => {
  it("the companion returns what the synchronous form returns, text or bytes", async () => {
    for (const column of ["hmac", "argon"]) {
      const ctx = at(column);
      for (const v of VALUES) {
        for (const input of [v, bytes(v)] as const) {
          const sync = c.blindIndex(input, ctx);
          const async = await c.blindIndexAsync(input, ctx);
          expect(async.equals(sync), `${column}/${JSON.stringify(v)}`).toBe(true);
          // Two calls, two allocations: neither may hand back the other's
          // buffer, and neither may be a view into Node's shared pool
          // (docs/11 §5).
          expect(async).not.toBe(sync);
          expect(async.buffer.byteLength).toBe(async.length);
          expect(async.byteOffset).toBe(0);
        }
      }
    }
  });

  it("a raised Argon2id cost reaches the companion's derivation too", async () => {
    // The parity half of providers.test.ts's #62 gate. A companion that read
    // t and m from a module constant instead of the declaration would agree
    // with the sync form on the minima column above and disagree here.
    for (const v of ["alice@example.com", "grüße"]) {
      expect((await c.blindIndexAsync(v, at("raised"))).equals(c.blindIndex(v, at("raised")))).toBe(true);
    }
    expect((await c.blindIndexAsync("alice@example.com", at("raised"))).equals(c.blindIndex("alice@example.com", at("argon")))).toBe(false);
  });

  it("the marker and the bucket agree across both forms", async () => {
    const marker = c.unindexableMarker(at("bucket"));
    expect((await c.unindexableMarkerAsync(at("bucket"))).equals(marker)).toBe(true);
    // A value the normalizer refuses lands in that same bucket either way.
    expect((await c.blindIndexAsync(UNPINNED, at("bucket"))).equals(marker)).toBe(true);
  });
});

describe("rejection parity (spec §11.1: the same §9 error for the same condition)", () => {
  const noIndexKey = makeClient({
    keyProvider: new StaticKeyProvider({ dek: DEK, keyId: KEY_ID }),
    indexes: COLUMNS,
  });

  /** A provider whose failure is not already a typed §9 error. */
  class ThrowingProvider implements KeyProvider {
    encryptionKey(_ctx: ResolvedContext): EncryptionKey {
      throw new Error("the KMS is having a day");
    }
    decryptionKeys(_header: EnvelopeHeader): Uint8Array[] {
      return [];
    }
  }
  const providerThrows = makeClient({ keyProvider: new ThrowingProvider(), indexes: COLUMNS });

  interface Refusal {
    readonly name: string;
    readonly code: string;
    readonly sync: () => unknown;
    readonly async: () => Promise<unknown>;
  }

  const REFUSALS: readonly Refusal[] = [
    { name: "value 42", code: "INVALID_ARGUMENT", sync: () => c.blindIndex(42 as never, at("argon")), async: () => c.blindIndexAsync(42 as never, at("argon")) },
    { name: "value null", code: "INVALID_ARGUMENT", sync: () => c.blindIndex(null as never, at("argon")), async: () => c.blindIndexAsync(null as never, at("argon")) },
    { name: "value {}", code: "INVALID_ARGUMENT", sync: () => c.blindIndex({} as never, at("argon")), async: () => c.blindIndexAsync({} as never, at("argon")) },
    { name: "value undefined", code: "INVALID_ARGUMENT", sync: () => c.blindIndex(undefined as never, at("argon")), async: () => c.blindIndexAsync(undefined as never, at("argon")) },
    { name: "ctx null", code: "INVALID_ARGUMENT", sync: () => c.blindIndex("x", null as never), async: () => c.blindIndexAsync("x", null as never) },
    { name: "ctx null (marker)", code: "INVALID_ARGUMENT", sync: () => c.unindexableMarker(null as never), async: () => c.unindexableMarkerAsync(null as never) },
    { name: "purpose encrypt", code: "INVALID_ARGUMENT", sync: () => c.blindIndex("x", { ...CTX, purpose: "encrypt" }), async: () => c.blindIndexAsync("x", { ...CTX, purpose: "encrypt" }) },
    { name: "purpose index:Argon", code: "INVALID_ARGUMENT", sync: () => c.blindIndex("x", at("Argon")), async: () => c.blindIndexAsync("x", at("Argon")) },
    { name: "undeclared index", code: "CONFIGURATION_ERROR", sync: () => c.blindIndex("x", at("nope")), async: () => c.blindIndexAsync("x", at("nope")) },
    { name: "undeclared index (marker)", code: "CONFIGURATION_ERROR", sync: () => c.unindexableMarker(at("nope")), async: () => c.unindexableMarkerAsync(at("nope")) },
    { name: "provider has no index key", code: "KEY_UNAVAILABLE", sync: () => noIndexKey.blindIndex("x", at("argon")), async: () => noIndexKey.blindIndexAsync("x", at("argon")) },
    { name: "provider throws untyped", code: "KEY_UNAVAILABLE", sync: () => providerThrows.blindIndex("x", at("argon")), async: () => providerThrows.blindIndexAsync("x", at("argon")) },
    { name: "lone surrogate", code: "INVALID_ARGUMENT", sync: () => c.blindIndex("a\uD800b", at("argon")), async: () => c.blindIndexAsync("a\uD800b", at("argon")) },
    { name: "unassigned code point under refuse", code: "INVALID_ARGUMENT", sync: () => c.blindIndex(UNPINNED, at("argon")), async: () => c.blindIndexAsync(UNPINNED, at("argon")) },
    // Order pin: the key is acquired before the value is normalized, so a
    // call that is wrong in both ways reports the key, not the value. The
    // harness relies on this precedence and the companion must not reorder
    // it by moving key acquisition after the first await.
    { name: "no index key AND a lone surrogate", code: "KEY_UNAVAILABLE", sync: () => noIndexKey.blindIndex("a\uD800b", at("argon")), async: () => noIndexKey.blindIndexAsync("a\uD800b", at("argon")) },
  ];

  it("each condition carries the same code on both paths", async () => {
    for (const r of REFUSALS) {
      expect(codeOf(r.sync), r.name).toBe(r.code);
      expect(await codeOfAsync(r.async), r.name).toBe(r.code);
    }
  });

  it("each refusal is a rejection, not a synchronous throw", async () => {
    // An `async` method that validated its arguments in a synchronous
    // wrapper would pass the test above and still break every caller who
    // wrote `client.blindIndexAsync(v, ctx).catch(...)`.
    for (const r of REFUSALS) {
      let p: unknown;
      expect(() => {
        p = r.async();
      }, r.name).not.toThrow();
      expect(p, r.name).toBeInstanceOf(Promise);
      await expect(p as Promise<unknown>, r.name).rejects.toBeInstanceOf(FieldsealError);
    }
  });

  it("the refusal still says which character it refused", async () => {
    // docs/09 §7.2 refuses two malformed values distinguishably; that must
    // survive the trip through the companion.
    const message = await c.blindIndexAsync("a\uD800b", at("argon")).then(
      () => "",
      (e: unknown) => (e as Error).message,
    );
    expect(message).toMatch(/D800/);
    expect(message).not.toMatch(/DC00/);
  });
});

describe("the companion is not the synchronous form in disguise (spec §11.1)", () => {
  /**
   * Counts event-loop turns taken while `work` runs. `setImmediate` fires in
   * the check phase, which a blocking derivation never reaches.
   *
   * What each side of this is worth, stated exactly, because the shape
   * invites over-reading. The `toBeGreaterThan(0)` assertions are the real
   * test: they fail for a companion that is the synchronous form in
   * disguise. The `toBe(0)` on the synchronous call is a much weaker
   * control than "the loop stood still" — `turns` is 0 for *any* callable
   * that does not yield, a no-op included (measured: no-op 0, `argon2Sync`
   * 0, `Promise.resolve(argon2Sync(...))` 0, real `argon2` ~87000). It
   * rules out a `blindIndex` that yields to the loop, and nothing more; it
   * does not observe blocking. Kept for that narrower property.
   *
   * Only 0 and "more than 0" are asserted anywhere. Durations are not
   * assertable in CI (docs/14 §7).
   */
  async function loopTurns(work: () => unknown): Promise<number> {
    let turns = 0;
    let stop = false;
    const turn = (): void => {
      turns += 1;
      if (!stop) setImmediate(turn);
    };
    await new Promise<void>((resolve) => setImmediate(resolve)); // let the loop settle
    setImmediate(turn);
    try {
      const r = work();
      if (r instanceof Promise) await r;
      return turns; // read here: for synchronous work, without an await in between
    } finally {
      stop = true;
    }
  }

  it("the synchronous derivation takes the loop with it; the companion does not", async () => {
    expect(await loopTurns(() => c.blindIndex("alice@example.com", at("argon")))).toBe(0);
    expect(await loopTurns(() => c.blindIndexAsync("alice@example.com", at("argon")))).toBeGreaterThan(0);
    expect(await loopTurns(() => c.unindexableMarkerAsync(at("bucket")))).toBeGreaterThan(0);
  });

  it("neither form routes through the other's backend", async () => {
    // The positive assertions are what make the negative ones non-vacuous: a
    // spy that was never installed on the path under test would satisfy
    // `not.toHaveBeenCalled()` for the wrong reason.
    const sync = vi.spyOn(nodeArgon2Backend, "argon2id");
    const async = vi.spyOn(nodeArgon2Backend, "argon2idAsync");

    c.blindIndex("alice@example.com", at("argon"));
    expect(sync).toHaveBeenCalledTimes(1);
    expect(async).not.toHaveBeenCalled();

    sync.mockClear();
    async.mockClear();

    await c.blindIndexAsync("alice@example.com", at("argon"));
    expect(async).toHaveBeenCalledTimes(1);
    expect(sync).not.toHaveBeenCalled();
  });

  it("an hmac column touches neither Argon2id form", async () => {
    const sync = vi.spyOn(nodeArgon2Backend, "argon2id");
    const async = vi.spyOn(nodeArgon2Backend, "argon2idAsync");
    c.blindIndex("alice@example.com", at("hmac"));
    await c.blindIndexAsync("alice@example.com", at("hmac"));
    expect(sync).not.toHaveBeenCalled();
    expect(async).not.toHaveBeenCalled();
  });
});

describe("what crosses the await (docs/09 §8.1; the pinned key-material-ownership decision)", () => {
  it("the caller's buffer is not read across the await, and is not erased", async () => {
    // `identity` hands the caller's own array through as the normalized
    // value. The companion copies it before yielding, so a caller who reuses
    // or clears the buffer while the derivation is in flight still gets the
    // index of the bytes they passed.
    const ctx = at("ident");
    const buf = bytes("alice@example.com");
    const expected = c.blindIndex(new Uint8Array(buf), ctx);

    const pending = c.blindIndexAsync(buf, ctx);
    buf.fill(0); // the caller reuses their buffer immediately
    expect((await pending).equals(expected)).toBe(true);

    const intact = bytes("alice@example.com");
    await c.blindIndexAsync(intact, ctx);
    expect(intact).toEqual(bytes("alice@example.com")); // the core zeroes only what it owns
  });

  it("the borrowed index key survives the companion", async () => {
    class BorrowingProvider implements KeyProvider {
      readonly indexKey = new Uint8Array(INDEX_KEY);
      readonly keyId = new Uint8Array(KEY_ID);
      readonly dek = new Uint8Array(DEK);
      encryptionKey(ctx: ResolvedContext): EncryptionKey {
        return { key: ctx.purpose === "encrypt" ? this.dek : this.indexKey, keyId: this.keyId };
      }
      decryptionKeys(_header: EnvelopeHeader): Uint8Array[] {
        return [this.dek];
      }
    }
    const p = new BorrowingProvider();
    const b = makeClient({ keyProvider: p, indexes: COLUMNS });
    const first = await b.blindIndexAsync("alice@example.com", at("argon"));
    expect(p.indexKey).toEqual(INDEX_KEY);
    expect((await b.blindIndexAsync("alice@example.com", at("argon"))).equals(first)).toBe(true);
  });

  it("the process-wide unindexable preimage survives being derived from", async () => {
    // UNINDEXABLE_PREIMAGE is a module singleton passed by reference into the
    // derivation. Zeroing it — the obvious "optimisation" if the copy in the
    // async path ever looks redundant — would silently destroy every
    // subsequent marker in the process, and every bucket lookup with it.
    const expected = new Uint8Array([0xff, ...Buffer.from("fieldseal-unindexable-v1", "ascii")]);
    const marker = c.unindexableMarker(at("bucket"));

    await c.unindexableMarkerAsync(at("bucket"));
    expect(UNINDEXABLE_PREIMAGE).toEqual(expected);

    await c.blindIndexAsync(UNPINNED, at("bucket")); // the rescue path, which substitutes the singleton
    expect(UNINDEXABLE_PREIMAGE).toEqual(expected);

    expect(c.unindexableMarker(at("bucket")).equals(marker)).toBe(true);
    expect((await c.unindexableMarkerAsync(at("bucket"))).equals(marker)).toBe(true);
  });
});

describe("concurrency", () => {
  it("eight concurrent derivations agree with eight sequential ones", async () => {
    // Eight is above the default UV_THREADPOOL_SIZE of 4, so the queue is
    // exercised rather than just the pool. UV_THREADPOOL_SIZE is deliberately
    // never set here: it is read once when the pool first spins up, and a
    // test that set it would be asserting something about the runner rather
    // than about this core.
    const values = ["a", "b", "c", "d", "e", "f", "g", "h"].map((s) => `${s}@example.com`);
    const sequential = values.map((v) => c.blindIndex(v, at("argon")));
    const concurrent = await Promise.all(values.map((v) => c.blindIndexAsync(v, at("argon"))));
    for (const [i, out] of concurrent.entries()) {
      expect(out.equals(sequential[i] as Buffer), values[i]).toBe(true);
    }
  });

  it("eight concurrent derivations of one value share no buffer", async () => {
    const outs = await Promise.all(Array.from({ length: 8 }, () => c.blindIndexAsync("alice@example.com", at("argon"))));
    const first = outs[0] as Buffer;
    for (const out of outs) {
      expect(out.equals(first)).toBe(true);
      expect(out.buffer.byteLength).toBe(out.length);
      expect(out.byteOffset).toBe(0);
    }
    expect(new Set(outs).size).toBe(8);
  });
});

describe("the Argon2id salt is key material and is erased (spec §7.3)", () => {
  /**
   * Spec §7.3 forbids Argon2's `K` and `X`, so "keying now rests entirely on
   * the salt" (`docs/02` line 546) and those 16 bytes carry the full strength
   * of the column's index key: anyone holding the salt can run the same
   * offline dictionary attack on that column's stored indexes as the holder
   * of the key. The core erases the key, the per-column key, the untruncated
   * IDF output and its copy of the normalized value, so leaving the salt to
   * GC would have been the one gap in the set — flagged in review of #111 and
   * closed on both paths.
   *
   * The salt is never handed to a caller, so the only place to observe it is
   * the backend seam. The spy captures the *reference*, not a copy.
   */
  // Bound before the spy replaces the property, so calling through does not
  // re-enter the spy.
  const realSync = nodeArgon2Backend.argon2id.bind(nodeArgon2Backend);
  const realAsync = nodeArgon2Backend.argon2idAsync.bind(nodeArgon2Backend);

  function captureSyncSalt(): () => Uint8Array {
    let seen: Uint8Array | undefined;
    vi.spyOn(nodeArgon2Backend, "argon2id").mockImplementation((pw, salt, t, m, p, len) => {
      seen = salt;
      return realSync(pw, salt, t, m, p, len);
    });
    return () => seen ?? expect.fail("argon2id was never called");
  }

  function captureAsyncSalt(): () => Uint8Array {
    let seen: Uint8Array | undefined;
    vi.spyOn(nodeArgon2Backend, "argon2idAsync").mockImplementation((pw, salt, t, m, p, len) => {
      seen = salt;
      return realAsync(pw, salt, t, m, p, len);
    });
    return () => seen ?? expect.fail("argon2idAsync was never called");
  }

  it("the synchronous path zeroes the salt once the derivation returns", () => {
    const salt = captureSyncSalt();
    const out = c.blindIndex("alice@example.com", at("argon"));
    // The derivation still produced the right answer, so the erasure happened
    // after the read and not before it — the assertion below would also pass
    // for a core that zeroed the salt too early and derived from zeros.
    expect(out.equals(c.blindIndex("alice@example.com", at("argon")))).toBe(true);
    expect(salt()).toEqual(new Uint8Array(16));
  });

  it("the companion zeroes the salt once the derivation completes", async () => {
    const salt = captureAsyncSalt();
    const out = await c.blindIndexAsync("alice@example.com", at("argon"));
    expect(out.equals(c.blindIndex("alice@example.com", at("argon")))).toBe(true);
    expect(salt()).toEqual(new Uint8Array(16));
  });

  it("the salt is erased on the refusal path too, not only on success", async () => {
    // A backend that throws stands in for any derivation failure: the salt
    // must not outlive the call because the call did not finish.
    const seen: Uint8Array[] = [];
    vi.spyOn(nodeArgon2Backend, "argon2idAsync").mockImplementation((_pw, salt) => {
      seen.push(salt);
      return Promise.reject(new Error("backend failure"));
    });
    await expect(c.blindIndexAsync("alice@example.com", at("argon"))).rejects.toThrow("backend failure");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual(new Uint8Array(16));
  });
});
