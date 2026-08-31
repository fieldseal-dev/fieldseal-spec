/**
 * L4 -- key acquisition in the value path (`docs/13` §5, §7; spec §10.1).
 *
 * The claim under test is narrow and worth stating exactly: **the core's value
 * path still performs no I/O.** `encrypt`, `decrypt` and `blindIndex` remain
 * synchronous and still refuse a cache miss with `KEY_UNAVAILABLE`, exactly as
 * they do under Django. What Prisma adds is an `await` *between* those
 * synchronous calls -- `$allOperations` is async and runs before the query
 * engine acquires a connection -- so the adapter can warm the cache and run the
 * pass again instead of handing the caller a refusal.
 *
 * So the instrumentation is the test. The provider below flags itself while a
 * synchronous core entry point is on the stack, and the KMS wrapper fails the
 * run if it is ever asked to unwrap while that flag is set. A regression that
 * "fixed" L4 by making the core block on the network would pass every
 * behavioural assertion here and fail that one.
 *
 * The other half is the journal (`journal.ts`): a retry only means anything if
 * the failed attempt left nothing behind. The `staged` provider below is what
 * makes that testable -- it misses per column rather than per tenant scope, so
 * a write can be interrupted *between* two columns of one row, which is
 * precisely the state a naive retry would encrypt a second time.
 *
 * **Measured, and it narrows the claim** (Prisma 7.10.0, 2026-08-31): Prisma
 * hands the extension a **copy** of the caller's arguments -- `args.data` is
 * not the object the caller passed. So the journal is not a caller-facing
 * promise that a refused write leaves your object alone; it is an internal
 * invariant about the tree the pipeline itself walks, and the retry is the only
 * thing that can observe it. The tests assert it that way rather than through
 * an identity that does not hold.
 */

import { beforeEach, describe, expect, it } from "vitest";

import {
  EnvelopeKeyProvider,
  type EnvelopeHeader,
  InMemoryKeyDirectory,
  KeyUnavailableError,
  type KeyProvider,
  type ResolvedContext,
  type Wrapper,
} from "@fieldseal/core";

import { Journal } from "../src/journal.ts";
import { tenantScope } from "../src/index.ts";
import { clearDb, DEK, INDEX_KEY, KEY_ID, loose, makeClient } from "./helpers.ts";

/** The scope every column that is not `tenant_bound` derives under. */
const NO_TENANT = new Uint8Array(0);
const TENANT = Buffer.from("tenant-0001", "utf8");

const DEK_A = new Uint8Array(32).fill(0x11);
const IK_A = new Uint8Array(32).fill(0x22);
const DEK_B = new Uint8Array(32).fill(0x33);
const IK_B = new Uint8Array(32).fill(0x44);

const KEY_ID_B = Buffer.from("0102030405060708090a0b0c0d0e0f11", "hex");

/** "Wrapping" is XOR with 0x55. The point is that it is *asynchronous*. */
const wrap = (k: Uint8Array): Uint8Array => k.map((b) => b ^ 0x55);

interface Rig {
  readonly provider: KeyProvider;
  /** One entry per KMS unwrap, in order. */
  readonly unwraps: string[];
  /** Set while a synchronous core entry point is on the stack. */
  readonly state: { inSyncCoreCall: boolean; violations: number };
}

/**
 * A cold `EnvelopeKeyProvider`, wrapped so the value path can be watched.
 *
 * `warmable: false` builds the same provider with `warm` removed, which is how
 * a `StaticKeyProvider`-shaped deployment looks to the extension: L4 has
 * nothing to call and must not pretend otherwise.
 */
function rig(opts: { warmable?: boolean; warmDoesNothing?: boolean } = {}): Rig {
  const unwraps: string[] = [];
  const state = { inSyncCoreCall: false, violations: 0 };

  const wrapper: Wrapper = {
    async unwrap(wrapped) {
      // The assertion this file exists for. `unwrap` is the only network-shaped
      // call in the provider; if it is ever reached from inside a synchronous
      // core operation, the core's docs/09 §8.2 rule has been broken.
      if (state.inSyncCoreCall) state.violations++;
      unwraps.push("unwrap");
      // A real KMS round trip yields to the event loop. So does this one, which
      // is what makes a synchronous caller structurally unable to await it.
      await Promise.resolve();
      return wrapped.map((b) => b ^ 0x55);
    },
  };

  const directory = new InMemoryKeyDirectory([
    {
      scope: NO_TENANT,
      activeVersion: 1,
      versions: [
        { version: 1, keyId: KEY_ID, wrappedDek: wrap(DEK_A), wrappedIndexKey: wrap(IK_A) },
      ],
    },
    {
      scope: TENANT,
      activeVersion: 1,
      versions: [
        { version: 1, keyId: KEY_ID_B, wrappedDek: wrap(DEK_B), wrappedIndexKey: wrap(IK_B) },
      ],
    },
  ]);

  const inner = new EnvelopeKeyProvider({
    wrapper,
    directory,
    cache: { maxAgeMs: 60_000, maxUses: 100_000, capacity: 16 },
  });

  const provider: KeyProvider = {
    encryptionKey(ctx: ResolvedContext) {
      state.inSyncCoreCall = true;
      try {
        return inner.encryptionKey(ctx);
      } finally {
        state.inSyncCoreCall = false;
      }
    },
    decryptionKeys(header: EnvelopeHeader) {
      state.inSyncCoreCall = true;
      try {
        return inner.decryptionKeys(header);
      } finally {
        state.inSyncCoreCall = false;
      }
    },
  };
  if (opts.warmable !== false) {
    (provider as { warm?: KeyProvider["warm"] }).warm = opts.warmDoesNothing === true
      ? async () => {
          unwraps.push("warm-noop");
        }
      : (contexts) => inner.warm(contexts);
  }

  return { provider, unwraps, state };
}

/**
 * A provider that misses **per column**, not per tenant scope.
 *
 * `EnvelopeKeyProvider` warms a whole scope at a time, and every column in the
 * fixture that is not `tenant_bound` shares one scope -- so a miss there is
 * always the first core call of the operation and never interrupts a row half
 * way. The `KeyProvider` interface does not require that granularity, and this
 * one serves the first `serveEncrypts` key requests and then refuses until
 * `warm()` opens it, which puts the miss wherever the test needs it.
 *
 * `decryptionKeys` sees only the envelope header, never a context, so the read
 * side is staged by count for the same reason.
 */
function staged(opts: { serveEncrypts?: number; serveDecrypts?: number }): {
  provider: KeyProvider;
  readonly warms: number;
} {
  let encrypts = 0;
  let decrypts = 0;
  let open = false;
  const counters = { warms: 0 };
  const provider: KeyProvider = {
    encryptionKey(ctx: ResolvedContext) {
      if (!open && encrypts++ >= (opts.serveEncrypts ?? 0)) {
        throw new KeyUnavailableError(KEY_ID, "staged provider: not warmed yet");
      }
      const index = ctx.purpose.startsWith("index:");
      return { key: new Uint8Array(index ? INDEX_KEY : DEK), keyId: new Uint8Array(KEY_ID) };
    },
    decryptionKeys(_header: EnvelopeHeader) {
      if (!open && decrypts++ >= (opts.serveDecrypts ?? 0)) return [];
      return [new Uint8Array(DEK)];
    },
    async warm() {
      counters.warms++;
      await Promise.resolve();
      open = true;
    },
  };
  return {
    provider,
    get warms() {
      return counters.warms;
    },
  };
}

describe("L4: warm() in the value path (docs/13 §5)", () => {
  beforeEach(async () => {
    const { base } = makeClient();
    await clearDb(base);
    await base.$disconnect();
  });

  it("is the difference between a cold deployment that works and one that does not", async () => {
    // The failure first, so the fix is measured against something. This is
    // exactly what Django's warm tests describe: an EnvelopeKeyProvider whose
    // cache is cold serves KEY_UNAVAILABLE for every operation until an
    // operator warms it out of band.
    const cold = rig();
    const { prisma: strict, base: b1 } = makeClient({
      keyProvider: cold.provider,
      warmOnKeyMiss: false,
    });
    await expect(
      loose(strict)["patient"]!["create"]!({
        data: { email: "ada@example.com", note: "n", age: 36, plainName: "Ada" },
      }),
    ).rejects.toThrow(/KEY_UNAVAILABLE|no key is available/);
    expect(cold.unwraps).toEqual([]);
    await b1.$disconnect();

    // Same provider shape, L4 armed (the default): the operation succeeds, and
    // the keys arrived through warm() rather than through the value path.
    const warm = rig();
    const { prisma, base } = makeClient({ keyProvider: warm.provider });
    const row = await loose(prisma)["patient"]!["create"]!({
      data: { email: "ada@example.com", note: "n", age: 36, plainName: "Ada" },
    });
    expect(row["email"]).toBe("ada@example.com");
    expect(warm.unwraps.length).toBeGreaterThan(0);
    expect(warm.state.violations).toBe(0);
    await base.$disconnect();
  });

  it("never unwraps from inside a synchronous core call (docs/09 §8.2 holds)", async () => {
    const r = rig();
    const { prisma, base } = makeClient({ keyProvider: r.provider });
    const created = await loose(prisma)["patient"]!["create"]!({
      data: { email: "grace@example.com", note: "n", age: 45, plainName: "Grace" },
    });
    const read = await loose(prisma)["patient"]!["findMany"]!({
      where: { id: created["id"] as string },
    });
    expect(read[0]!["email"]).toBe("grace@example.com");
    // The whole claim: every unwrap happened between synchronous core calls,
    // never inside one.
    expect(r.state.violations).toBe(0);
    await base.$disconnect();
  });

  it("warms once per cold operation, and not at all once the cache is warm", async () => {
    const r = rig();
    const { prisma, base } = makeClient({ keyProvider: r.provider });
    await loose(prisma)["patient"]!["create"]!({
      data: { email: "ada@example.com", note: "n", age: 36, plainName: "Ada" },
    });
    const afterFirst = r.unwraps.length;
    expect(afterFirst).toBe(2); // the scope's dek and its index key, once each

    await loose(prisma)["patient"]!["create"]!({
      data: { email: "bob@example.com", note: "n", age: 20, plainName: "Bob" },
    });
    // The retry is not on the happy path: a warm cache means no warm at all.
    expect(r.unwraps.length).toBe(afterFirst);
    await base.$disconnect();
  });

  it("warms the index key too, not only the data key (spec §5.2 siblings)", async () => {
    // The index key is a *sibling* of the tenant DEK, not a child of it, so a
    // warm derived from value contexts alone would leave every indexed lookup
    // stalled -- "a slow query rather than a cold cache". The ledger records
    // the index context because `indexContext()` reports it.
    const r = rig();
    const { prisma, base } = makeClient({ keyProvider: r.provider });
    const row = await loose(prisma)["patient"]!["create"]!({
      data: { email: "ada@example.com", note: "n", age: 36, plainName: "Ada" },
    });
    expect(row["id"]).toBeTruthy();
    await base.$disconnect();

    // A second client over the same directory: a cold cache whose *first* core
    // call is a blindIndex on the query operand, not an encrypt.
    const q = rig();
    const { prisma: p2, base: b2 } = makeClient({ keyProvider: q.provider });
    const found = await loose(p2)["patient"]!["findMany"]!({
      where: { email: "ada@example.com" },
    });
    expect(found).toHaveLength(1);
    expect(found[0]!["email"]).toBe("ada@example.com");
    expect(q.state.violations).toBe(0);
    await b2.$disconnect();
  });

  it("warms a tenant-bound column under its own scope", async () => {
    const r = rig();
    const { prisma, base } = makeClient({ keyProvider: r.provider });
    // `await` **inside** the scope, never a lazy promise returned out of it: a
    // Prisma client method dispatches nothing until something calls `.then`,
    // so a synchronous `storage.run` would exit before the query ran.
    const row = await tenantScope("tenant-0001", async () =>
      loose(prisma)["tenantDoc"]!["create"]!({ data: { body: "tenant-scoped body" } }),
    );
    expect(row["body"]).toBe("tenant-scoped body");
    expect(r.state.violations).toBe(0);
    await base.$disconnect();
  });

  it("warms again for the read pass when the cache evicts between the passes", async () => {
    // Warm accounting is per pass, not per operation. The §5.5 cache can evict
    // between the write pass and the read pass -- the write pass's own
    // derivations advance the use counter, and the query engine's round trip
    // runs between the two -- and the warm that saved the write pass says
    // nothing about the read side's misses.
    //
    // The staging is the regression's exact shape: the write-pass miss lands on
    // the operation's LAST context (the value key serves, the index derivation
    // misses), so the warm cycle marks every context the pass built. With one
    // per-operation ledger the read-pass miss then found nothing pending and
    // raised KEY_UNAVAILABLE -- for a row the database had already committed,
    // when one more warm would have served it. A miss on the FIRST context
    // masked the bug, because contexts recorded during the successful retry
    // were never marked warmed.
    let phase = 0; // 0 = cold; 1 = encrypt keys cached; 2 = cached again
    let served = 0;
    const provider: KeyProvider = {
      encryptionKey(ctx: ResolvedContext) {
        if (phase < 1 && served++ >= 1) {
          throw new KeyUnavailableError(KEY_ID, "staged: evicted");
        }
        const index = ctx.purpose.startsWith("index:");
        return { key: new Uint8Array(index ? INDEX_KEY : DEK), keyId: new Uint8Array(KEY_ID) };
      },
      decryptionKeys(_header: EnvelopeHeader) {
        return phase < 2 ? [] : [new Uint8Array(DEK)];
      },
      async warm() {
        phase++;
        await Promise.resolve();
      },
    };
    const { prisma, base } = makeClient({ keyProvider: provider });
    const row = await loose(prisma)["person"]!["create"]!({ data: { legalName: "Ada Lovelace" } });
    expect(row["legalName"]).toBe("Ada Lovelace");
    expect(phase).toBe(2); // one warm per pass that missed, never one per operation
    await base.$disconnect();
  });

  it("gives up rather than looping when warming does not help", async () => {
    // Termination: a warm that returns without populating the cache leaves the
    // ledger with nothing new to warm, so the second attempt's miss is raised.
    // Blocking a query on repeated KMS round trips is the availability failure
    // spec §8.1 warns about, so one unproductive cycle is the limit.
    const r = rig({ warmDoesNothing: true });
    const { prisma, base } = makeClient({ keyProvider: r.provider });
    await expect(
      loose(prisma)["patient"]!["create"]!({
        data: { email: "ada@example.com", note: "n", age: 36, plainName: "Ada" },
      }),
    ).rejects.toThrow(/KEY_UNAVAILABLE|no key is available/);
    expect(r.unwraps).toEqual(["warm-noop"]);
    await base.$disconnect();
  });

  it("is inert when the provider cannot warm", async () => {
    // Nothing to call, so nothing is called: the miss is raised exactly as it
    // is in a sync adapter, and no retry runs.
    const r = rig({ warmable: false });
    const { prisma, base } = makeClient({ keyProvider: r.provider });
    await expect(
      loose(prisma)["patient"]!["create"]!({
        data: { email: "ada@example.com", note: "n", age: 36, plainName: "Ada" },
      }),
    ).rejects.toThrow(/KEY_UNAVAILABLE|no key is available/);
    expect(r.unwraps).toEqual([]);
    await base.$disconnect();
  });
});

describe("the journal: a retried pass starts from a clean tree", () => {
  beforeEach(async () => {
    const { base } = makeClient();
    await clearDb(base);
    await base.$disconnect();
  });

  it("restores exactly, in reverse, so a read-modify-write undoes too", () => {
    // The unit property the visitors rely on. Reverse order is the part worth
    // asserting: `rewrite.ts` reads `AND`, extends it, and writes it back, and
    // restoring those in forward order would leave the *intermediate* value
    // behind rather than the original.
    const j = new Journal();
    const node: Record<string, unknown> = { kept: 1, replaced: "before" };
    j.set(node, "replaced", "after");
    j.set(node, "added", true);
    j.set(node, "added", false);
    j.remove(node, "kept");
    expect(node).toEqual({ replaced: "after", added: false });

    j.rollback();
    expect(node).toEqual({ kept: 1, replaced: "before" });
    expect("added" in node).toBe(false);
    // Idempotent: a second rollback must not undo whatever ran after the first.
    j.set(node, "kept", 2);
    j.rollback();
    j.rollback();
    expect(node).toEqual({ kept: 1, replaced: "before" });
  });

  it("distinguishes an absent key from one set to undefined", () => {
    // Prisma's `undefined` means "do not touch this field", which `write.ts`
    // relies on. A rollback that turned an absent key into an explicit
    // `undefined` would change the meaning of the operation it restores.
    const j = new Journal();
    const node: Record<string, unknown> = { present: undefined };
    j.set(node, "present", 1);
    j.set(node, "absent", 1);
    j.rollback();
    expect("present" in node).toBe(true);
    expect(node["present"]).toBeUndefined();
    expect("absent" in node).toBe(false);
  });

  it("writes each column exactly once when the write pass is retried", async () => {
    // The failure the journal exists to prevent, at the layer it happens: the
    // first attempt encrypts `email`, misses the key deriving its index, and is
    // retried. Without the rollback the retry reads the envelope it just wrote
    // as if it were the caller's value -- double encryption, and here a codec
    // refusal, because a Uint8Array is not a string.
    const s = staged({ serveEncrypts: 1 });
    const { prisma, base } = makeClient({ keyProvider: s.provider });
    const row = await loose(prisma)["patient"]!["create"]!({
      data: { email: "ada@example.com", note: "n", age: 36, plainName: "Ada" },
    });
    expect(s.warms).toBe(1);
    expect(row["email"]).toBe("ada@example.com");
    expect(row["note"]).toBe("n");
    expect(row["age"]).toBe(36);
    await base.$disconnect();

    // And the stored row is a single envelope, readable by an ordinary client.
    const { prisma: p2, base: b2 } = makeClient();
    const again = await loose(p2)["patient"]!["findMany"]!({});
    expect(again).toHaveLength(1);
    expect(again[0]!["email"]).toBe("ada@example.com");
    await b2.$disconnect();
  });

  it("decrypts each column exactly once when the read pass is retried", async () => {
    const { prisma, base } = makeClient();
    await loose(prisma)["patient"]!["create"]!({
      data: { email: "ada@example.com", note: "n", age: 36, plainName: "Ada" },
    });
    await base.$disconnect();

    // Two columns decrypt, the third misses. Without the rollback the retry
    // hands an already-decrypted string back to `fromColumn`, which refuses it
    // as a storage mismatch -- the same class of failure as the write side.
    const s = staged({ serveDecrypts: 2 });
    const { prisma: p2, base: b2 } = makeClient({ keyProvider: s.provider });
    const rows = await loose(p2)["patient"]!["findMany"]!({});
    expect(s.warms).toBe(1);
    expect(rows).toHaveLength(1);
    expect(rows[0]!["email"]).toBe("ada@example.com");
    expect(rows[0]!["note"]).toBe("n");
    expect(rows[0]!["age"]).toBe(36);
    await b2.$disconnect();
  });

  it("does not grow the caller's AND across a retry", async () => {
    // `place()` copies rather than pushing. An in-place `push` is a mutation no
    // journal can undo by restoring a key -- the restored reference is the same
    // array, one element longer -- so a retried rewrite would conjoin the extra
    // predicate twice. Observed on the *inner* side of fieldseal: an extension
    // registered after it sits closer to the engine and sees the args it
    // produced (`tests/prisma-private-api.test.ts` pins that ordering).
    const { prisma: writer, base: wb } = makeClient();
    await loose(writer)["patient"]!["create"]!({
      data: {
        email: "ada@example.com",
        note: "n",
        age: 36,
        nickname: "Ada",
        plainName: "Ada",
      },
    });
    await wb.$disconnect();

    // Three index derivations: `email`'s two operators, then `nickname`'s. The
    // miss lands on the third, after `place` has already extended `AND`.
    const s = staged({ serveEncrypts: 2 });
    const { prisma, base } = makeClient({ keyProvider: s.provider });
    const seen: unknown[] = [];
    const probed = prisma.$extends({
      name: "probe",
      query: {
        $allOperations({ args, query }: { args: unknown; query: (a: unknown) => Promise<unknown> }) {
          seen.push(args);
          return query(args);
        },
      },
    } as never) as unknown as typeof prisma;

    const rows = await loose(probed)["patient"]!["findMany"]!({
      where: {
        email: { equals: "ada@example.com", in: ["ada@example.com"] },
        nickname: "Ada",
        AND: [{ plainName: "Ada" }],
      },
    });
    expect(s.warms).toBe(1);
    expect(rows).toHaveLength(1);
    const where = (seen[0] as { where: Record<string, unknown> }).where;
    // The caller's one conjunct, plus the one `place` moved there. Not three.
    expect(where["AND"]).toHaveLength(2);
    await base.$disconnect();
  });
});
