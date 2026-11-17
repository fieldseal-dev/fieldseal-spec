/**
 * The index role's missing use budget, at the cache (docs/09 §8.3; #225).
 *
 * docs/09 §8.3: use counting is per cached entry, incremented per **DEK-role**
 * `encryption_key` return, and **the index role has no use budget** — an index
 * key is never AEAD key material and draws no nonce, so the SP 800-38D ceiling
 * spec §5.5 sets `maxUses` for does not reach it. Max-age and the capacity LRU
 * still apply to both roles.
 *
 * This file is cited by the report's `pinned_decisions.index-role-use-budget`
 * and run by `tests/harness/run.ts` (docs/14 §4: a test-backed pinned
 * decision). If it is missing or red, the report claims no level and
 * `npm run vectors` exits 1. Renaming the `describe` or the `it` means changing
 * `PINNED_TESTS` in the harness in the same commit.
 *
 * `providers.test.ts`' "index-role returns do not deplete max-uses" proves the
 * other half end to end: that the provider really puts its index-role slots
 * uncounted. This one proves what the cache does with such a slot, with
 * nothing between the assertion and `DekCache`.
 */

import { describe, expect, it } from "vitest";
import { DekCache } from "../src/cache.ts";

const DEK = Uint8Array.from({ length: 32 }, (_, i) => i);
const INDEX_KEY = Uint8Array.from({ length: 32 }, (_, i) => 32 + i);
// Slot keys shaped like the provider's (scope, tenant, version, role); the
// cache treats them as opaque strings, the role is carried by `counted`.
const INDEX_SLOT = "scope|tenant|v1|index";
const DEK_SLOT = "scope|tenant|v1|dek";

const same = (a: Uint8Array | undefined, b: Uint8Array): boolean => a !== undefined && Buffer.from(a).equals(Buffer.from(b));

describe("index-role use budget (docs/09 §8.3, #225)", () => {
  // Both halves are asserted in one test, so it turns red whichever way
  // `counted` is inverted: the read check in `DekCache.get`, or the default
  // in `DekCache.put`.
  it("index-role slot lookups never spend maxUses; a DEK slot in the same cache still does", () => {
    // maxUses 1, the lowest §5.5 allows: a single counted lookup is the whole
    // budget, so one spent index lookup would already evict. The clock is
    // fixed; maxAgeMs is never reached here.
    const cache = new DekCache({ maxAgeMs: 3_600_000, maxUses: 1, capacity: 4 }, { now: () => 1000 });

    cache.put(INDEX_SLOT, INDEX_KEY, { counted: false });
    for (let i = 0; i < 10; i++) {
      expect(same(cache.get(INDEX_SLOT), INDEX_KEY), `index lookup ${i}`).toBe(true);
      expect(cache.has(INDEX_SLOT), `index slot gone after lookup ${i}`).toBe(true);
    }
    expect(cache.metrics.evictions["max-uses"]).toBe(0);

    // The control: a DEK-role slot, put with the default, is spent by its one
    // allowed return and evicted on max-uses. Without it, a cache that counted
    // nothing at all would pass the half above.
    cache.put(DEK_SLOT, DEK);
    expect(same(cache.get(DEK_SLOT), DEK)).toBe(true);
    expect(cache.get(DEK_SLOT)).toBeUndefined();
    expect(cache.has(DEK_SLOT)).toBe(false);
    expect(cache.metrics.evictions["max-uses"]).toBe(1);

    // The index slot is untouched by the DEK's eviction and still served.
    expect(same(cache.get(INDEX_SLOT), INDEX_KEY)).toBe(true);
    expect(cache.metrics.evictions["max-uses"]).toBe(1);
  });
});
