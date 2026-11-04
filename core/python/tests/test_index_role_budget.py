"""The index role's missing use budget, at the cache (docs/09 §8.3; #225).

docs/09 §8.3: use counting is per cached entry, incremented per **DEK-role**
`encryption_key` return, and **the index role has no use budget** -- an index
key is never AEAD key material and draws no nonce, so the SP 800-38D ceiling
spec §5.5 sets `max_uses` for does not reach it. `max_age` and the capacity
LRU still apply to both roles.

This file is cited by the report's `pinned_decisions.index-role-use-budget`
and run by `tests/run_vectors.py` (docs/14 §4: a test-backed pinned decision).
If it is missing or red, the report claims no level and exits 1. Renaming the
test means changing `PINNED_TESTS` in `run_vectors.py` in the same commit.

`test_providers.py::TestEnvelopeKeyProvider::test_index_key_returns_do_not_
deplete_max_uses` proves the other half end to end: that the provider really
puts its index-role slots uncounted. This one proves what the cache does with
such a slot, with nothing between the assertion and `DekCache`.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from fieldseal.cache import CachePolicy, DekCache  # noqa: E402

DEK = bytes(range(32))
INDEX_KEY = bytes(range(32, 64))
# Slot keys shaped like the provider's (scope, tenant, version, role); the
# cache treats them as opaque strings, the role is carried by `counted`.
INDEX_SLOT = "scope|tenant|v1|index"
DEK_SLOT = "scope|tenant|v1|dek"


class TestIndexRoleUseBudget:
    """docs/09 §8.3 (#225): an index-role slot is put with `counted=False`
    and no lookup of it spends `max_uses`; a DEK-role slot in the same cache
    still does. Both halves are asserted, so the test turns red whichever
    way `counted` is inverted -- the read check in `DekCache.get`, or the
    default in `DekCache.put`."""

    def test_index_role_slot_never_spends_max_uses(self):
        # max_uses=1, the lowest §5.5 allows: a single counted lookup is the
        # whole budget, so one spent index lookup would already evict. The
        # clock is fixed at an exactly representable value (#227); max_age
        # is never reached here.
        cache = DekCache(
            CachePolicy(max_age=timedelta(hours=1), max_uses=1, capacity=4),
            now=lambda: 1000.0)

        cache.put(INDEX_SLOT, INDEX_KEY, counted=False)
        for i in range(10):
            assert cache.get(INDEX_SLOT) == INDEX_KEY, f"index lookup {i}"
            assert cache.has(INDEX_SLOT), f"index slot gone after lookup {i}"
        assert cache.metrics.evictions["max-uses"] == 0

        # The control: a DEK-role slot, put with the default, is spent by its
        # one allowed return and evicted on max-uses. Without it, a cache
        # that counted nothing at all would pass the half above.
        cache.put(DEK_SLOT, DEK)
        assert cache.get(DEK_SLOT) == DEK
        assert cache.get(DEK_SLOT) is None
        assert not cache.has(DEK_SLOT)
        assert cache.metrics.evictions["max-uses"] == 1

        # The index slot is untouched by the DEK's eviction and still served.
        assert cache.get(INDEX_SLOT) == INDEX_KEY
        assert cache.metrics.evictions["max-uses"] == 1
