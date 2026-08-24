"""Providers and the DEK cache (spec §5.5, §8; docs/09 §8; docs/10 §6 item 2).

The use-counting test below is the one docs/10 §6 pinned in writing *before*
`cache.py` and `EnvelopeKeyProvider` existed (commit e0d7d63), so that the bug
fixed in TypeScript PR #55 -- decrypt-path candidate reads depleting §5.5
max-uses -- is not re-introduced when the Python modules land. Everything else
here mirrors `core/typescript/tests/providers.test.ts` contract for contract.
Out of scope for the vector suite by design (docs/08 §8).
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Callable

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from fieldseal import FieldContext, Fieldseal  # noqa: E402
from fieldseal.cache import CachePolicy, DekCache  # noqa: E402
from fieldseal.envelope import EnvelopeHeader  # noqa: E402
from fieldseal.errors import ConfigurationError, KeyUnavailable  # noqa: E402
from fieldseal.keyprovider import (  # noqa: E402
    EnvelopeKeyProvider,
    InMemoryKeyDirectory,
    StaticKeyProvider,
    WrappedKeySet,
    WrappedKeyVersion,
)

KEY_ID = bytes(range(16))
DEK = bytes(range(32))
INDEX_KEY = bytes(range(32, 64))
PT = b"123456789"
SCOPE = b"tenant-0001"
CTX = FieldContext(table_uuid=bytes(16), column_uuid=bytes(range(16)),
                   purpose="encrypt", tenant_id=SCOPE)

SECONDS = 1.0  # one clock tick; policies below use whole-second max_ages


def _client(provider: object, **kw: object) -> Fieldseal:
    return Fieldseal(key_provider=provider,  # type: ignore[arg-type]
                     allowed_suites={0xFF01}, write_suite=0xFF01,
                     arm_provisional_suites=True, **kw)


def _run(coro: Callable[..., object]) -> object:
    return asyncio.run(coro)  # type: ignore[arg-type]


# -- DekCache (spec §5.5) ------------------------------------------------------

class TestDekCache:
    def test_validates_thresholds(self):
        def p(max_age=timedelta(seconds=1), max_uses=1, capacity=1):
            return CachePolicy(max_age=max_age, max_uses=max_uses,
                               capacity=capacity)

        with pytest.raises(ConfigurationError, match="max_age"):
            p(max_age=timedelta(0))
        with pytest.raises(ConfigurationError, match="max_age"):
            p(max_age=-timedelta(seconds=1))
        with pytest.raises(ConfigurationError, match="max_age"):
            p(max_age=100)
        with pytest.raises(ConfigurationError, match="max_uses"):
            p(max_uses=0)
        with pytest.raises(ConfigurationError, match="max_uses"):
            p(max_uses=2**32 + 1)
        assert p(max_uses=2**32).max_uses == 2**32  # the ceiling is allowed
        with pytest.raises(ConfigurationError, match="capacity"):
            p(capacity=0)

    def test_evicts_on_max_age_and_holds_its_own_copy(self):
        now = [1000.0]
        evicted = []
        c = DekCache(CachePolicy(max_age=timedelta(seconds=100),
                                 max_uses=1000, capacity=10),
                     now=lambda: now[0],
                     on_evict=lambda k, cause: evicted.append(f"{k}:{cause}"))
        material = bytearray([9] * 32)
        c.put("k", material)
        material[0] = 0xFF  # the caller mutates its own copy afterwards
        assert c.get("k") == bytes([9] * 32)  # the cache held its own
        now[0] = 1099.0
        assert c.get("k") is not None
        now[0] = 1100.0
        assert c.get("k") is None
        assert evicted == ["k:max-age"]

    def test_sweeps_expired_entries_on_put(self):
        """Expired material must not sit in memory until its exact key is read
        again (TTL is a security parameter, spec §5.5)."""
        now = [0.0]
        evicted = []
        c = DekCache(CachePolicy(max_age=timedelta(seconds=100),
                                 max_uses=1000, capacity=10),
                     now=lambda: now[0],
                     on_evict=lambda k, cause: evicted.append(f"{k}:{cause}"))
        c.put("a", bytes([1] * 32))
        c.put("b", bytes([2] * 32))
        now[0] = 100.0  # both expired; neither is ever get()
        c.put("c", bytes([3] * 32))
        assert c.size == 1
        assert sorted(evicted) == ["a:max-age", "b:max-age"]

    def test_has_does_not_claim_an_expired_entry(self):
        now = [0.0]
        c = DekCache(CachePolicy(max_age=timedelta(seconds=100),
                                 max_uses=1000, capacity=10),
                     now=lambda: now[0])
        c.put("k", bytes(32))
        assert c.has("k")
        now[0] = 100.0
        assert not c.has("k")
        assert c.size == 0
        assert c.metrics.evictions["max-age"] == 1

    def test_peek_returns_copies_and_never_counts_a_use(self):
        now = [0.0]
        c = DekCache(CachePolicy(max_age=timedelta(seconds=100),
                                 max_uses=2, capacity=10),
                     now=lambda: now[0])
        c.put("k", bytes([7] * 32))
        for _ in range(50):
            assert c.peek("k") == bytes([7] * 32)  # never depletes max_uses
        assert c.get("k") is not None   # use 1
        assert c.get("k") is not None   # use 2 → evicted on return
        assert c.peek("k") is None
        c.put("k2", bytes(32))
        now[0] = 100.0
        assert c.peek("k2") is None     # peek still enforces max-age
        assert c.metrics.evictions["max-age"] == 1

    def test_evicts_on_max_uses_exactly(self):
        c = DekCache(CachePolicy(max_age=timedelta(days=36500),
                                 max_uses=3, capacity=10))
        c.put("k", bytes([1] * 32))
        assert c.get("k") == bytes([1] * 32)    # use 1
        assert c.get("k") == bytes([1] * 32)    # use 2
        assert c.get("k") is not None           # use 3 → evicted on return
        assert c.get("k") is None
        assert c.metrics.evictions["max-uses"] == 1

    def test_evicts_least_recently_used_beyond_capacity(self):
        c = DekCache(CachePolicy(max_age=timedelta(days=36500),
                                 max_uses=1_000_000, capacity=2))
        c.put("a", bytes(32))
        c.put("b", bytes(32))
        c.get("a")  # a is now most recent
        c.put("c", bytes(32))
        assert c.has("a")
        assert not c.has("b")
        assert c.has("c")
        assert c.metrics.evictions["capacity"] == 1

    def test_clear_zeroizes_everything(self):
        c = DekCache(CachePolicy(max_age=timedelta(days=36500),
                                 max_uses=1_000_000, capacity=5))
        c.put("a", bytes([1] * 32))
        c.clear()
        assert c.size == 0
        assert c.metrics.evictions["clear"] == 1


# -- EnvelopeKeyProvider (docs/09 §8.2) ----------------------------------------

class CountingXorWrapper:
    """A toy wrapper: "unwrapping" is XOR with 0x55, every call counted."""

    def __init__(self) -> None:
        self.calls = 0

    async def unwrap(self, wrapped: bytes, scope: bytes) -> bytes:
        self.calls += 1
        return bytes(b ^ 0x55 for b in wrapped)


def wrap(k: bytes) -> bytes:
    return bytes(b ^ 0x55 for b in k)


DIRECTORY = InMemoryKeyDirectory([
    WrappedKeySet(
        scope=SCOPE, active_version=1,
        versions=[WrappedKeyVersion(version=1, key_id=KEY_ID,
                                    wrapped_dek=wrap(DEK),
                                    wrapped_index_key=wrap(INDEX_KEY))]),
])


def _provider(max_uses: int = 1000) -> tuple[EnvelopeKeyProvider,
                                             CountingXorWrapper]:
    wrapper = CountingXorWrapper()
    provider = EnvelopeKeyProvider(
        wrapper=wrapper, directory=DIRECTORY,
        cache=CachePolicy(max_age=timedelta(seconds=60 * SECONDS),
                          max_uses=max_uses, capacity=16))
    return provider, wrapper


class TestEnvelopeKeyProvider:
    def test_value_path_is_cache_only(self):
        """KEY_UNAVAILABLE before warm(), works after, and never unwraps on
        the value path (spec §11.1; docs/09 §8.2)."""
        p, w = _provider()
        c = _client(p)
        w.calls = 0
        with pytest.raises(KeyUnavailable):
            c.encrypt(PT, CTX)
        assert w.calls == 0
        _run(c.warm([CTX, CTX]))  # duplicate context: single-flight dedupes
        assert w.calls == 2       # dek + index key, once each
        env = c.encrypt(PT, CTX)
        assert c.decrypt(env, CTX) == PT
        assert w.calls == 2
        assert p.cache.metrics.hits > 0

    def test_unknown_scope_is_key_unavailable_and_warm_reports_it(self):
        p, _ = _provider()
        c = _client(p)
        other = replace(CTX, tenant_id=b"nobody")
        with pytest.raises(KeyUnavailable):
            c.encrypt(PT, other)
        with pytest.raises(KeyUnavailable, match="scope"):
            _run(c.warm([other]))

    def test_failed_unwrap_never_poisons_the_cache(self):
        class Failing:
            async def unwrap(self, wrapped: bytes, scope: bytes) -> bytes:
                raise RuntimeError("KMS unreachable")

        p = EnvelopeKeyProvider(wrapper=Failing(), directory=DIRECTORY,
                                cache=CachePolicy(max_age=timedelta(minutes=1),
                                                  max_uses=1000, capacity=16))
        c = _client(p)
        with pytest.raises(RuntimeError, match="KMS"):
            _run(c.warm([CTX]))
        assert p.cache.size == 0
        with pytest.raises(KeyUnavailable):
            c.encrypt(PT, CTX)

    def test_max_uses_eviction_takes_effect_on_the_value_path(self):
        p, _ = _provider(max_uses=2)
        c = _client(p)
        _run(c.warm([CTX]))
        c.encrypt(PT, CTX)
        c.encrypt(PT, CTX)
        with pytest.raises(KeyUnavailable):
            c.encrypt(PT, CTX)

    def test_decrypt_candidate_reads_do_not_deplete_max_uses(self):
        """THE PINNED TEST (docs/10 §6 item 2, written before this module
        existed): use counting is per `encryption_key` return (docs/09 §8.3);
        `decryption_keys` candidate reads go through `peek` and must not touch
        the counter. Mirrors core/typescript providers.test.ts, the case fixed
        by PR #55."""
        p, _ = _provider(max_uses=3)
        c = _client(p)
        _run(c.warm([CTX]))
        env = c.encrypt(PT, CTX)                    # use 1
        for _ in range(20):
            assert c.decrypt(env, CTX) == PT        # candidate reads: no use
        c.encrypt(PT, CTX)                          # use 2
        c.encrypt(PT, CTX)                          # use 3 → evicted on return
        with pytest.raises(KeyUnavailable):
            c.encrypt(PT, CTX)

    def test_decryption_keys_for_an_unknown_key_id_is_empty(self):
        p, _ = _provider()
        _run(p.warm([CTX]))
        header = EnvelopeHeader(fmt_ver=1, suite_id=0xFF01,
                                key_id=bytes(16), msg_seed=bytes(32))
        assert list(p.decryption_keys(header)) == []


# -- construction-time refusals --------------------------------------------------

def test_static_provider_still_enforces_the_sibling_rule():
    with pytest.raises(ConfigurationError):
        StaticKeyProvider(KEY_ID, DEK, DEK)
