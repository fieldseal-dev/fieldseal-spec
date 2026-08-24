"""In-memory DEK cache (spec §5.5; docs/09 §8.3).

Eviction on max-age AND max-uses (≤ 2³²) AND capacity (LRU). Evicted material
is overwritten with zeros. Max-age is enforced on every read (`get`, `peek`,
`has`) and swept on every `put`, so expired material does not linger until its
exact key happens to be read again.

Use counting is per cached entry, incremented per `encryption_key` return
(docs/09 §8.3) -- `get`. Decrypt-path candidate reads go through `peek` and do
not count: charging them would advance a version's counter with the tenant's
total decrypt traffic, a per-provider count wearing a per-key-version name,
and would evict old-but-valid versions at a rate unrelated to their actual
use. That bug was fixed in the TypeScript core in PR #55; docs/10 §6 pins the
regression test so this port cannot reintroduce it.

Zeroization honesty (docs/10 §5): entries are held as `bytearray` and
overwritten with zeros on eviction. CPython cannot erase immutable `bytes`;
copies taken inside dependencies or by the allocator are outside our control,
and there is no `mlock` (docs/09 §8.3 deviation, documented). This narrows the
window exposed to memory dumps, core files and swap; it does not close it.
TTL is a security parameter (spec §5.5), not a tuning knob.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Literal

from .errors import ConfigurationError

EvictionCause = Literal["max-age", "max-uses", "capacity", "explicit", "clear"]

MAX_USES_CEILING = 2**32  # spec §5.5


@dataclass(frozen=True)
class CachePolicy:
    """The §5.5 thresholds. All three are required -- there is no default that
    could silently weaken either security threshold."""

    max_age: timedelta
    max_uses: int
    capacity: int

    def __post_init__(self) -> None:
        if not isinstance(self.max_age, timedelta) \
                or self.max_age.total_seconds() <= 0:
            raise ConfigurationError(
                "cache.max_age must be a positive timedelta (spec §5.5)")
        if isinstance(self.max_uses, bool) or not isinstance(self.max_uses, int) \
                or not 1 <= self.max_uses <= MAX_USES_CEILING:
            raise ConfigurationError(
                f"cache.max_uses must be an integer in 1..2^32 (spec §5.5); "
                f"got {self.max_uses!r}")
        if isinstance(self.capacity, bool) or not isinstance(self.capacity, int) \
                or self.capacity < 1:
            raise ConfigurationError(
                "cache.capacity must be an integer >= 1")


@dataclass
class CacheMetrics:
    hits: int = 0
    misses: int = 0
    evictions: dict[str, int] = field(
        default_factory=lambda: {"max-age": 0, "max-uses": 0, "capacity": 0,
                                 "explicit": 0, "clear": 0})


@dataclass(slots=True)
class _Entry:
    material: bytearray
    inserted_at: float
    uses: int


class DekCache:
    """Thread-safe DEK cache: one lock around metadata (docs/10 §5). The value
    path never blocks on another entry's refresh -- refresh lives in the
    provider's `warm`, not here."""

    def __init__(
        self,
        policy: CachePolicy,
        *,
        now: Callable[[], float] | None = None,
        on_evict: Callable[[str, EvictionCause], None] | None = None,
    ) -> None:
        # CachePolicy validates itself in __post_init__; construction of an
        # invalid one raises before we get here.
        self.policy = policy
        self.metrics = CacheMetrics()
        # Plain dict: insertion-ordered; re-inserting on access makes it an LRU.
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()
        self._now: Callable[[], float] = now if now is not None else time.monotonic
        self._on_evict = on_evict

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def put(self, key: str, material: bytes | bytearray) -> None:
        """Stores a private copy of `material`; the caller's buffer is never
        aliased."""
        with self._lock:
            # TTL is a security parameter: expired material must not sit in
            # memory until someone happens to `get` its exact key, and it must
            # not consume capacity evictions owed to live entries. Sweeping
            # here keeps eviction off the value path (put runs from warm()).
            self._sweep_expired()
            existing = self._entries.get(key)
            if existing is not None:
                self._drop(key, existing, "explicit", count=False)
            while len(self._entries) >= self.policy.capacity:
                oldest = next(iter(self._entries))
                self._drop(oldest, self._entries[oldest], "capacity",
                           count=True)
            self._entries[key] = _Entry(material=bytearray(material),
                                        inserted_at=self._now(), uses=0)

    def get(self, key: str) -> bytes | None:
        """Returns a copy of the cached material, or None. Counts one use; an
        entry reaching max_uses is returned this last time and then evicted,
        so the threshold is an exact count of returns."""
        with self._lock:
            e = self._entries.get(key)
            if e is None:
                self.metrics.misses += 1
                return None
            if self._expired(e):
                self._drop(key, e, "max-age", count=True)
                self.metrics.misses += 1
                return None
            self.metrics.hits += 1
            out = bytes(e.material)
            e.uses += 1
            if e.uses >= self.policy.max_uses:
                self._drop(key, e, "max-uses", count=True)
            else:
                # LRU touch.
                del self._entries[key]
                self._entries[key] = e
            return out

    def peek(self, key: str) -> bytes | None:
        """Returns a copy without counting a §5.5 use. docs/09 §8.3: use
        counting increments per `encryption_key` return; a decrypt-path
        candidate read is not a use of the entry. Max-age is still enforced --
        an expired key must never be served, counted or not -- and there is no
        LRU touch, so peeks do not keep an otherwise-idle entry alive past
        capacity pressure."""
        with self._lock:
            e = self._entries.get(key)
            if e is None:
                self.metrics.misses += 1
                return None
            if self._expired(e):
                self._drop(key, e, "max-age", count=True)
                self.metrics.misses += 1
                return None
            self.metrics.hits += 1
            return bytes(e.material)

    def has(self, key: str) -> bool:
        with self._lock:
            e = self._entries.get(key)
            if e is None:
                return False
            if self._expired(e):
                # An expired entry is not "had"; saying otherwise would let a
                # caller act on key material the TTL already retired.
                self._drop(key, e, "max-age", count=True)
                return False
            return True

    def evict(self, key: str) -> None:
        with self._lock:
            e = self._entries.get(key)
            if e is not None:
                self._drop(key, e, "explicit", count=True)

    def clear(self) -> None:
        """Evicts and zeroizes everything (e.g. before a fork, docs/09 §10)."""
        with self._lock:
            for key, e in list(self._entries.items()):
                self._drop(key, e, "clear", count=True)

    # -- internals ---------------------------------------------------------

    def _expired(self, e: _Entry) -> bool:
        return self._now() - e.inserted_at >= self.policy.max_age.total_seconds()

    def _sweep_expired(self) -> None:
        # Entries are in LRU order (get re-inserts), not insertion-time order,
        # so a full walk is required; n is bounded by policy.capacity.
        now = self._now()
        for key, e in list(self._entries.items()):
            if now - e.inserted_at >= self.policy.max_age.total_seconds():
                self._drop(key, e, "max-age", count=True)

    def _drop(self, key: str, e: _Entry, cause: EvictionCause, *,
              count: bool) -> None:
        # Best-effort zeroization (docs/10 §5): overwrite the visible
        # allocation; nothing more is promiseable in CPython.
        e.material[:] = bytes(len(e.material))
        del self._entries[key]
        if count:
            self.metrics.evictions[cause] += 1
            if self._on_evict is not None:
                self._on_evict(key, cause)
