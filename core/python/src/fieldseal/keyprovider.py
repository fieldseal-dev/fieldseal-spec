"""Key providers: spec §8, docs/09 §8.

Two shipped providers:

  StaticKeyProvider    one key in memory; test/development only
  EnvelopeKeyProvider  KMS-wrapped DEKs; unwrap happens ONLY in warm();
                       the value path is cache-only

(docs/10 §3 lists a third, DerivedKeyProvider; it is not yet ported.)

The interface is spec §8's, by name: `encryption_key(ctx)` for a write and
`decryption_keys(header)` for a read. Purpose routing matters in the first: an
index purpose MUST be served the tenant index key and never the DEK (spec §8).
The index key material is a sibling of the DEK under the KEK, not derived from
it (spec §5.2).

`decryption_keys` returns *every* currently-valid version the header could
have been written under, in preference order (spec §8, §5.6). The core tries
each candidate's commitment in turn (docs/09 §3.2 step 6); an empty list is
`KEY_UNAVAILABLE`. A provider that can read the version out of `key_id` should
put that version first -- the core does not reorder.

The value-path methods are synchronous and MUST NOT perform network I/O
(spec §11.1). Only `warm` may.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from .cache import CachePolicy, DekCache
from .context import FieldContext
from .envelope import EnvelopeHeader
from .errors import ConfigurationError, KeyUnavailable

KEY_ID_LEN = 16  # spec §3.1


def _scope_of(ctx: FieldContext) -> bytes:
    """The DEK scope (spec §5.2): the tenant id, or the empty scope for
    deployments without tenancy."""
    return ctx.tenant_id if ctx.tenant_id is not None else b""


class KeyProvider(Protocol):
    def encryption_key(self, ctx: FieldContext) -> tuple[bytes, bytes]:
        """Returns (key_material, key_id) for a write. For purpose "encrypt"
        the material is the tenant DEK; for "index:<id>" it is the tenant
        INDEX key -- never the DEK (spec §8)."""

    def decryption_keys(self, header: EnvelopeHeader) -> Sequence[bytes]:
        """Candidate DEKs for the envelope `header` names, preference-ordered,
        covering every currently-valid version. Empty if `key_id` is not
        resolvable (spec §9 `KEY_UNAVAILABLE`). MUST NOT perform network I/O
        (spec §11.1): this runs in the value path."""


class StaticKeyProvider:
    """Test-only provider holding one DEK and one index key in memory.

    Not for production: it performs no KMS call, no caching, no rotation, and
    holds key material for the process lifetime. Its one "currently-valid
    version" is the key it was built with, so `decryption_keys` returns that
    key for its own `key_id` and nothing for any other.
    """

    def __init__(self, key_id: bytes, tenant_dek: bytes,
                 tenant_index_key: bytes) -> None:
        if len(key_id) != KEY_ID_LEN:
            raise ConfigurationError(
                f"key_id is {KEY_ID_LEN} bytes (spec §3.1)")
        if tenant_dek == tenant_index_key:
            raise ConfigurationError(
                "the tenant index key must not equal the DEK (spec §5.2)")
        self._key_id = bytes(key_id)
        self._dek = bytes(tenant_dek)
        self._index_key = bytes(tenant_index_key)

    def encryption_key(self, ctx: FieldContext) -> tuple[bytes, bytes]:
        if ctx.purpose == "encrypt":
            return self._dek, self._key_id
        if ctx.purpose.startswith("index:"):
            return self._index_key, self._key_id
        raise ConfigurationError(  # pragma: no cover - FieldContext forbids it
            f"purpose {ctx.purpose!r} is outside the §6.1 grammar")

    def decryption_keys(self, header: EnvelopeHeader) -> Sequence[bytes]:
        return [self._dek] if header.key_id == self._key_id else []


# ---------------------------------------------------------------------------
# EnvelopeKeyProvider

class Wrapper(Protocol):
    """The KMS integration seam (docs/09 §8.2): per-language, pluggable,
    optional dependency. docs/09 names the seam `wrap(dek) / unwrap(blob)`;
    `wrap` is deferred -- nothing in the Phase 1 core calls it (backfill
    tooling will). `unwrap` runs only inside `warm` -- never on the value
    path."""

    async def unwrap(self, wrapped: bytes, scope: bytes) -> bytes:
        """Unwraps a wrapped DEK or index key. MUST be async so that warm can
        await it without blocking an event loop."""


@dataclass(frozen=True)
class WrappedKeyVersion:
    """One wrapped (scope, version): the directory's record of what the KMS
    holds. `wrapped_index_key` is optional where no blind index exists."""

    version: int
    key_id: bytes
    wrapped_dek: bytes
    wrapped_index_key: bytes | None = None


@dataclass(frozen=True)
class WrappedKeySet:
    scope: bytes
    versions: tuple[WrappedKeyVersion, ...]
    active_version: int


class KeyDirectory(Protocol):
    """Where the deployment keeps its wrapped-key metadata. Lookups are
    synchronous and local -- this never talks to the KMS itself."""

    def by_scope(self, scope: bytes) -> WrappedKeySet | None: ...

    def by_key_id(self, key_id: bytes) -> tuple[bytes, int] | None:
        """(scope, version) named by an envelope header's key_id."""


class InMemoryKeyDirectory:
    """A KeyDirectory over in-process records; sufficient for tests and small
    deployments. Construction validates what docs/09 §8 requires and refuses
    anything else at startup rather than mid-request."""

    def __init__(self, sets: Iterable[WrappedKeySet]) -> None:
        self._by_scope: dict[bytes, WrappedKeySet] = {}
        self._by_key_id: dict[bytes, tuple[bytes, int]] = {}
        for s in sets:
            if not any(v.version == s.active_version
                       for v in s.versions):
                raise ConfigurationError(
                    "InMemoryKeyDirectory: active_version must be one of "
                    "the key set's versions (spec §5.6)")
            self._by_scope[s.scope] = s
            for v in s.versions:
                if len(v.key_id) != KEY_ID_LEN:
                    raise ConfigurationError(
                        "InMemoryKeyDirectory: key_id must be "
                        f"{KEY_ID_LEN} bytes")
                if v.key_id in self._by_key_id:
                    raise ConfigurationError(
                        "InMemoryKeyDirectory: duplicate key_id "
                        f"{v.key_id.hex()}")
                self._by_key_id[v.key_id] = (s.scope, v.version)

    def by_scope(self, scope: bytes) -> WrappedKeySet | None:
        return self._by_scope.get(scope)

    def by_key_id(self, key_id: bytes) -> tuple[bytes, int] | None:
        return self._by_key_id.get(key_id)


_DEGRADATION_MODES = ("fail-closed", "serve-cached")


def _cache_key(scope: bytes, version: int, role: str) -> str:
    return f"{scope.hex()}/{version}/{role}"


class EnvelopeKeyProvider:
    """The production path: KMS-wrapped DEKs, unwrapped only in `warm()`,
    served from the §5.5 cache on the value path.

    On a cache miss the behavior is the deployment's §8.1 degradation mode --
    but on this path both modes behave identically (docs/09 §8.2):
    `serve-cached` means *only* "what the cache can decrypt", so either way a
    miss is `KEY_UNAVAILABLE`. The value path NEVER blocks on the network.
    """

    def __init__(
        self,
        *,
        wrapper: Wrapper,
        directory: KeyDirectory,
        cache: CachePolicy,
        degradation: str = "fail-closed",
    ) -> None:
        if not callable(getattr(wrapper, "unwrap", None)):
            raise ConfigurationError(
                "EnvelopeKeyProvider: wrapper.unwrap is required")
        if not callable(getattr(directory, "by_scope", None)):
            raise ConfigurationError("EnvelopeKeyProvider: directory is required")
        if degradation not in _DEGRADATION_MODES:
            raise ConfigurationError(
                f"degradation must be one of {_DEGRADATION_MODES} (spec §8.1)")
        self._cache = DekCache(cache)
        self._degradation = degradation
        self._wrapper = wrapper
        self._directory = directory
        # Single-flight per scope, per event loop: concurrent warms share one
        # task instead of stampeding the KMS (docs/09 §8.3). The value path
        # never touches this.
        self._inflight: dict[str, asyncio.Task[None]] = {}

    # Read-only: rebinding either mid-flight would quietly fork the security
    # policy the provider was constructed under (PR #57 review, item 6).

    @property
    def cache(self) -> DekCache:
        return self._cache

    @property
    def degradation(self) -> str:
        return self._degradation

    # -- spec §8 interface ---------------------------------------------------

    def encryption_key(self, ctx: FieldContext) -> tuple[bytes, bytes]:
        scope = _scope_of(ctx)
        s = self._directory.by_scope(scope)
        if s is None:
            raise KeyUnavailable(
                "no key set is registered for this tenant scope")
        active = next((v for v in s.versions if v.version == s.active_version),
                      None)
        if active is None:
            # A directory that hands back a set without its declared active
            # version is malformed; the typed-errors contract (docs/09 §9)
            # forbids letting an AttributeError escape.
            raise KeyUnavailable(
                "the key set registered for this scope declares no active "
                "version")
        role = "index" if ctx.purpose != "encrypt" else "dek"
        if role == "index" and active.wrapped_index_key is None:
            # Not a cache miss: `_unwrap_scope` never fills this slot, so no
            # number of warm() calls could satisfy it. Prescribing "call
            # warm() first" here would be a remedy that cannot work (cf. the
            # TS StaticKeyProvider's honest message).
            raise KeyUnavailable(
                f"key_id {active.key_id.hex()}: active version "
                f"{active.version} has no wrapped index key registered for "
                "this scope; warm() cannot provide one")
        key = self.cache.get(_cache_key(scope, active.version, role))
        if key is None:
            # docs/09 §9: messages carry the key_id (public envelope
            # content).
            raise KeyUnavailable(
                f"{role} key for version {active.version} (key_id "
                f"{active.key_id.hex()}) is not in the cache (call warm() "
                "first; the value path never unwraps)")
        return key, active.key_id

    def decryption_keys(self, header: EnvelopeHeader) -> Sequence[bytes]:
        hit = self._directory.by_key_id(header.key_id)
        if hit is None:
            return []
        scope, named = hit
        s = self._directory.by_scope(scope)
        if s is None:
            return []
        # The version the header names first, then active, then the rest --
        # all from cache; what is not cached is simply not a candidate.
        #
        # `peek`, not `get`: docs/09 §8.3 counts a §5.5 use per
        # `encryption_key` return. Charging every offered candidate would
        # advance every version's counter with the scope's total decrypt
        # traffic -- a per-provider count wearing a per-key-version name --
        # and evict old-but-valid versions at a rate unrelated to their
        # actual use. This is the bug PR #55 fixed; docs/10 §6 pins the test.
        order = [named, s.active_version]
        order += [v.version for v in s.versions]
        seen: dict[int, None] = {}
        for v in order:
            seen.setdefault(v, None)
        out: list[bytes] = []
        for v in seen:
            k = self.cache.peek(_cache_key(scope, v, "dek"))
            if k is not None:
                out.append(k)
        return out

    # -- warm (docs/09 §3.6) --------------------------------------------------

    async def warm(self, contexts: Iterable[FieldContext]) -> None:
        """Unwraps every version for every scope in `contexts` and loads the
        cache. Failures are reported (the first raised after all scopes
        settle), never cached."""
        scopes: dict[bytes, None] = {}
        for ctx in contexts:
            scopes.setdefault(_scope_of(ctx), None)
        results = await asyncio.gather(
            *(self._warm_scope(s) for s in scopes),
            return_exceptions=True)
        for r in results:
            if isinstance(r, BaseException):
                raise r

    async def _warm_scope(self, scope: bytes) -> None:
        # Cancellation safety (PR #57 review, defect 1): awaiting a task
        # directly hands the awaiter's cancellation TO the task --
        # Task.cancel cancels the future the task is blocked on -- so an
        # unshielded await here would kill the shared unwrap out from under
        # every other awaiter, and the next warm() would hit the KMS with a
        # fresh unwrap (docs/09 §8.3). Both joins therefore go through
        # asyncio.shield, and cleanup is attached to the task rather than to
        # any awaiter's try/finally, since with shields in place no
        # awaiter's stack frame is guaranteed to survive to run it. The TS
        # core has neither hazard: promises are not cancellable.
        key = scope.hex()
        existing = self._inflight.get(key)
        if existing is not None:
            await asyncio.shield(existing)
            return
        task = asyncio.ensure_future(self._unwrap_scope(scope))
        self._inflight[key] = task

        def _cleanup(t: asyncio.Future[None], k: str = key) -> None:
            # The identity guard covers the callback firing after a newer
            # task has taken the slot.
            if self._inflight.get(k) is t:
                del self._inflight[k]
            if not t.cancelled():
                # An abandoned failure must not surface as "exception was
                # never retrieved" noise; any surviving awaiter re-raises
                # via its own `await`.
                t.exception()

        task.add_done_callback(_cleanup)
        await asyncio.shield(task)

    async def _unwrap_scope(self, scope: bytes) -> None:
        s = self._directory.by_scope(scope)
        if s is None:
            raise KeyUnavailable(
                "no key set is registered for this tenant scope")
        for v in s.versions:
            dek = await self._wrapper.unwrap(v.wrapped_dek, scope)
            self.cache.put(_cache_key(scope, v.version, "dek"), dek)
            if v.wrapped_index_key is not None:
                ik = await self._wrapper.unwrap(v.wrapped_index_key, scope)
                self.cache.put(_cache_key(scope, v.version, "index"), ik)
            # Zeroization honesty: `dek`/`ik` are typically immutable `bytes`
            # returned by the wrapper; CPython gives us nothing to overwrite.
            # A wrapper returning `bytearray` precisely to permit erasure is
            # deliberately not erased here either (the TS warm path zeroizes
            # its buffers); recording or closing that asymmetry is a
            # cross-core follow-up on PR #57. The long-lived copy is the
            # cache's bytearray, zeroized on eviction (cache.py).

