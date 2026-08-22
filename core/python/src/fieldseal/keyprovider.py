"""Key provider protocol and a static provider for tests (spec §8, docs/09 §8).

Purpose routing matters here: an index purpose MUST NOT return the field DEK
(spec §8). The index key material is a sibling of the DEK under the KEK, never
derived from it (spec §5.2).
"""

from __future__ import annotations

from typing import Protocol

from .context import FieldContext
from .errors import ConfigurationError


class KeyProvider(Protocol):
    def dek_for(self, ctx: FieldContext) -> tuple[bytes, bytes]:
        """Returns (key_id, tenant_dek) for a write."""

    def dek_for_key_id(self, key_id: bytes, ctx: FieldContext) -> bytes:
        """Returns the tenant DEK named by key_id. Raises KeyError if gone."""

    def index_key_material(self, ctx: FieldContext) -> bytes:
        """Returns the tenant INDEX key -- never the DEK."""


class StaticKeyProvider:
    """Test-only provider holding one DEK and one index key in memory.

    Not for production: it performs no KMS call, no caching, no rotation, and
    holds key material for the process lifetime.
    """

    def __init__(self, key_id: bytes, tenant_dek: bytes,
                 tenant_index_key: bytes) -> None:
        if len(key_id) != 16:
            raise ConfigurationError("key_id is 16 bytes (spec §3.1)")
        if tenant_dek == tenant_index_key:
            raise ConfigurationError(
                "the tenant index key must not equal the DEK (spec §5.2)")
        self._key_id = key_id
        self._dek = tenant_dek
        self._index_key = tenant_index_key

    def dek_for(self, ctx: FieldContext) -> tuple[bytes, bytes]:
        if ctx.purpose != "encrypt":
            raise ConfigurationError(
                f"dek_for called with purpose {ctx.purpose!r}; an index "
                "purpose must never be served the field DEK (spec §8)")
        return self._key_id, self._dek

    def dek_for_key_id(self, key_id: bytes, ctx: FieldContext) -> bytes:
        if key_id != self._key_id:
            raise KeyError(key_id.hex())
        return self._dek

    def index_key_material(self, ctx: FieldContext) -> bytes:
        return self._index_key
