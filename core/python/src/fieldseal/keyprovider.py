"""Key provider protocol and a static provider for tests (spec §8, docs/09 §8).

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
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from .context import FieldContext
from .envelope import EnvelopeHeader
from .errors import ConfigurationError


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
        if len(key_id) != 16:
            raise ConfigurationError("key_id is 16 bytes (spec §3.1)")
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
