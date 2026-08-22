"""Key derivations (spec §5.3, §7.2) and key commitment (spec §4.6).

HKDF comes from pyca/cryptography rather than being hand-rolled here. That is
deliberate beyond convenience: `tools/vector-gen` hand-rolls HKDF from `hmac`,
so the two paths through this project do not share an implementation and
agreement between them is a real check rather than a tautology.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .context import FieldContext, canonical_context
from .errors import ConfigurationError

INDEX_KEY_SALT = b"fieldseal-index-v1"
COMMIT_INFO = b"fieldseal-commit-v1"
COMMIT_LEN = 32


def hkdf_sha512(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    # pyca treats salt=b"" and salt=None differently; RFC 5869 §2.2 says an
    # absent salt is HashLen zero bytes, which is what passing None gives.
    return HKDF(algorithm=hashes.SHA512(), length=length,
                salt=salt or None, info=info).derive(ikm)


def record_key(tenant_dek: bytes, key_id: bytes, msg_seed: bytes,
               ctx: FieldContext, length: int) -> bytes:
    """Spec §5.3. `msg_seed` is fresh per write, so every record key is
    single-use -- key uniqueness is structural, not a nonce property."""
    if ctx.purpose != "encrypt":
        raise ConfigurationError(
            "record_key requires purpose='encrypt' (spec §5.3)")
    return hkdf_sha512(ikm=tenant_dek, salt=key_id + msg_seed,
                       info=canonical_context(ctx), length=length)


def index_key(tenant_index_key: bytes, ctx: FieldContext,
              index_id: str) -> bytes:
    """Spec §7.2. Derived from the tenant index key, a sibling of the DEK under
    the KEK -- never from the DEK (spec §5.2)."""
    return hkdf_sha512(ikm=tenant_index_key, salt=INDEX_KEY_SALT,
                       info=canonical_context(ctx.for_index(index_id)),
                       length=32)


def commitment(record_key_bytes: bytes) -> bytes:
    """Spec §4.6, provisionally per gap G1."""
    return hkdf_sha512(ikm=record_key_bytes, salt=b"", info=COMMIT_INFO,
                       length=COMMIT_LEN)
