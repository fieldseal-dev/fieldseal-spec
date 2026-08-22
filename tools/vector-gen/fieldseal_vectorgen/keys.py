"""Key derivations from the hierarchy of spec §5."""

from __future__ import annotations

from .context import FieldContext, canonical_context
from .primitives import hkdf

INDEX_KEY_SALT = b"fieldseal-index-v1"


def record_key(tenant_dek: bytes, key_id: bytes, msg_seed: bytes,
               ctx: FieldContext, length: int) -> bytes:
    """Spec §5.3. `msg_seed` is fresh per write, so every record key is
    single-use -- which is what makes key uniqueness structural rather than a
    property of the nonce (spec §4.4, §5.3)."""
    if ctx.purpose != "encrypt":
        raise ValueError("record_key requires purpose='encrypt' (spec §5.3)")
    return hkdf(ikm=tenant_dek, salt=key_id + msg_seed,
                info=canonical_context(ctx), length=length)


def index_key(tenant_index_key: bytes, ctx: FieldContext, index_id: str) -> bytes:
    """Spec §7.2. Derived from the tenant *index* key, a sibling of the tenant
    DEK under the KEK -- never from the DEK itself (spec §5.2)."""
    return hkdf(ikm=tenant_index_key, salt=INDEX_KEY_SALT,
                info=canonical_context(ctx.for_index(index_id)), length=32)
