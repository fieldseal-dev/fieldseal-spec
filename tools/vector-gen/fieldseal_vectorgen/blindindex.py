"""Index derivation functions (spec §7.3).

HMAC-SHA-512 is stdlib. Argon2id needs `argon2-cffi`, imported lazily so the
stdlib-only families still generate without it.
"""

from __future__ import annotations

import hmac

from .primitives import HASH, hkdf, truncate

ARGON2_SALT_INFO = b"fieldseal-argon2-salt-v1"
ARGON2_SALT_LEN = 16      # libsodium fixes crypto_pwhash salt at exactly 16 B
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 32768  # 32 MiB
ARGON2_PARALLELISM = 1     # forced: libsodium exposes no parallelism parameter
ARGON2_OUTPUT_LEN = 64
ARGON2_VERSION = 0x13


def idf_hmac(index_key: bytes, normalized: bytes) -> bytes:
    """Spec §7.3, high-entropy domains only."""
    return hmac.new(index_key, normalized, HASH).digest()


def argon2_salt(index_key: bytes) -> bytes:
    """Spec §7.3. The index key enters the IDF only through this salt --
    Argon2's `K` and `X` are forbidden, because `K` is unreachable in Python
    and an implementation that added a pepper would diverge silently."""
    return hkdf(ikm=index_key, salt=b"", info=ARGON2_SALT_INFO,
                length=ARGON2_SALT_LEN)


def idf_argon2id(index_key: bytes, normalized: bytes) -> bytes:
    """Spec §7.3, enumerable domains. Requires argon2-cffi."""
    from argon2.low_level import Type, hash_secret_raw

    # argon2-cffi's `secret=` keyword is the PASSWORD, not RFC 9106's secret
    # value K. The names collide; passing index_key here would be wrong and
    # would fail silently rather than raise.
    return hash_secret_raw(
        secret=normalized,
        salt=argon2_salt(index_key),
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_OUTPUT_LEN,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


def blind_index(index_key: bytes, normalized: bytes, b_bits: int,
                idf: str) -> bytes:
    raw = idf_hmac(index_key, normalized) if idf == "hmac-sha512" \
        else idf_argon2id(index_key, normalized)
    return truncate(raw, b_bits)
