"""Blind index derivation (spec §7.2, §7.3) and truncation."""

from __future__ import annotations

import hmac
import unicodedata

from .kdf import hkdf_sha512

ARGON2_SALT_INFO = b"fieldseal-argon2-salt-v1"
ARGON2_SALT_LEN = 16
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 32768
ARGON2_PARALLELISM = 1
ARGON2_OUTPUT_LEN = 64
ARGON2_VERSION = 0x13


def truncate(raw: bytes, b_bits: int) -> bytes:
    """Spec §7.2, bit-exact: leading ceil(b/8) bytes, trailing
    8*ceil(b/8) - b bits of the final byte zeroed, MSB-first numbering."""
    if b_bits <= 0:
        raise ValueError("b must be positive")
    n = (b_bits + 7) // 8
    if n > len(raw):
        raise ValueError(f"cannot truncate {len(raw)} bytes to {b_bits} bits")
    out = bytearray(raw[:n])
    spare = 8 * n - b_bits
    if spare:
        out[-1] &= (0xFF << spare) & 0xFF
    return bytes(out)


def normalize_nfc_casefold(value: str) -> bytes:
    return unicodedata.normalize("NFC", value).casefold().encode("utf-8")


def idf_hmac_sha512(index_key: bytes, normalized: bytes) -> bytes:
    return hmac.new(index_key, normalized, "sha512").digest()


def argon2_salt(index_key: bytes) -> bytes:
    return hkdf_sha512(ikm=index_key, salt=b"", info=ARGON2_SALT_INFO,
                       length=ARGON2_SALT_LEN)


def idf_argon2id(index_key: bytes, normalized: bytes) -> bytes:
    """Spec §7.3.

    UNVALIDATED. The `blind-index/argon2id.json` vector family is held out of
    the pinned suite because this primitive has never been checked against an
    external known-answer source -- RFC 9106 §5.3's vector needs a nonzero
    secret and associated data, both of which §7.3 forbids and Python cannot
    supply. Passing the project's own vectors here would prove only that two
    implementations copied one unverified assumption.
    """
    from argon2.low_level import Type, hash_secret_raw

    # `secret=` here is argon2-cffi's name for the PASSWORD. It is *not*
    # RFC 9106's secret value K, which §7.3 forbids and which this API cannot
    # supply anyway. Passing index_key here would be silently wrong.
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
