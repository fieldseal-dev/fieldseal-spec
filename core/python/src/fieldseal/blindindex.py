"""Blind index derivation (spec §7.2, §7.3), normalizers (docs/09 §7) and
truncation."""

from __future__ import annotations

import hmac
import re
import unicodedata
from collections.abc import Callable

from .errors import InvalidArgument
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


# -- normalizers (docs/09 §7: a closed, versioned set; portability surface) ---

def _as_text(value: str | bytes) -> str:
    """A text normalizer over bytes decodes them as UTF-8, strictly. Decoding
    with replacement characters would map distinct invalid inputs onto one
    index value, so invalid UTF-8 is refused instead (docs/18 D-10(d))."""
    if isinstance(value, str):
        return value
    try:
        return bytes(value).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InvalidArgument(
            "value is not valid UTF-8; a text normalizer cannot index it "
            "(use the `identity` normalizer for opaque bytes)") from exc


def _as_bytes(value: str | bytes) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def normalize_identity(value: str | bytes) -> bytes:
    """`identity` -- bytes unchanged; text is its UTF-8 encoding."""
    return _as_bytes(value)


def normalize_nfc_casefold(value: str | bytes) -> bytes:
    """`nfc-casefold-v1` -- NFC, then full case folding (Unicode C+F via
    `str.casefold`), then UTF-8 (docs/09 §7). No second normalization pass
    after folding: the document says none, and docs/18 D-10(c) records that
    this is a pin, not a settled point. The Unicode version is the
    interpreter's (`unicodedata.unidata_version`), reported in the
    conformance report's environment block."""
    return unicodedata.normalize("NFC", _as_text(value)).casefold() \
        .encode("utf-8")


_NON_DIGIT = re.compile(rb"[^0-9]")


def normalize_digits_only(value: str | bytes) -> bytes:
    """`digits-only-v1` -- strip every byte that is not an ASCII digit
    (docs/09 §7; phone/SSN-like values). Defined on bytes, so it needs no
    decoding and cannot fail."""
    return _NON_DIGIT.sub(b"", _as_bytes(value))


NORMALIZERS: dict[str, Callable[[str | bytes], bytes]] = {
    "identity": normalize_identity,
    "nfc-casefold-v1": normalize_nfc_casefold,
    "digits-only-v1": normalize_digits_only,
}


# -- IDFs (spec §7.3) ---------------------------------------------------------

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


IDFS: dict[str, Callable[[bytes, bytes], bytes]] = {
    "argon2id": idf_argon2id,
    "hmac-sha512": idf_hmac_sha512,
}
