"""Cryptographic primitives used by the generator.

Only stdlib. Anything needing a third-party dependency lives in `envelope.py`
(AES-GCM) or `blindindex.py` (Argon2id), so that the families listed in the
README as stdlib-only stay runnable on a bare interpreter.
"""

from __future__ import annotations

import hashlib
import hmac

HASH = hashlib.sha512
HASH_LEN = HASH().digest_size  # 64


def u8(n: int) -> bytes:
    if not 0 <= n <= 0xFF:
        raise ValueError(f"u8 out of range: {n}")
    return n.to_bytes(1, "big")


def u64be(n: int) -> bytes:
    if not 0 <= n < 1 << 64:
        raise ValueError(f"u64be out of range: {n}")
    return n.to_bytes(8, "big")


def lv(value: bytes) -> bytes:
    """Length-prefixed value: u64be(len) || value (spec §6.2)."""
    return u64be(len(value)) + value


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * HASH_LEN:
        raise ValueError(f"HKDF output too long: {length}")
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), HASH).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA-512 (RFC 5869), the KDF of both registered suites (spec §4.2).

    RFC 5869 §2.2: a zero-length salt is replaced by HashLen zero bytes. This
    matters here because spec §4.6 and §7.3 both call HKDF with salt = "".
    """
    if len(salt) == 0:
        salt = b"\x00" * HASH_LEN
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def truncate(raw: bytes, b_bits: int) -> bytes:
    """`truncate(raw, b bits)` exactly as pinned in spec §7.2.

    Keep the leading ceil(b/8) bytes, then zero the trailing
    8*ceil(b/8) - b bits of the final byte. Bits are numbered MSB-first.
    """
    if b_bits <= 0:
        raise ValueError("b must be positive")
    n_bytes = (b_bits + 7) // 8
    if n_bytes > len(raw):
        raise ValueError(f"cannot truncate {len(raw)} bytes to {b_bits} bits")
    out = bytearray(raw[:n_bytes])
    spare = 8 * n_bytes - b_bits
    if spare:
        out[-1] &= (0xFF << spare) & 0xFF
    return bytes(out)
