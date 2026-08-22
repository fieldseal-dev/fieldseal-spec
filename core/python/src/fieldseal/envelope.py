"""Envelope parsing and serialization (spec §3.1, §3.2, §3.4)."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import LengthExceeded, NotCiphertext, UnknownFormatVersion
from .registry import SUITES, Suite

FMT_VER = 0x01
HEADER_LEN = 51  # 1 + 2 + 16 + 32
MAX_PLAINTEXT = (1 << 31) - 1  # spec §3.5


@dataclass(frozen=True, slots=True)
class EnvelopeHeader:
    fmt_ver: int
    suite_id: int
    key_id: bytes
    msg_seed: bytes


def serialize_header(suite_id: int, key_id: bytes, msg_seed: bytes) -> bytes:
    return (bytes([FMT_VER]) + suite_id.to_bytes(2, "big") + key_id + msg_seed)


def parse_header(blob: bytes) -> EnvelopeHeader:
    if len(blob) < HEADER_LEN:
        raise NotCiphertext(f"shorter than the {HEADER_LEN}-byte header")
    fmt_ver = blob[0]
    if fmt_ver != FMT_VER:
        raise UnknownFormatVersion(f"fmt_ver {fmt_ver:#04x} unrecognized")
    return EnvelopeHeader(
        fmt_ver=fmt_ver,
        suite_id=int.from_bytes(blob[1:3], "big"),
        key_id=blob[3:19],
        msg_seed=blob[19:51],
    )


def split(blob: bytes, suite: Suite) -> tuple[bytes, bytes, bytes, bytes]:
    """nonce, ciphertext, tag, commitment. Raises NotCiphertext on any length
    that cannot hold them -- never IndexError, never a slice that silently
    yields short bytes."""
    fixed = HEADER_LEN + suite.nonce_len + suite.tag_len + suite.commit_len
    if len(blob) < fixed:
        raise NotCiphertext(
            f"{len(blob)} bytes cannot hold suite {suite.suite_id:#06x}'s "
            f"{fixed}-byte fixed overhead")
    if len(blob) - fixed > MAX_PLAINTEXT:
        raise LengthExceeded("envelope implies a plaintext over the §3.5 bound")
    i = HEADER_LEN
    nonce = blob[i:i + suite.nonce_len]
    i += suite.nonce_len
    end = len(blob) - suite.commit_len
    commit = blob[end:]
    tag = blob[end - suite.tag_len:end]
    ct = blob[i:end - suite.tag_len]
    return nonce, ct, tag, commit


def is_ciphertext(blob: object) -> bool:
    """Spec §3.4. Total on arbitrary input: never raises, for any value.

    A cheap structural check only -- it says "this looks like one of ours",
    not "this is authentic". Authenticity is decrypt's job.
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        return False
    b = bytes(blob)
    if len(b) < HEADER_LEN or b[0] != FMT_VER:
        return False
    suite = SUITES.get(int.from_bytes(b[1:3], "big"))
    if suite is None:
        return False
    fixed = HEADER_LEN + suite.nonce_len + suite.tag_len + suite.commit_len
    return len(b) >= fixed
