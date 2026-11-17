"""The cipher suite registry (spec §4.2) and the provisional range (spec §4.8).

A `suite_id` names a complete, frozen suite. There is no caller-settable
algorithm parameter anywhere in this package -- that is the §4.1 commitment,
and it is why this table is a frozen dataclass rather than configuration.

This module also carries the operand byte-string predicate (docs/09 §1, #257).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeGuard

PROVISIONAL_MIN = 0xFF00
PROVISIONAL_MAX = 0xFFFF


@dataclass(frozen=True, slots=True)
class Suite:
    suite_id: int
    name: str
    key_len: int
    nonce_len: int
    tag_len: int
    commit_len: int


SUITES: dict[int, Suite] = {
    0xFF01: Suite(0xFF01, "FLE-AES256GCM-HKDF-SHA512-PROVISIONAL",
                  key_len=32, nonce_len=12, tag_len=16, commit_len=32),
    0xFF02: Suite(0xFF02, "FLE-XCHACHA20POLY1305-HKDF-SHA512-PROVISIONAL",
                  key_len=32, nonce_len=24, tag_len=16, commit_len=32),
}


def is_provisional(suite_id: int) -> bool:
    """Spec §4.8. One masked comparison, answerable from the header alone --
    no key, no provider, no decrypt."""
    return PROVISIONAL_MIN <= suite_id <= PROVISIONAL_MAX


def is_byte_string(operand: object) -> TypeGuard[bytes | bytearray | memoryview]:
    """What every operation that takes bytes accepts (spec §11.1, docs/10 §4):
    `bytes`, `bytearray`, or a `memoryview` that is one-dimensional,
    contiguous and of format "B" -- the view `memoryview(b)` gives over
    either. A view of wider items, a strided view or a multi-dimensional one
    is bytes-typed and still unusable: the AEAD refuses it with a raw error,
    `len()` counts its items rather than its bytes, and a normalizer would
    index its machine-endian bytes (#254).

    This is the one definition of a usable byte view: recognition
    (`envelope._view`) and the operations (`api._require_bytes`,
    `blindindex.require_index_operand`) share it, so `is_ciphertext` never
    says True of a value `decrypt` refuses (#257). It lives in `registry`
    because docs/09 §1 lets `envelope`, `blindindex` and `api` all import
    `registry`, so sharing it adds no edge; `blindindex` re-exports the name.

    The guard narrows to the three types, not to the shape: a `memoryview`
    that narrowing admits may still be one this function refused, so a
    caller must use the boolean, not the static type.
    """
    if isinstance(operand, bytes | bytearray):
        return True
    if not isinstance(operand, memoryview):
        return False
    try:
        return (operand.ndim == 1 and operand.format == "B"
                and operand.c_contiguous)
    except ValueError:  # a released view
        return False
