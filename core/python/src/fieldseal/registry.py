"""The cipher suite registry (spec §4.2) and the provisional range (spec §4.8).

A `suite_id` names a complete, frozen suite. There is no caller-settable
algorithm parameter anywhere in this package -- that is the §4.1 commitment,
and it is why this table is a frozen dataclass rather than configuration.
"""

from __future__ import annotations

from dataclasses import dataclass

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
