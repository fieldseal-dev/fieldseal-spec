from __future__ import annotations

from typing import Protocol


class AeadBackend(Protocol):
    def seal(self, key: bytes, nonce: bytes, plaintext: bytes,
             aad: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, tag) split out -- the envelope stores them in
        separate positions (spec §3.1), not as one blob."""

    def open(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
             aad: bytes) -> bytes:
        ...
