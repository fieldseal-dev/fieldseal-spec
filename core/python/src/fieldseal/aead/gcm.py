"""AES-256-GCM backend for suite 0xFF01."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import TagInvalid

TAG_LEN = 16


class GcmBackend:
    def seal(self, key: bytes, nonce: bytes, plaintext: bytes,
             aad: bytes) -> tuple[bytes, bytes]:
        blob = AESGCM(key).encrypt(nonce, plaintext, aad)
        return blob[:-TAG_LEN], blob[-TAG_LEN:]

    def open(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
             aad: bytes) -> bytes:
        try:
            return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
        except InvalidTag as exc:
            # GCM cannot distinguish "wrong AAD" from "flipped bit" -- both are
            # one InvalidTag. Spec §9 wants them separate where possible, and
            # under dual-layer binding (§6.3) a context mismatch usually
            # surfaces earlier as COMMITMENT_INVALID, because the wrong context
            # derives the wrong record key. What reaches here is the residue.
            # Which of AAD_MISMATCH / TAG_INVALID applies is gap G5 and is not
            # settled; reporting TAG_INVALID is the conservative choice, since
            # it claims less about why.
            raise TagInvalid("AEAD authentication failed") from exc
