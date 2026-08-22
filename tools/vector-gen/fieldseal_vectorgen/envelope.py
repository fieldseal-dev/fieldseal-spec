"""Envelope assembly (spec §3.1) and key commitment (spec §4.6).

AES-GCM needs `cryptography`, imported lazily.
"""

from __future__ import annotations

from dataclasses import dataclass

from .context import FieldContext, aad, canonical_context
from .keys import record_key
from .primitives import hkdf

COMMIT_INFO = b"fieldseal-commit-v1"
COMMIT_LEN = 32
FMT_VER = 0x01

SUITES = {
    0xFF01: {"name": "FLE-AES256GCM-HKDF-SHA512-PROVISIONAL",
             "key_len": 32, "nonce_len": 12, "tag_len": 16, "commit_len": 32},
    0xFF02: {"name": "FLE-XCHACHA20POLY1305-HKDF-SHA512-PROVISIONAL",
             "key_len": 32, "nonce_len": 24, "tag_len": 16, "commit_len": 32},
}


def commitment(rk: bytes) -> bytes:
    """Spec §4.6, provisionally per gap G1. Verified constant-time before the
    AEAD open on the decrypt side -- the generator only produces it."""
    return hkdf(ikm=rk, salt=b"", info=COMMIT_INFO, length=COMMIT_LEN)


def header(suite_id: int, key_id: bytes, msg_seed: bytes) -> bytes:
    if len(key_id) != 16:
        raise ValueError("key_id is 16 bytes (spec §3.1)")
    if len(msg_seed) != 32:
        raise ValueError("msg_seed is 32 bytes (spec §3.1)")
    return bytes([FMT_VER]) + suite_id.to_bytes(2, "big") + key_id + msg_seed


@dataclass(frozen=True)
class Sealed:
    envelope: bytes
    canonical_context: bytes
    aad: bytes
    record_key: bytes
    commitment: bytes


def seal(suite_id: int, tenant_dek: bytes, key_id: bytes, msg_seed: bytes,
         nonce: bytes, ctx: FieldContext, plaintext: bytes) -> Sealed:
    suite = SUITES[suite_id]
    if len(nonce) != suite["nonce_len"]:
        raise ValueError(f"suite {suite_id:#06x} takes a "
                         f"{suite['nonce_len']}-byte nonce")
    if ctx.suite_id != suite_id:
        raise ValueError("ctx.suite_id must match the write suite (docs/09 §3.2)")

    rk = record_key(tenant_dek, key_id, msg_seed, ctx, suite["key_len"])
    a = aad(FMT_VER, key_id, msg_seed, ctx)

    if suite_id == 0xFF01:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        blob = AESGCM(rk).encrypt(nonce, plaintext, a)
    else:
        raise NotImplementedError(
            "suite 0xFF02 needs an XChaCha20-Poly1305 backend; its normative "
            "source is gap G7 and unresolved (spec §4.2)")

    tag_len = suite["tag_len"]
    ct, tag = blob[:-tag_len], blob[-tag_len:]
    commit = commitment(rk)
    return Sealed(
        envelope=header(suite_id, key_id, msg_seed) + nonce + ct + tag + commit,
        canonical_context=canonical_context(ctx),
        aad=a,
        record_key=rk,
        commitment=commit,
    )
