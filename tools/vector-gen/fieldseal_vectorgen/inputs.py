"""Every input the generator uses, fixed here.

Fixed so that regeneration is byte-reproducible and MANIFEST hashes mean
something. These are PUBLIC test values and MUST NOT resemble real key
material; spec §3.1/§4.4 require a CSPRNG for `msg_seed` and `nonce` in any
real encryption, including UPDATEs.
"""

from __future__ import annotations

import hashlib

# Deliberately structured rather than random-looking, so that a human reading a
# failing vector can tell inputs from outputs at a glance.
TENANT_DEK = bytes(range(0x00, 0x20))
TENANT_INDEX_KEY = bytes(range(0x20, 0x40))
KEY_ID = bytes.fromhex("0123456789abcdef0123456789abcdef")

# A second tenant, for the cases that need two keys under one key_id shape
# (the salamander vector in errors/, the keys/ file for cross/).
TENANT_DEK_B = bytes(range(0x80, 0xA0))
TENANT_INDEX_KEY_B = bytes(range(0xA0, 0xC0))
KEY_ID_B = bytes.fromhex("fedcba9876543210fedcba9876543210")

TABLE_UUID = bytes.fromhex("3f2504e0-4f89-11d3-9a0c-0305e82c3301".replace("-", ""))
COLUMN_UUID = bytes.fromhex("7d444840-9dc0-11d1-b245-5ffdce74fad2".replace("-", ""))
COLUMN_UUID_B = bytes.fromhex("16fd2706-8baf-433b-82eb-8c7fada847da".replace("-", ""))
TENANT_ID = b"tenant-0001"
ROW_ID = b"row-42"

# docs/08 §4.3 boundary lengths for the optional context fields, plus the two
# lengths G14 is about: 255 is the bound G14 proposes (option A), and 2000 is
# above Node's 1024-byte HKDF `info` cap -- the length that split the two
# cores on 2026-08-22 with no vector noticing. If G14 adopts the 255-byte
# bound, the 2000-byte vectors retire and a refusal vector replaces them.
TENANT_ID_1B = b"t"
TENANT_ID_16B = b"tenant-0000000016"[:16]
TENANT_ID_64B = (b"tenant-" + b"0123456789" * 6)[:64]
TENANT_ID_255B = (b"tenant-255:" + bytes(range(0x30, 0x3A)) * 25)[:255]
TENANT_ID_2000B = (b"tenant-2000:" + bytes(range(0x61, 0x7B)) * 80)[:2000]
ROW_ID_255B = (b"row-255:" + bytes(range(0x41, 0x5B)) * 10)[:255]
ROW_ID_2000B = (b"row-2000:" + bytes(range(0x41, 0x5B)) * 80)[:2000]

# The anti-forgery case of docs/08 §4.3: a tenant_id whose trailing bytes look
# like a u64be length prefix for an 8-byte value, followed by eight bytes that
# could be read as that value. Under naive concatenation the field boundary is
# ambiguous; under §6.2's length-prefixed encoding it is not.
TENANT_ID_FORGERY = b"ten" + bytes([0, 0, 0, 0, 0, 0, 0, 8]) + b"row-0042"

# Spec §3.3's benchmark value is a 9-byte SSN-shaped string.
PLAINTEXTS = {
    "empty": b"",
    "one-byte": b"A",
    "ssn-9b": b"123456789",
    "block-boundary-16b": b"0123456789abcdef",
    "utf8-multibyte": "grüße 世界".encode("utf-8"),
    "one-kib": bytes(range(256)) * 4,
}


def msg_seed_for(vector_id: str) -> bytes:
    """A distinct 32-byte seed per vector, derived from its id.

    Until suite 0.1.0 every envelope vector shared one seed and one nonce, so
    the six vectors with identical context shared one record key *and* one
    nonce -- AES-GCM nonce reuse, shipped as test data by a specification whose
    second commitment is a fresh nonce on every write. Per-vector values fix
    that; deriving them from the id keeps regeneration reproducible and lets a
    reader recompute any seed by hand: SHA-256("fieldseal-vector-seed:" + id).
    """
    return hashlib.sha256(b"fieldseal-vector-seed:" + vector_id.encode()).digest()


def nonce_for(vector_id: str, nonce_len: int) -> bytes:
    """Per-vector nonce: the leading nonce_len bytes of
    SHA-256("fieldseal-vector-nonce:" + id)."""
    return hashlib.sha256(
        b"fieldseal-vector-nonce:" + vector_id.encode()).digest()[:nonce_len]
