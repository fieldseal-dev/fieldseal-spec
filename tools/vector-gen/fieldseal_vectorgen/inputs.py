"""Every input the generator uses, fixed here.

Fixed so that regeneration is byte-reproducible and MANIFEST hashes mean
something. These are PUBLIC test values and MUST NOT resemble real key
material; spec §3.1/§4.4 require a CSPRNG for `msg_seed` and `nonce` in any
real encryption, including UPDATEs.
"""

from __future__ import annotations

# Deliberately structured rather than random-looking, so that a human reading a
# failing vector can tell inputs from outputs at a glance.
TENANT_DEK = bytes(range(0x00, 0x20))
TENANT_INDEX_KEY = bytes(range(0x20, 0x40))
KEY_ID = bytes.fromhex("0123456789abcdef0123456789abcdef")
MSG_SEED = bytes(range(0x40, 0x60))
NONCE_FF01 = bytes.fromhex("000102030405060708090a0b")

TABLE_UUID = bytes.fromhex("3f2504e0-4f89-11d3-9a0c-0305e82c3301".replace("-", ""))
COLUMN_UUID = bytes.fromhex("7d444840-9dc0-11d1-b245-5ffdce74fad2".replace("-", ""))
TENANT_ID = b"tenant-0001"
ROW_ID = b"row-42"

# Spec §3.3's benchmark value is a 9-byte SSN-shaped string.
PLAINTEXTS = {
    "empty": b"",
    "one-byte": b"A",
    "ssn-9b": b"123456789",
    "block-boundary-16b": b"0123456789abcdef",
    "utf8-multibyte": "gr\u00fc\u00dfe \u4e16\u754c".encode("utf-8"),
    "one-kib": bytes(range(256)) * 4,
}
