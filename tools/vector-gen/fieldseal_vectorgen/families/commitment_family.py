"""`commitment/ff01.json` -- spec §4.6, provisionally per gap G1."""

from __future__ import annotations

from .. import inputs as I
from ..context import FieldContext
from ..envelope import COMMIT_INFO, COMMIT_LEN, commitment
from ..keys import record_key
from ._common import suite_str, wrapper

SUITE = 0xFF01


def generate() -> dict:
    ctx = FieldContext(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                       column_uuid=I.COLUMN_UUID, purpose="encrypt",
                       tenant_id=I.TENANT_ID)
    vid = "commitment/ff01/from-record-key"
    rk = record_key(I.TENANT_DEK, I.KEY_ID, I.msg_seed_for(vid), ctx, 32)
    vectors = [{
        "id": vid,
        "description": "key commitment derived from a record key",
        "spec_ref": "§4.6, §3.1",
        "suite_id": suite_str(SUITE),
        "record_key": rk.hex(),
        "expected": {
            "salt": "",
            "info": COMMIT_INFO.hex(),
            "commitment": commitment(rk).hex(),
            "length": COMMIT_LEN,
        },
        "provisional_on": ["G1"],
    }]

    # The property the commitment exists for: distinct keys, distinct
    # commitments. A partitioning oracle needs one ciphertext valid under two
    # keys (spec §4.6, AWS-2025-032). The second key differs from the first in
    # exactly one bit -- bit 0 of the last byte -- which is what the earlier
    # description claimed while the code flipped bit 0 of every byte.
    other = rk[:-1] + bytes([rk[-1] ^ 0x01])
    assert sum(bin(x ^ y).count("1") for x, y in zip(rk, other)) == 1
    a, b = commitment(rk), commitment(other)
    assert a != b
    vectors.append({
        "id": "commitment/ff01/distinct-keys-distinct-commitments",
        "description": "two record keys differing in one bit (bit 0 of the "
                       "last byte) MUST produce different commitments",
        "spec_ref": "§4.6",
        "assertion": "distinct",
        "suite_id": suite_str(SUITE),
        "inputs": {"record_key_a": rk.hex(), "record_key_b": other.hex()},
        "expected": {"commitment_a": a.hex(), "commitment_b": b.hex(),
                     "must_be_equal": False},
        "provisional_on": ["G1"],
    })
    return wrapper("commitment", vectors)
