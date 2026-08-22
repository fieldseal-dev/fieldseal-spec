"""`commitment/ff01.json` -- spec §4.6, provisionally per gap G1."""

from __future__ import annotations

from .. import inputs as I
from ..context import FieldContext
from ..envelope import commitment
from ..keys import record_key
from ._common import suite_str, wrapper

SUITE = 0xFF01


def generate() -> dict:
    ctx = FieldContext(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                       column_uuid=I.COLUMN_UUID, purpose="encrypt",
                       tenant_id=I.TENANT_ID)
    rk = record_key(I.TENANT_DEK, I.KEY_ID, I.MSG_SEED, ctx, 32)
    vectors = [{
        "id": "commitment/ff01/from-record-key",
        "description": "key commitment derived from a record key",
        "spec_ref": "§4.6, §3.1",
        "suite_id": suite_str(SUITE),
        "record_key": rk.hex(),
        "expected": {
            "info": b"fieldseal-commit-v1".hex(),
            "commitment": commitment(rk).hex(),
            "length": 32,
        },
    }]

    # The property the commitment exists for: distinct keys, distinct
    # commitments. A partitioning oracle needs one ciphertext valid under two
    # keys (spec §4.6, AWS-2025-032).
    other = bytes(b ^ 0x01 for b in rk)
    a, b = commitment(rk), commitment(other)
    assert a != b
    vectors.append({
        "id": "commitment/ff01/distinct-keys-distinct-commitments",
        "description": "two record keys differing in one bit MUST produce "
                       "different commitments",
        "spec_ref": "§4.6",
        "assertion": "distinct",
        "expected": {"commitment_a": a.hex(), "commitment_b": b.hex(),
                     "must_be_equal": False},
    })
    return wrapper("commitment", vectors)
