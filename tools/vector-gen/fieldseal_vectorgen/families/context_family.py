"""`context/canonical.json` -- the presence-bitmap cases of spec §6.2."""

from __future__ import annotations

from .. import inputs as I
from ..context import FieldContext, canonical_context
from ._common import ctx_json, wrapper

SUITE = 0xFF01


def _ctx(**kw) -> FieldContext:
    base = dict(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                column_uuid=I.COLUMN_UUID, purpose="encrypt")
    base.update(kw)
    return FieldContext(**base)


CASES = [
    ("both-absent", "neither optional field present", _ctx()),
    ("tenant-present", "tenant_id present, row_id absent",
     _ctx(tenant_id=I.TENANT_ID)),
    ("both-present", "tenant_id and row_id both present",
     _ctx(tenant_id=I.TENANT_ID, row_id=I.ROW_ID)),
    ("row-only", "row_id present without tenant_id",
     _ctx(row_id=I.ROW_ID)),
    ("tenant-zero-length", "tenant_id present with zero length -- MUST differ "
     "from tenant-absent (gap G4)", _ctx(tenant_id=b"")),
    ("purpose-index", "purpose retargeted to an index (spec §7.2)",
     _ctx(tenant_id=I.TENANT_ID, purpose="index:email-eq")),
    ("purpose-max-index-id", "index-id at the §6.1 grammar's 32-char maximum",
     _ctx(tenant_id=I.TENANT_ID, purpose="index:" + "a" * 32)),
]


def generate() -> dict:
    vectors = []
    for slug, description, ctx in CASES:
        encoded = canonical_context(ctx)
        vectors.append({
            "id": f"context/canonical/{slug}",
            "description": description,
            "spec_ref": "§6.1, §6.2",
            "context": ctx_json(ctx),
            "expected": {
                "presence": ctx.presence(),
                "canonical_context": encoded.hex(),
                "length": len(encoded),
            },
        })

    # The G4 aliasing case, asserted as a relation rather than a value: the
    # thing that must hold is that these two are different, and a reader should
    # not have to diff two hex blobs to see that it is being checked.
    absent = canonical_context(_ctx())
    zero_len = canonical_context(_ctx(tenant_id=b""))
    assert absent != zero_len, "G4 regression: absent aliases zero-length"
    vectors.append({
        "id": "context/canonical/absent-differs-from-zero-length",
        "description": "absent tenant_id and zero-length tenant_id MUST NOT "
                       "produce the same encoding (gap G4)",
        "spec_ref": "§6.2",
        "assertion": "distinct",
        "expected": {
            "tenant_absent": absent.hex(),
            "tenant_zero_length": zero_len.hex(),
            "must_be_equal": False,
        },
    })
    return wrapper("context", vectors)
