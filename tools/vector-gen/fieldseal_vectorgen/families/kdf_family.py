"""`kdf/record-key.json` and `kdf/index-key.json` -- spec §5.3 and §7.2."""

from __future__ import annotations

from .. import inputs as I
from ..context import FieldContext, canonical_context
from ..keys import index_key, record_key
from ._common import ctx_json, suite_str, wrapper

SUITE = 0xFF01


def _ctx(**kw) -> FieldContext:
    base = dict(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                column_uuid=I.COLUMN_UUID, purpose="encrypt",
                tenant_id=I.TENANT_ID)
    base.update(kw)
    return FieldContext(**base)


def generate_record_key() -> dict:
    vectors = []
    for slug, description, ctx in [
        ("row-absent", "record key with row_id absent", _ctx()),
        ("row-present", "record key with row_id present (L3-row binding)",
         _ctx(row_id=I.ROW_ID)),
        ("tenant-absent", "record key with no tenant in context", 
         _ctx(tenant_id=None)),
    ]:
        rk = record_key(I.TENANT_DEK, I.KEY_ID, I.MSG_SEED, ctx, 32)
        vectors.append({
            "id": f"kdf/record-key/{slug}",
            "description": description,
            "spec_ref": "§5.3, §6.2",
            "suite_id": suite_str(SUITE),
            "tenant_dek": I.TENANT_DEK.hex(),
            "key_id": I.KEY_ID.hex(),
            "msg_seed": I.MSG_SEED.hex(),
            "context": ctx_json(ctx),
            "expected": {
                "salt": (I.KEY_ID + I.MSG_SEED).hex(),
                "info": canonical_context(ctx).hex(),
                "record_key": rk.hex(),
            },
        })

    # msg_seed is what makes each derived key single-use (spec §4.4, §5.3).
    # Asserting that directly is worth more than another positive vector.
    ctx = _ctx()
    other_seed = bytes(b ^ 0xFF for b in I.MSG_SEED)
    a = record_key(I.TENANT_DEK, I.KEY_ID, I.MSG_SEED, ctx, 32)
    b = record_key(I.TENANT_DEK, I.KEY_ID, other_seed, ctx, 32)
    assert a != b
    vectors.append({
        "id": "kdf/record-key/seed-changes-key",
        "description": "a different msg_seed under identical context MUST "
                       "produce a different record key -- this is what makes "
                       "every derived key single-use",
        "spec_ref": "§4.4, §5.3",
        "assertion": "distinct",
        "expected": {"key_a": a.hex(), "key_b": b.hex(),
                     "must_be_equal": False},
    })
    return wrapper("kdf", vectors)


def generate_index_key() -> dict:
    vectors = []
    for index_id in ["email-eq", "ssn-eq"]:
        ctx = _ctx()
        ik = index_key(I.TENANT_INDEX_KEY, ctx, index_id)
        vectors.append({
            "id": f"kdf/index-key/{index_id}",
            "description": f"index key for index-id {index_id!r}",
            "spec_ref": "§5.2, §7.2",
            "suite_id": suite_str(SUITE),
            "tenant_index_key": I.TENANT_INDEX_KEY.hex(),
            "index_id": index_id,
            "context": ctx_json(ctx),
            "expected": {
                "salt": b"fieldseal-index-v1".hex(),
                "info": canonical_context(ctx.for_index(index_id)).hex(),
                "index_key": ik.hex(),
            },
        })

    # §7.2: two indexes MUST NOT share a key.
    ctx = _ctx()
    a = index_key(I.TENANT_INDEX_KEY, ctx, "email-eq")
    b = index_key(I.TENANT_INDEX_KEY, ctx, "ssn-eq")
    assert a != b
    vectors.append({
        "id": "kdf/index-key/distinct-per-index",
        "description": "two index-ids under one tenant MUST derive different "
                       "index keys (spec §7.2)",
        "spec_ref": "§7.2",
        "assertion": "distinct",
        "expected": {"key_a": a.hex(), "key_b": b.hex(),
                     "must_be_equal": False},
    })
    return wrapper("kdf", vectors)
