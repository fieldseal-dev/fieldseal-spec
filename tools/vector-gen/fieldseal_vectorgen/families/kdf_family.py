"""`kdf/record-key.json` and `kdf/index-key.json` -- spec §5.3 and §7.2."""

from __future__ import annotations

from .. import inputs as I
from ..context import FieldContext, canonical_context
from ..keys import INDEX_KEY_SALT, index_key, record_key
from ._common import ctx_json, suite_str, wrapper

SUITE = 0xFF01
MAX_INDEX_ID = "a" * 32


def _ctx(**kw) -> FieldContext:
    base = dict(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                column_uuid=I.COLUMN_UUID, purpose="encrypt",
                tenant_id=I.TENANT_ID)
    base.update(kw)
    return FieldContext(**base)


def generate_record_key() -> dict:
    vectors = []
    cases = [
        ("row-absent", "record key with row_id absent", _ctx(), None),
        ("row-present", "record key with row_id present (L3-row binding)",
         _ctx(row_id=I.ROW_ID), None),
        ("tenant-absent", "record key with no tenant in context",
         _ctx(tenant_id=None), None),
        ("max-context",
         "record key under the longest encrypt-path context: 2000-byte "
         "tenant_id and row_id (HKDF info above node:crypto's 1024-byte cap; "
         "the G14 case). Retires if G14 adopts a bound below it",
         _ctx(tenant_id=I.TENANT_ID_2000B, row_id=I.ROW_ID_2000B), "G14"),
    ]
    for slug, description, ctx, provisional_on in cases:
        vid = f"kdf/record-key/{slug}"
        seed = I.msg_seed_for(vid)
        rk = record_key(I.TENANT_DEK, I.KEY_ID, seed, ctx, 32)
        vec = {
            "id": vid,
            "description": description,
            "spec_ref": "§5.3, §6.2",
            "suite_id": suite_str(SUITE),
            "tenant_dek": I.TENANT_DEK.hex(),
            "key_id": I.KEY_ID.hex(),
            "msg_seed": seed.hex(),
            "context": ctx_json(ctx),
            "expected": {
                "salt": (I.KEY_ID + seed).hex(),
                "info": canonical_context(ctx).hex(),
                "record_key": rk.hex(),
            },
        }
        if provisional_on:
            vec["provisional_on"] = [provisional_on]
        vectors.append(vec)

    # msg_seed is what makes each derived key single-use (spec §4.4, §5.3).
    # Asserting that directly is worth more than another positive vector. Both
    # seeds are carried (docs/18 D-08) so each side is reproducible.
    vid = "kdf/record-key/seed-changes-key"
    ctx = _ctx()
    seed_a = I.msg_seed_for(vid)
    seed_b = bytes(b ^ 0xFF for b in seed_a)
    a = record_key(I.TENANT_DEK, I.KEY_ID, seed_a, ctx, 32)
    b = record_key(I.TENANT_DEK, I.KEY_ID, seed_b, ctx, 32)
    assert a != b
    vectors.append({
        "id": vid,
        "description": "a different msg_seed under identical context MUST "
                       "produce a different record key -- this is what makes "
                       "every derived key single-use",
        "spec_ref": "§4.4, §5.3",
        "assertion": "distinct",
        "suite_id": suite_str(SUITE),
        "inputs": {
            "tenant_dek": I.TENANT_DEK.hex(),
            "key_id": I.KEY_ID.hex(),
            "context": ctx_json(ctx),
            "msg_seed_a": seed_a.hex(),
            "msg_seed_b": seed_b.hex(),
        },
        "expected": {"key_a": a.hex(), "key_b": b.hex(),
                     "must_be_equal": False},
    })
    return wrapper("kdf", vectors)


def _index_vector(slug: str, description: str, ctx: FieldContext,
                  index_id: str, provisional_on: str | None = None) -> dict:
    """docs/08 §4.2: the index-key family mirrors record-key with `purpose`
    of the form `index:<index-id>` and `row_id` forced null. The context is
    carried exactly as the core derives under it (docs/18 D-06); `index_id`
    is repeated at the top level for readability only."""
    ictx = ctx.for_index(index_id)
    ik = index_key(I.TENANT_INDEX_KEY, ctx, index_id)
    vec = {
        "id": f"kdf/index-key/{slug}",
        "description": description,
        "spec_ref": "§5.2, §7.2",
        "suite_id": suite_str(SUITE),
        "tenant_index_key": I.TENANT_INDEX_KEY.hex(),
        "index_id": index_id,
        "context": ctx_json(ictx),
        "expected": {
            "salt": INDEX_KEY_SALT.hex(),
            "info": canonical_context(ictx).hex(),
            "index_key": ik.hex(),
        },
    }
    if provisional_on:
        vec["provisional_on"] = [provisional_on]
    return vec


def generate_index_key() -> dict:
    vectors = [
        _index_vector("email-eq", "index key for index-id 'email-eq'",
                      _ctx(), "email-eq"),
        _index_vector("ssn-eq", "index key for index-id 'ssn-eq' -- differs "
                      "from email-eq only in the index-id (§7.2 distinctness)",
                      _ctx(), "ssn-eq"),
        _index_vector("email-eq-column-b",
                      "index key for 'email-eq' under a different column_uuid "
                      "-- differs from email-eq only in the column (§7.2 "
                      "per-column separation)",
                      _ctx(column_uuid=I.COLUMN_UUID_B), "email-eq"),
        _index_vector("row-id-dropped",
                      "the caller's context carried a row_id; §7.2 drops it "
                      "for index derivation, so this equals email-eq",
                      _ctx(row_id=I.ROW_ID), "email-eq"),
        _index_vector("max-context",
                      "index key under the longest index-path context: "
                      "2000-byte tenant_id, index-id at the 32-char maximum "
                      "(the G14 case). Retires if G14 adopts a bound below it",
                      _ctx(tenant_id=I.TENANT_ID_2000B), MAX_INDEX_ID, "G14"),
    ]
    # row-id-dropped is, by construction, the same derivation as email-eq.
    # Say so where a reader will see it rather than leaving two identical
    # expected values to be noticed.
    assert (vectors[3]["expected"]["index_key"]
            == vectors[0]["expected"]["index_key"])
    vectors[3]["same_as"] = vectors[0]["id"]

    # §7.2: two indexes MUST NOT share a key. Inputs carried (docs/18 D-08).
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
        "suite_id": suite_str(SUITE),
        "inputs": {
            "tenant_index_key": I.TENANT_INDEX_KEY.hex(),
            "context_a": ctx_json(ctx.for_index("email-eq")),
            "context_b": ctx_json(ctx.for_index("ssn-eq")),
        },
        "expected": {"key_a": a.hex(), "key_b": b.hex(),
                     "must_be_equal": False},
    })
    return wrapper("kdf", vectors)
