"""`envelope/ff01.json` -- the round-trip family of docs/08 §4.1."""

from __future__ import annotations

from .. import inputs as I
from ..context import FieldContext
from ..envelope import seal
from ._common import ctx_json, suite_str, wrapper

SUITE = 0xFF01


def _ctx(**kw) -> FieldContext:
    base = dict(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                column_uuid=I.COLUMN_UUID, purpose="encrypt",
                tenant_id=I.TENANT_ID)
    base.update(kw)
    return FieldContext(**base)


def generate() -> dict:
    vectors = []
    # docs/08 §4.1 minimum coverage, one vector per named case.
    cases = [
        ("empty-plaintext", "empty", _ctx()),
        ("one-byte", "one-byte", _ctx()),
        ("basic-roundtrip", "ssn-9b", _ctx()),
        ("block-boundary", "block-boundary-16b", _ctx()),
        ("one-kib", "one-kib", _ctx()),
        ("utf8-multibyte", "utf8-multibyte", _ctx()),
        ("row-id-present", "ssn-9b", _ctx(row_id=I.ROW_ID)),
        ("tenant-absent", "ssn-9b", _ctx(tenant_id=None)),
    ]
    for slug, pt_name, ctx in cases:
        pt = I.PLAINTEXTS[pt_name]
        # Every envelope context carries purpose="encrypt" -- spec §5.3
        # constrains record-key derivation to it, so an index purpose is not
        # expressible here at all. The maximum-length index-id belongs to the
        # context family, which is where it is covered; a vector here that
        # silently substituted an encrypt context would be a duplicate of
        # basic-roundtrip wearing a name that claims otherwise.
        assert ctx.purpose == "encrypt", slug
        s = seal(SUITE, I.TENANT_DEK, I.KEY_ID, I.MSG_SEED, I.NONCE_FF01,
                 ctx, pt)
        vectors.append({
            "id": f"envelope/ff01/{slug}",
            "description": f"{len(pt)}-byte plaintext, "
                           f"{'row_id present' if ctx.row_id else 'row_id absent'}",
            "spec_ref": "§3.1, §4.2, §5.3, §6.2, §6.3",
            "suite_id": suite_str(SUITE),
            "tenant_dek": I.TENANT_DEK.hex(),
            "key_id": I.KEY_ID.hex(),
            "msg_seed": I.MSG_SEED.hex(),
            "nonce": I.NONCE_FF01.hex(),
            "context": ctx_json(ctx),
            "plaintext": pt.hex(),
            "expected": {
                "envelope": s.envelope.hex(),
                "canonical_context": s.canonical_context.hex(),
                "aad": s.aad.hex(),
                "envelope_bytes": len(s.envelope),
            },
            "intermediates": {
                "record_key": s.record_key.hex(),
                "commitment": s.commitment.hex(),
            },
        })
    return wrapper("envelope", vectors)
