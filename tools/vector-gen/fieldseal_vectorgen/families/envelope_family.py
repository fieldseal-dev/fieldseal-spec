"""`envelope/ff01.json` -- the round-trip family of docs/08 §4.1."""

from __future__ import annotations

from .. import inputs as I
from ..context import FieldContext
from ..envelope import SUITES, seal
from ._common import ctx_json, suite_str, wrapper

SUITE = 0xFF01


def _ctx(**kw) -> FieldContext:
    base = dict(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                column_uuid=I.COLUMN_UUID, purpose="encrypt",
                tenant_id=I.TENANT_ID)
    base.update(kw)
    return FieldContext(**base)


# docs/08 §4.1 minimum coverage, one vector per named case, plus the
# maximum-context case G14 asks for.
CASES = [
    ("empty-plaintext", "empty", _ctx(), None),
    ("one-byte", "one-byte", _ctx(), None),
    ("basic-roundtrip", "ssn-9b", _ctx(), None),
    ("block-boundary", "block-boundary-16b", _ctx(), None),
    ("one-kib", "one-kib", _ctx(), None),
    ("utf8-multibyte", "utf8-multibyte", _ctx(), None),
    ("row-id-present", "ssn-9b", _ctx(row_id=I.ROW_ID), None),
    ("tenant-absent", "ssn-9b", _ctx(tenant_id=None), None),
    ("max-context", "ssn-9b",
     _ctx(tenant_id=I.TENANT_ID_2000B, row_id=I.ROW_ID_2000B), "G14"),
]


def generate() -> dict:
    vectors = []
    for slug, pt_name, ctx, provisional_on in CASES:
        pt = I.PLAINTEXTS[pt_name]
        # Every envelope context carries purpose="encrypt" -- spec §5.3
        # constrains record-key derivation to it, so an index purpose is not
        # expressible here at all. The maximum-length index-id belongs to the
        # context family, which is where it is covered; a vector here that
        # silently substituted an encrypt context would be a duplicate of
        # basic-roundtrip wearing a name that claims otherwise.
        assert ctx.purpose == "encrypt", slug
        vid = f"envelope/ff01/{slug}"
        seed = I.msg_seed_for(vid)
        nonce = I.nonce_for(vid, SUITES[SUITE]["nonce_len"])
        s = seal(SUITE, I.TENANT_DEK, I.KEY_ID, seed, nonce, ctx, pt)
        desc = (f"{len(pt)}-byte plaintext, "
                f"{'row_id present' if ctx.row_id else 'row_id absent'}")
        if provisional_on == "G14":
            desc += (" -- 2000-byte tenant_id and row_id: the envelope the "
                     "TypeScript core could not open on 2026-08-22 because "
                     "node:crypto caps HKDF info at 1024 bytes. Retires if "
                     "G14 adopts a bound below it")
        vec = {
            "id": vid,
            "description": desc,
            "spec_ref": "§3.1, §4.2, §5.3, §6.2, §6.3",
            "suite_id": suite_str(SUITE),
            "tenant_dek": I.TENANT_DEK.hex(),
            "key_id": I.KEY_ID.hex(),
            "msg_seed": seed.hex(),
            "nonce": nonce.hex(),
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
        }
        if provisional_on:
            vec["provisional_on"] = [provisional_on]
        vectors.append(vec)

    # Per-vector seeds and nonces are the point of inputs.msg_seed_for: no two
    # envelope vectors may share a (record_key, nonce) pair. Checked here so
    # the property cannot regress silently.
    pairs = {(v["intermediates"]["record_key"], v["nonce"]) for v in vectors}
    assert len(pairs) == len(vectors), "record_key/nonce pair reused"
    return wrapper("envelope", vectors)
