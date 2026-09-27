"""`context/canonical.json` -- the presence-bitmap cases of spec §6.2, the
boundary lengths of docs/08 §4.3, and the lengths G14 is about."""

from __future__ import annotations

from .. import declaration
from .. import inputs as I
from ..context import FieldContext, canonical_context
from ._common import ctx_json, suite_str, wrapper

SUITE = 0xFF01
MAX_INDEX_ID = "a" * 32


def _ctx(**kw) -> FieldContext:
    base = dict(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                column_uuid=I.COLUMN_UUID, purpose="encrypt")
    base.update(kw)
    return FieldContext(**base)


# (slug, description, context, provisional_on)
CASES = [
    ("both-absent", "neither optional field present", _ctx(), None),
    ("tenant-present", "tenant_id present, row_id absent",
     _ctx(tenant_id=I.TENANT_ID), None),
    ("both-present", "tenant_id and row_id both present",
     _ctx(tenant_id=I.TENANT_ID, row_id=I.ROW_ID), None),
    ("row-only", "row_id present without tenant_id",
     _ctx(row_id=I.ROW_ID), None),
    ("tenant-zero-length", "tenant_id present with zero length -- MUST differ "
     "from tenant-absent (gap G4)", _ctx(tenant_id=b""), "G4"),
    ("purpose-index", "purpose retargeted to an index (spec §7.2)",
     _ctx(tenant_id=I.TENANT_ID, purpose="index:email-eq"), None),
    ("purpose-max-index-id", "index-id at the §6.1 grammar's 32-char maximum",
     _ctx(tenant_id=I.TENANT_ID, purpose="index:" + MAX_INDEX_ID), None),
    # docs/08 §4.3 boundary lengths.
    ("tenant-1b", "tenant_id of 1 byte (docs/08 §4.3 boundary)",
     _ctx(tenant_id=I.TENANT_ID_1B), None),
    ("tenant-16b", "tenant_id of 16 bytes (docs/08 §4.3 boundary)",
     _ctx(tenant_id=I.TENANT_ID_16B), None),
    ("tenant-64b", "tenant_id of 64 bytes (docs/08 §4.3 boundary)",
     _ctx(tenant_id=I.TENANT_ID_64B), None),
    # The anti-forgery case that justifies length-prefixing (docs/08 §4.3).
    ("tenant-looks-like-length-prefix",
     "tenant_id whose trailing bytes read as a u64be length prefix followed "
     "by an 8-byte value; under §6.2 the field boundary is unambiguous",
     _ctx(tenant_id=I.TENANT_ID_FORGERY, row_id=I.ROW_ID), None),
    # G14: the proposed bound, and the length that split the cores.
    ("tenant-row-255b",
     "tenant_id and row_id each 255 bytes -- the bound G14 proposes "
     "(expected.length gives the resulting canonical_context size)",
     _ctx(tenant_id=I.TENANT_ID_255B, row_id=I.ROW_ID_255B), "G14"),
    ("tenant-row-2000b",
     "tenant_id and row_id each 2000 bytes -- above the 1024-byte HKDF info "
     "cap of node:crypto and Web Crypto; the length that split the cores on "
     "2026-08-22. Retires if G14 adopts a bound below it",
     _ctx(tenant_id=I.TENANT_ID_2000B, row_id=I.ROW_ID_2000B), "G14"),
    ("max-context-index",
     "the longest index-path context: 2000-byte tenant_id, row_id absent "
     "(spec §7.2), index-id at the 32-char maximum",
     _ctx(tenant_id=I.TENANT_ID_2000B, purpose="index:" + MAX_INDEX_ID),
     "G14"),
]


def generate() -> dict:
    vectors = []
    for slug, description, ctx, provisional_on in CASES:
        encoded = canonical_context(ctx)
        vec = {
            "id": f"context/canonical/{slug}",
            "description": description,
            "spec_ref": "§6.1, §6.2",
            "suite_id": suite_str(SUITE),
            "context": ctx_json(ctx),
            "expected": {
                "presence": ctx.presence(),
                "canonical_context": encoded.hex(),
                "length": len(encoded),
            },
        }
        if provisional_on:
            vec["provisional_on"] = [provisional_on]
        vectors.append(vec)

    # The G4 aliasing case, asserted as a relation rather than a value: the
    # thing that must hold is that these two are different, and a reader should
    # not have to diff two hex blobs to see that it is being checked. Both
    # inputs are carried (docs/18 D-08) so a core can reproduce each side.
    absent_ctx, zero_ctx = _ctx(), _ctx(tenant_id=b"")
    absent = canonical_context(absent_ctx)
    zero_len = canonical_context(zero_ctx)
    assert absent != zero_len, "G4 regression: absent aliases zero-length"
    vectors.append({
        "id": "context/canonical/absent-differs-from-zero-length",
        "description": "absent tenant_id and zero-length tenant_id MUST NOT "
                       "produce the same encoding (gap G4)",
        "spec_ref": "§6.2",
        "assertion": "distinct",
        "suite_id": suite_str(SUITE),
        "inputs": {"context_a": ctx_json(absent_ctx),
                   "context_b": ctx_json(zero_ctx)},
        "expected": {
            "tenant_absent": absent.hex(),
            "tenant_zero_length": zero_len.hex(),
            "must_be_equal": False,
        },
        "provisional_on": ["G4"],
    })
    vectors += declaration_vectors()
    return wrapper("context", vectors)


# Spec §12 and docs/08 §4.3 (G11, #210): index declarations whose identifier
# breaks the §6.1 grammar are refused when declared. Each is otherwise valid
# (P = 2^20, b = 16 sits inside the §7.4 band and clears the §7.6 gate), so
# the identifier is the only thing wrong. The 32-character twin is accepted:
# without it, a core that refused every declaration would pass all four.
_DECL_P, _DECL_B = 1 << 20, 16
IDENTIFIER_CASES = [
    ("index-id-uppercase", "Exact",
     "index:Exact -- uppercase is outside [a-z0-9-]"),
    ("index-id-non-ascii", "é",
     "index:é -- U+00E9, two UTF-8 bytes C3 A9, outside the ASCII "
     "grammar"),
    ("index-id-empty", "",
     "index: -- the grammar requires at least one character"),
    ("index-id-33-bytes", "a" * 33,
     "a 33-byte identifier -- one past the grammar's 32-byte maximum"),
]


def declaration_vectors() -> list[dict]:
    out = []
    for slug, index_id, why in IDENTIFIER_CASES:
        out.append(declaration.vector(
            f"context/canonical/{slug}",
            f"index declaration refused at declaration time: {why} "
            "(configuration refusal, no §9 code)",
            "§6.1, §7.2, §12",
            declaration.Declaration(index_id=index_id,
                                    projected_population=_DECL_P,
                                    truncate_bits=_DECL_B),
            "refused", "§6.1 index-id"))
    out.append(declaration.vector(
        "context/canonical/index-id-32-bytes-accepted",
        "index declaration with a 32-byte identifier, the grammar's maximum, "
        "is accepted -- the positive twin of index-id-33-bytes",
        "§6.1, §7.2",
        declaration.Declaration(index_id=MAX_INDEX_ID,
                                projected_population=_DECL_P,
                                truncate_bits=_DECL_B),
        "accepted", None))
    return out
