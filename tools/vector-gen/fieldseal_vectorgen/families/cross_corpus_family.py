"""`cross/corpus.json` -- the shared input corpus for cross producers
(docs/08 §4.7, docs/14 §3).

Inputs only: key refs, contexts, plaintexts. No expected values and no
envelopes -- each implementation produces those through its REAL production
path (runtime CSPRNG, no injection), so a producer's output differs on every
run and is checked by every consumer decrypting it, not by comparing bytes to
this file. Listed under `MANIFEST.support`; never iterated by a harness.

One definition, consumed by every producer, so the corpus cannot drift
between languages. docs/08 §4.7 asks for at least 16 cases spanning §4.1's
size and shape coverage plus every context shape.
"""

from __future__ import annotations

from .. import inputs as I
from ..manifest import SPEC_VERSION, VECTOR_SUITE_VERSION
from ._common import suite_str

SUITE = 0xFF01


def _ctx(tenant: bytes | None, row: bytes | None) -> dict:
    return {
        "table_uuid": I.TABLE_UUID.hex(),
        "column_uuid": I.COLUMN_UUID.hex(),
        "tenant_id": None if tenant is None else tenant.hex(),
        "row_id": None if row is None else row.hex(),
        "purpose": "encrypt",
    }


def generate() -> dict:
    a, b = "tenant-a-dek-v1", "tenant-b-dek-v1"
    t, r = I.TENANT_ID, I.ROW_ID
    cases = []

    # §4.1 size coverage under the common shape (tenant present, row absent).
    for name, pt in I.PLAINTEXTS.items():
        cases.append((f"size-{name}", a, _ctx(t, None), pt))

    ssn = I.PLAINTEXTS["ssn-9b"]
    kib = I.PLAINTEXTS["one-kib"]
    # Context shapes.
    cases += [
        ("shape-row-present", a, _ctx(t, r), ssn),
        ("shape-row-present-one-kib", a, _ctx(t, r), kib),
        ("shape-tenant-absent", a, _ctx(None, None), ssn),
        ("shape-tenant-absent-row-present", a, _ctx(None, r), ssn),
        ("shape-tenant-zero-length", a, _ctx(b"", None), ssn),
        ("shape-tenant-zero-length-row-present", a, _ctx(b"", r), ssn),
        # The G14 lengths, through the production path.
        ("shape-tenant-row-255b", a, _ctx(I.TENANT_ID_255B, I.ROW_ID_255B), ssn),
        ("shape-max-context", a,
         _ctx(I.TENANT_ID_2000B, I.ROW_ID_2000B), ssn),
        # The second tenant, so cross-decryption exercises key resolution.
        ("key-tenant-b", b, _ctx(t, None), ssn),
        ("key-tenant-b-row-present", b, _ctx(t, r), ssn),
    ]
    assert len(cases) >= 16 and len({c[0] for c in cases}) == len(cases)
    return {
        "schema": "fieldseal-vectors/cross-corpus/v1",
        "vector_suite_version": VECTOR_SUITE_VERSION,
        "spec_version": SPEC_VERSION,
        "suite_id": suite_str(SUITE),
        "note": (
            "Producer inputs only (docs/08 §4.7). A producer encrypts every "
            "case through its production path -- runtime CSPRNG for msg_seed "
            "and nonce, no test-mode injection -- resolving key_ref against "
            "keys/test-keys.json, and emits cross/<impl> files whose "
            "envelopes every other implementation must decrypt."
        ),
        "cases": [
            {"case": slug, "key_ref": ref, "context": ctx,
             "plaintext": pt.hex()}
            for slug, ref, ctx, pt in cases
        ],
    }
