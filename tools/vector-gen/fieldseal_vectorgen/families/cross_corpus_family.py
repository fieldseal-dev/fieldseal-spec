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

**Two halves.** `cases` are envelope cases: encrypt, then every consumer
decrypts and compares plaintext. `index_cases` are the other half of the same
claim and the more valuable one -- a blind index derived by one implementation
must be derived byte-identically by every other, because a mismatched index is
a **silent lookup miss** rather than an error. Nothing raises; the row simply
stops being findable. That is the failure the envelope half cannot catch, and
it is why `docs/07` §7 recorded the index half as the next increment.

An index case carries a `declaration` block rather than the flat fields the
pinned `blind-index/` family uses. The reason is that a cross producer derives
through a **constructed client**, not through primitives, so the consumer must
be able to build a declaration that `validate_index_declaration` accepts --
which needs `projected_population`, `on_unindexable` and any override ceremony,
none of which affect a derived byte and all of which gate construction.
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


def _idx_ctx(index_id: str, column: bytes, tenant: bytes | None) -> dict:
    return {
        "table_uuid": I.TABLE_UUID.hex(),
        "column_uuid": column.hex(),
        "tenant_id": None if tenant is None else tenant.hex(),
        "row_id": None,
        "purpose": f"index:{index_id}",
    }


def _decl(index_id: str, normalize: str, bits: int, population: int,
          on_unindexable: str = "refuse") -> dict:
    d = {
        "index_id": index_id,
        "idf": "hmac-sha512",
        "idf_params": {},
        "normalize": normalize,
        "truncate_bits": bits,
        "projected_population": population,
        "on_unindexable": on_unindexable,
    }
    if on_unindexable == "bucket":
        # docs/09 §7.2 gates bucket mode behind the same recorded approval
        # spec §7.6 requires for a cardinality override. Without it the
        # declaration is refused at construction, so a consumer could not
        # build the client this case needs -- which is exactly why the
        # ceremony travels with the declaration rather than being assumed.
        d["unindexable_override"] = {
            "reason": "Cross corpus: exercises the §7.2 reserved marker.",
            "approved_by": "tools/vector-gen",
            "date": "2026-08-31",
        }
    return d


#: Index cases. Every one is `hmac-sha512`: `argon2id` joins when
#: `blind-index/argon2id.json` leaves `MANIFEST.held_out`, because a cross job
#: asserting Argon2id agreement on every merge while the manifest says the
#: suite deliberately does not count that family would have the two saying
#: different things about the same primitive. `idf_params` is present and empty
#: so the slot exists the day it does.
def _index_cases() -> list[tuple]:
    a = "tenant-a-dek-v1"
    t = I.TENANT_ID
    C, CB = I.COLUMN_UUID, I.COLUMN_UUID_B

    exact = _decl("exact", "nfc-casefold-v1", 15, 100_000)
    # A wider truncation, so a divergence has more than two bytes to show
    # itself in. §7.4's band (2 <= P*2^-b < sqrt(P)) forces the population up
    # with the width: at b=30 it needs P >= 2^31.
    wide = _decl("wide", "nfc-casefold-v1", 30, 5_000_000_000)
    raw = _decl("raw", "identity", 15, 100_000)
    digits = _decl("digits", "digits-only-v1", 15, 100_000)
    bucketed = _decl("bucketed", "nfc-casefold-v1", 15, 100_000, "bucket")

    return [
        # The workhorse, and a non-ASCII value: a core whose UTF-8 handling
        # differed would pass the ASCII case and fail this one.
        ("exact-ascii", a, exact, _idx_ctx("exact", C, t), {"value_text": "alice@example.com"}),
        ("exact-non-ascii", a, exact, _idx_ctx("exact", C, t), {"value_text": "grüße@example.com"}),
        # The fold pair. `nfc-casefold-v1` MUST land these on one index value,
        # and spec §7.5's re-verification rule is built on their doing so.
        # Checked transitively -- each side is derived and compared against the
        # producer's value, so agreement on both *is* agreement that they
        # match. No `assertion: equal` field: the pinned `blind-index/` family
        # needs one because it compares two vectors inside one file, and this
        # family compares every case against another implementation instead.
        ("fold-pair-lower", a, exact, _idx_ctx("exact", C, t), {"value_text": "ada@example.com"}),
        ("fold-pair-upper", a, exact, _idx_ctx("exact", C, t), {"value_text": "ADA@EXAMPLE.COM"}),
        # The G19 pair: precomposed U+00E9 against decomposed e + U+0301. NFC
        # collapses them, and a core folding before composing would not.
        ("nfc-pair-composed", a, exact, _idx_ctx("exact", C, t), {"value_text": "caf\u00e9@example.com"}),
        ("nfc-pair-decomposed", a, exact, _idx_ctx("exact", C, t), {"value_text": "cafe\u0301@example.com"}),
        # No tenant: the index key is a *sibling* of the tenant DEK (spec
        # §5.2), so the tenantless scope is a different key, not a missing one.
        ("exact-tenant-absent", a, exact, _idx_ctx("exact", C, None), {"value_text": "alice@example.com"}),
        # A wider index on the same column, which is a different registry entry
        # (table + column + index_id) and therefore a different derivation.
        ("wide-b30", a, wide, _idx_ctx("wide", C, t), {"value_text": "alice@example.com"}),
        # `identity` takes the bytes as they are: no normalization, so this is
        # the case where the value is given as bytes rather than as text.
        ("identity-bytes", a, raw, _idx_ctx("raw", CB, t), {"value_bytes": b"\x00\x01\xfe\xff".hex()}),
        # `digits-only-v1`, the third registry normalizer. Added in the #103
        # review round: docs/08 §4.7's own new rule asks for one case per
        # normalizer the producer supports, and the corpus covered two of
        # three -- the cores violated the rule this change introduced. The
        # value carries separators the normalizer strips, so a core that
        # skipped the stripping would derive differently.
        ("digits-only", a, digits, _idx_ctx("digits", CB, t), {"value_text": "+1 (555) 010-9999"}),
        # The §7.2 reserved marker -- a derivation with no plaintext at all.
        # The consumer calls `unindexable_marker(ctx)`, not `blind_index`.
        ("bucket-marker", a, bucketed, _idx_ctx("bucketed", CB, t), {"value_marker": True}),
    ]


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

    index_cases = _index_cases()
    assert len({c[0] for c in index_cases}) == len(index_cases)
    # Every declaration a producer must register, keyed as the core keys it
    # (table + column + index_id). Two cases may share one entry -- the fold
    # pair does -- but two entries with one key and different parameters would
    # be a registry collision the producer could not build.
    by_key: dict[tuple, dict] = {}
    for _slug, _ref, decl, ctx, _val in index_cases:
        key = (ctx["table_uuid"], ctx["column_uuid"], decl["index_id"])
        if by_key.setdefault(key, decl) != decl:
            raise AssertionError(
                "conflicting declarations for "
                f"{key[0]}/{key[1]}/{key[2]} -- two index cases share a "
                "registry key and disagree about its parameters")
        assert ctx["purpose"] == f"index:{decl['index_id']}", (
            f"{_slug}: purpose and index_id disagree")

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
            "envelopes every other implementation must decrypt. "
            "`index_cases` are the other half: a producer registers each "
            "`declaration` on its client and derives the index through its "
            "production path, and every consumer re-derives and compares "
            "byte-exact -- a mismatched index is a silent lookup miss, not an "
            "error, so nothing else in the matrix would notice."
        ),
        "cases": [
            {"case": slug, "key_ref": ref, "context": ctx,
             "plaintext": pt.hex()}
            for slug, ref, ctx, pt in cases
        ],
        "index_cases": [
            {"case": slug, "key_ref": ref, "declaration": decl,
             "context": ctx, **val}
            for slug, ref, decl, ctx, val in index_cases
        ],
    }
