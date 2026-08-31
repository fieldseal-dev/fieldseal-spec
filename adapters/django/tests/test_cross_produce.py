"""A local guard on the cross-language producer (`tests/cross_produce.py`).

The real cross-language leg runs in CI, where a **TypeScript** core decrypts
what Django wrote. That needs Node, so it does not run here. What runs here is
the half that catches the producer breaking: the file is a well-formed
`cross/v1` document, and a core client built independently from the shared
key file decrypts every case.

Independently matters. The producer's own client is configured through
`FIELDSEAL`; the client below is built straight from `vectors/keys/`, so a
case only passes if the adapter's stored bytes are readable from the key
material alone -- which is what a consumer in another language has.

The producer runs in a subprocess because it calls `settings.configure()`,
which cannot run inside an already-configured Django process.
"""

from __future__ import annotations

import json
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

ADAPTER = Path(__file__).resolve().parents[1]
REPO = ADAPTER.parents[1]
H = bytes.fromhex


@pytest.fixture(scope="module")
def produced(tmp_path_factory):
    out = tmp_path_factory.mktemp("cross") / "cross-django.json"
    result = subprocess.run(
        [sys.executable, str(ADAPTER / "tests" / "cross_produce.py"),
         "--out", str(out)],
        cwd=ADAPTER, capture_output=True, text=True,
        env={"PYTHONPATH": str(ADAPTER), "PYTHONIOENCODING": "utf-8",
             "PATH": __import__("os").environ.get("PATH", ""),
             "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")},
    )
    assert result.returncode == 0, result.stderr
    return json.loads(out.read_text("utf-8"))


def test_it_is_a_wellformed_cross_document(produced):
    """The schema is the point: every existing consumer reads this file
    unmodified, so the adapter joins the N x N matrix as one more producer
    rather than needing a bespoke checker."""
    # v2 because it carries the index half. A producer emitting index cases
    # MUST say so: a v1-era consumer handed a v2 document would decrypt every
    # envelope, report `fail: 0`, and never touch the indexes.
    assert produced["schema"] == "fieldseal-vectors/cross/v2"
    assert produced["producer"]["implementation"] == "django"
    assert produced["cases"]


def test_every_case_decrypts_from_the_shared_key_material_alone(produced):
    """What a consumer in another language actually has: the envelope bytes,
    the caller-side context, and a `key_ref` into the public key file."""
    from fieldseal import FieldContext, Fieldseal
    from fieldseal.errors import FieldsealWarning
    from fieldseal.keyprovider import StaticKeyProvider

    keys = json.loads(
        (REPO / "vectors" / "keys" / "test-keys.json").read_text("utf-8"))["keys"]

    for case in produced["cases"]:
        key = keys[case["key_ref"]]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FieldsealWarning)
            client = Fieldseal(
                key_provider=StaticKeyProvider(
                    H(key["key_id"]), H(key["tenant_dek"]),
                    H(key["tenant_index_key"])),
                allowed_suites={int(key["suite_id"], 16)},
                write_suite=int(key["suite_id"], 16),
                arm_provisional_suites=True,
            )
        c = case["context"]
        ctx = FieldContext(
            table_uuid=H(c["table_uuid"]), column_uuid=H(c["column_uuid"]),
            purpose=c["purpose"],
            tenant_id=None if c["tenant_id"] is None else H(c["tenant_id"]),
            row_id=None if c["row_id"] is None else H(c["row_id"]),
        )
        got = client.decrypt(H(case["envelope"]), ctx)
        assert got == H(case["plaintext"]), case["id"]


def test_every_index_case_derives_from_the_shared_key_material_alone(produced):
    """The half `docs/07` §7 calls the more valuable one.

    A mismatched blind index is a **silent lookup miss**: the row is stored,
    decryptable, and simply stops being findable, so nothing in the envelope
    half would notice. What a consumer has is the declaration, the context and
    a `key_ref` -- so that is all this rebuilds from, and the declaration comes
    from the model's own `BlindIndex(...)` rather than being restated here.
    """
    import warnings

    from fieldseal import CardinalityOverride, FieldContext, Fieldseal, IndexDeclaration
    from fieldseal.errors import FieldsealWarning
    from fieldseal.keyprovider import StaticKeyProvider

    keys = json.loads(
        (REPO / "vectors" / "keys" / "test-keys.json").read_text("utf-8"))["keys"]

    assert produced["index_cases"], "no index cases emitted"
    for case in produced["index_cases"]:
        key = keys[case["key_ref"]]
        d, c = case["declaration"], case["context"]
        override = d.get("unindexable_override")
        decl = IndexDeclaration(
            table_uuid=H(c["table_uuid"]), column_uuid=H(c["column_uuid"]),
            index_id=d["index_id"], idf=d["idf"], normalize=d["normalize"],
            truncate_bits=d["truncate_bits"],
            projected_population=d["projected_population"],
            on_unindexable=d["on_unindexable"],
            unindexable_override=None if override is None
            else CardinalityOverride(reason=override["reason"],
                                     approved_by=override["approved_by"],
                                     date=override["date"]),
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FieldsealWarning)
            client = Fieldseal(
                key_provider=StaticKeyProvider(
                    H(key["key_id"]), H(key["tenant_dek"]),
                    H(key["tenant_index_key"])),
                allowed_suites={int(key["suite_id"], 16)},
                write_suite=int(key["suite_id"], 16),
                indexes=[decl], arm_provisional_suites=True,
            )
        ctx = FieldContext(
            table_uuid=H(c["table_uuid"]), column_uuid=H(c["column_uuid"]),
            purpose=c["purpose"],
            tenant_id=None if c["tenant_id"] is None else H(c["tenant_id"]),
            # Read, not assumed: every index case is row_id-absent today, and
            # hardcoding `None` would keep passing on the day one is not,
            # against a context the producer never used (#103 review).
            row_id=None if c["row_id"] is None else H(c["row_id"]),
        )
        # docs/08 §4.7's MUST, asserted here as the consumers assert it.
        assert c["purpose"] == f"index:{d['index_id']}", case["id"]
        got = (client.unindexable_marker(ctx) if case.get("value_marker")
               else client.blind_index(case["value_text"], ctx))
        assert got.hex() == case["index"], case["id"]


def test_the_adapter_stores_the_marker_for_a_refused_value_unasked(produced):
    """The case only an adapter can produce.

    Nothing in the write asked for a marker: the field derived it because
    `Person.legal_name` declares `on_unindexable="bucket"` and U+0378 is
    unassigned in every published Unicode version. A core alone cannot
    demonstrate this -- it has no column declaration and no write path.
    """
    marker = next(c for c in produced["index_cases"] if c.get("value_marker"))
    assert marker["declaration"]["on_unindexable"] == "bucket"
    assert marker["index"], "the marker case carries no index value"
    assert "value_text" not in marker
    # docs/09 §7.2 gates bucket mode behind a recorded approval, and a consumer
    # cannot construct the client without it.
    assert marker["declaration"]["unindexable_override"]


def test_the_fold_pair_lands_on_one_index_value(produced):
    """`nfc-casefold-v1` MUST merge them, and spec §7.5's re-verification rule
    is built on its doing so. Two rows written through the ORM in different
    cases, one index value."""
    by_id = {c["id"].rsplit("/", 1)[-1]: c for c in produced["index_cases"]}
    lower, upper = by_id["email-exact"], by_id["email-fold"]
    assert lower["value_text"] != upper["value_text"]
    assert lower["index"] == upper["index"]


def test_it_declares_the_context_shapes_it_cannot_produce(produced):
    """docs/08 §4.7: an adapter producer's coverage axis is the decisions it
    owns, and the shapes it structurally cannot reach are declared rather than
    left absent -- so `row_id`-present is a stated gap that closes itself the
    day L3-row ships, not a silence."""
    shapes = [x["shape"] for x in produced["producer"].get("limitations", [])]
    assert "row_id-present" in shapes


def test_it_covers_the_decisions_no_core_test_reaches(produced):
    """Three things between an application value and the stored column belong
    to the adapter: the codec's rendering, the storage form, and context
    assembly. A case list that lost any of them would still pass every
    assertion above."""
    ids = {c["id"].rsplit("/", 1)[-1] for c in produced["cases"]}
    assert "non-text-integer" in ids   # the codec decides IntegerField -> b"45"
    assert "text-non-ascii" in ids     # UTF-8, not an ASCII-only accident
    assert "tenant-bound" in ids       # context from the contextvar
    assert "text-empty" in ids         # a value, not an absence


def test_the_integer_case_pins_the_codecs_rendering(produced):
    """`IntegerField(45)` becoming `b"45"` is an adapter decision. A consumer
    that expected an integer encoding would decrypt successfully and read the
    wrong value -- which is why the expected plaintext is asserted here rather
    than only round-tripped."""
    case = next(c for c in produced["cases"]
                if c["id"].endswith("non-text-integer"))
    assert H(case["plaintext"]) == b"45"


def test_envelopes_differ_between_runs(produced, tmp_path):
    """Spec §4.4: a fresh nonce and msg_seed on every write. The producer uses
    the real path -- runtime CSPRNG, no test-mode injection -- so two runs
    that agreed would mean it had drifted onto the injection seam."""
    out = tmp_path / "second.json"
    result = subprocess.run(
        [sys.executable, str(ADAPTER / "tests" / "cross_produce.py"),
         "--out", str(out)],
        cwd=ADAPTER, capture_output=True, text=True,
        env={"PYTHONPATH": str(ADAPTER), "PYTHONIOENCODING": "utf-8",
             "PATH": __import__("os").environ.get("PATH", ""),
             "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")},
    )
    assert result.returncode == 0, result.stderr
    second = json.loads(out.read_text("utf-8"))
    first_envs = [c["envelope"] for c in produced["cases"]]
    second_envs = [c["envelope"] for c in second["cases"]]
    assert first_envs != second_envs
    # ...but the plaintexts must be identical, or the two runs are not
    # comparable and the assertion above proves nothing.
    assert ([c["plaintext"] for c in produced["cases"]]
            == [c["plaintext"] for c in second["cases"]])
