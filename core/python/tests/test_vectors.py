"""pytest wrapper around the vector harness."""

from __future__ import annotations

import pytest
from run_vectors import run

REPORT = run()


@pytest.mark.parametrize(
    "result", REPORT["results"], ids=[r["id"] for r in REPORT["results"]])
def test_vector(result):
    assert result["status"] == "pass", result.get("reason", "")


def test_held_out_families_are_not_run():
    """A held-out family must be reported as not-run, never as passed or
    skipped -- 'skipped' already means 'this implementation does not claim that
    suite', which is a different statement (docs/14 §4).

    The suite holds nothing out as of 0.6.0-provisional, so this guards the
    rule rather than a case. It used to also assert that
    `blind-index/argon2id.json` was the held-out family; that assertion is now
    `test_argon2id_family_is_pinned_and_run` below, which is the same fact
    from the other side.
    """
    for h in REPORT["held_out"]:
        assert h["status"] == "not-run"


def test_argon2id_family_is_pinned_and_run():
    """Argon2id is derived and counted, not merely present.

    The family was held out of the suite until 2026-08-31 (docs/07 §7), which
    meant this core's harness never derived an Argon2id index -- it refused
    anything but HMAC. A report that counted the file without running it, or a
    harness that quietly fell back to HMAC, would both look green here, so
    assert on derived results rather than on the manifest.
    """
    ids = {r["id"] for r in REPORT["results"] if r["status"] == "pass"}
    argon2 = {i for i in ids if i.startswith("blind-index/argon2id/")}
    assert argon2, "no Argon2id vector was run"
    # The assertion shapes are the ones the hold-out hid: they carried no
    # idf_params until the family was promoted, and both cores treat a missing
    # cost as malformed rather than as "the minimum" (docs/08 §4.4, #62).
    assert any(i.endswith("/unindexable-marker-b15") for i in argon2)
    assert any(i.endswith("/unindexable-bucketed-b15") for i in argon2)
    assert not REPORT["held_out"]


def test_l0_not_claimed_against_a_frozen_format():
    """The suite is provisional (spec §4.8), so a green run must still say so
    -- otherwise the report reads as conformance to a format nobody froze."""
    assert REPORT["provisional_suites"] is True
    assert REPORT["vector_suite_version"].endswith("-provisional")


def test_no_two_vectors_share_an_expected_envelope():
    """A vector whose expected output duplicates another's tests nothing while
    reporting as a passing case, and inflates the count into implying breadth
    the suite does not have. envelope/ff01/purpose-max-index-id was exactly
    that until 2026-08-22."""
    import json

    from run_vectors import VECTORS
    doc = json.loads((VECTORS / "envelope" / "ff01.json").read_text("utf-8"))
    seen: dict[str, str] = {}
    for v in doc["vectors"]:
        env = v["expected"]["envelope"]
        assert env not in seen, f"{v['id']} duplicates {seen.get(env)}"
        seen[env] = v["id"]

def test_carries_every_pinned_decision_key_docs14_requires():
    """docs/14 §4 fixes the key set so two reports can be diffed key by key.
    The TypeScript harness has asserted this since G15; the Python one did
    not, which is how a report could have drifted a key without any test
    noticing (G17, issue #67)."""
    for key in ("decrypt-order", "aad-mismatch", "api-boundary-order",
                "unimplemented-registered-suite", "commitment-construction",
                "key-material-ownership"):
        assert REPORT["pinned_decisions"].get(key), key


def test_does_not_declare_decisions_the_spec_has_taken_over():
    """G15 (#48) closed these four into the text; a report still declaring one
    would misreport the core as making a choice it no longer makes."""
    for key in ("unknown-format-version-set", "provisional-arming",
                "rotate-in-permissive", "normalizer-text-over-bytes"):
        assert key not in REPORT["pinned_decisions"], key
