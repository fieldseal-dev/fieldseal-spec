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
    # A vector off the minima is the only one that can tell a harness that
    # derives at the declared cost from one that derives at its default and
    # happens to agree (docs/08 §4.4; the #108 review caught the TypeScript
    # marker check doing exactly that). Both raised-cost shapes, and the
    # primitive's #pipeline companion, must be present and passing.
    assert any(i.endswith("/raised-cost-t4-b15") for i in argon2)
    assert any(i.endswith("/raised-cost-t4-b15#pipeline") for i in argon2)
    assert any(i.endswith("/unindexable-marker-t4-b15") for i in argon2)
    assert not REPORT["held_out"]


def test_harness_notes_do_not_contradict_the_results():
    """The #108 review found the TypeScript report describing
    `blind-index/argon2id.json` as held out and not iterated while listing
    30 of its results as passing: `harness_notes` is emitted verbatim
    (docs/14 §4) and nothing asserted on it. A note that names a file whose
    vectors appear in `results` may not say the file was held out or not run.
    """
    import re

    ran = {"/".join(r["id"].split("/")[:2]) for r in REPORT["results"]}
    for note in REPORT["harness_notes"]:
        for fam in re.findall(r"([\w-]+/[\w-]+)\.json", note):
            if fam in ran:
                assert not re.search(
                    r"held out|held-out|not-run|not iterated", note, re.I), note


def test_argon2_params_reads_the_vector_not_the_core():
    """`_argon2_params` is where docs/08 §4.4's rule lives for this core.
    Three things the #108 reviewers asked to see pinned rather than inferred
    from a green run: an HMAC vector's empty `idf_params` yields no Argon2
    parameters at all; a missing cost is an error naming the key, not a bare
    KeyError; and a vector declaring a `version`, `parallelism` or
    `output_len` other than §7.3's is refused rather than silently derived
    at the constant."""
    from run_vectors import _argon2_params

    assert _argon2_params({"idf": "hmac-sha512", "idf_params": {}}) is None
    with pytest.raises(KeyError, match="idf_params.time_cost"):
        _argon2_params({"idf": "argon2id"})
    with pytest.raises(KeyError, match="idf_params.time_cost"):
        _argon2_params({"idf": "argon2id", "idf_params": {"time_cost": 3}})
    ok = _argon2_params({"idf": "argon2id",
                         "idf_params": {"time_cost": 4, "memory_kib": 32768,
                                        "version": 19, "parallelism": 1,
                                        "output_len": 64}})
    assert ok is not None and (ok.time_cost, ok.memory_kib) == (4, 32768)
    with pytest.raises(ValueError, match="parallelism"):
        _argon2_params({"idf": "argon2id",
                        "idf_params": {"time_cost": 3, "memory_kib": 32768,
                                       "parallelism": 2}})


def test_a_vector_the_harness_cannot_derive_is_a_recorded_failure(monkeypatch):
    """The #108 review stripped `idf_params` from the eight Argon2id
    assertion vectors in a copy of the suite: the TypeScript harness recorded
    eight failures and emitted its report; this one aborted with
    `KeyError('idf_params')` and emitted nothing -- no artifact for the CI
    gate. `run_blind_index` now has the per-vector boundary `run_envelope`
    and `run_errors` already had. The same boundary is what keeps the
    `argon2` extra from being a hard dependency of the *report* (a green one
    still needs it): without it, `run()` raised ModuleNotFoundError from
    inside the core and this module errored at collection."""
    import json

    import run_vectors
    from run_vectors import VECTORS, run_blind_index

    doc = json.loads(
        (VECTORS / "blind-index" / "argon2id.json").read_text("utf-8"))
    marker = next(v for v in doc["vectors"]
                  if v["id"].endswith("/unindexable-marker-b15"))
    malformed = json.loads(json.dumps(marker))
    del malformed["inputs"]["idf_params"]
    results: list[dict] = []
    run_blind_index({"vectors": [malformed]}, results)
    assert [(r["id"], r["status"]) for r in results] == [
        (marker["id"], "fail")]
    assert "idf_params" in results[0]["reason"]

    primitive = next(v for v in doc["vectors"] if "assertion" not in v)

    def no_argon2(*_a, **_k):
        raise ModuleNotFoundError("No module named 'argon2'", name="argon2")

    monkeypatch.setattr(run_vectors, "idf", no_argon2)
    results = []
    run_blind_index({"vectors": [primitive]}, results)
    assert {r["id"]: r["status"] for r in results} == {
        primitive["id"]: "fail", primitive["id"] + "#pipeline": "fail"}
    assert all("argon2 extra" in r["reason"] for r in results)


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
