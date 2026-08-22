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
    suite', which is a different statement (docs/14 §4)."""
    for h in REPORT["held_out"]:
        assert h["status"] == "not-run"
    assert any(h["path"] == "blind-index/argon2id.json"
               for h in REPORT["held_out"])


def test_l0_not_claimed_against_a_frozen_format():
    """The suite is provisional (spec §4.8), so a green run must still say so
    -- otherwise the report reads as conformance to a format nobody froze."""
    assert REPORT["provisional_suites"] is True
    assert REPORT["vector_suite_version"].endswith("-provisional")
