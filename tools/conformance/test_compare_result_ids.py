"""Guards in the cross-core result-id comparison (docs/08 §9; #114 review item 10).

Each guard was verified by hand when the job was written, and a guard nobody
exercises is one a refactor can delete silently. Every test starts from a pair
of synthetic reports that agree, confirms the baseline passes, then breaks one
thing and asserts the finding it should produce.

Runs without pytest and without either core:

    python tools/conformance/test_compare_result_ids.py

Pytest can also collect it, since every check is a `test_*` function.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import sys
import tempfile
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import compare_result_ids as c  # noqa: E402

MANIFEST = {"files": [{"path": "blind-index/hmac-sha512.json"}, {"path": "envelope/aes-gcm.json"}]}
SYNC = [
    "blind-index/hmac-sha512/bi-001",
    "blind-index/hmac-sha512/bi-002",
    "envelope/aes-gcm/env-001",
    # A composed id: the async twin appends the suffix after '#decrypt'.
    "envelope/aes-gcm/env-001#decrypt",
]
OOB = ["oob/length-bound", "oob/surrogate-refusal"]


def report(sync: list[str] = SYNC, twins: bool = True) -> dict[str, Any]:
    ids = list(sync) + ([i + c.ASYNC for i in sync] if twins else [])
    return {
        "results": [{"id": i, "status": "pass"} for i in ids],
        "out_of_band": [{"id": o, "status": "pass"} for o in OOB],
        "async_companions": twins,
    }


def pair() -> dict[str, Any]:
    return {"python": report(), "typescript": report()}


def findings(reports: dict[str, Any], manifest: dict[str, Any] = MANIFEST) -> list[str]:
    return c.compare(reports, manifest)[0]


def expect(reports: dict[str, Any], *fragments: str, manifest: dict[str, Any] = MANIFEST) -> None:
    fail = findings(reports, manifest)
    assert fail, "expected a finding, the comparison passed"
    for frag in fragments:
        assert any(frag in f for f in fail), f"no finding contains {frag!r}; got {fail}"


def drop(r: dict[str, Any], prefix: str) -> None:
    r["results"] = [x for x in r["results"] if not x["id"].startswith(prefix)]


# --------------------------------------------------------------------------
# the baseline: without it every test below could pass for the wrong reason
# --------------------------------------------------------------------------

def test_agreeing_reports_pass() -> None:
    fail, log = c.compare(pair(), MANIFEST)
    assert fail == [], fail
    assert any("identical: 4 synchronous result ids" in line for line in log), log


def test_agreeing_reports_without_async_pass() -> None:
    assert findings({"python": report(twins=False), "typescript": report(twins=False)}) == []


# --------------------------------------------------------------------------
# one report on its own
# --------------------------------------------------------------------------

def test_unreadable_report() -> None:
    r = pair()
    r["typescript"] = json.JSONDecodeError("Expecting value", "", 0)
    expect(r, "typescript: report unreadable (JSONDecodeError")


def test_report_missing_a_key() -> None:
    r = pair()
    del r["python"]["out_of_band"]
    expect(r, "python: report unreadable (KeyError")


def test_duplicate_id_masking_a_dropped_one() -> None:
    # Same result count as the other core, one id repeated in place of one
    # missing: anything counting results would call these equal.
    r = pair()
    res = r["python"]["results"]
    victim = next(x for x in res if x["id"] == "blind-index/hmac-sha512/bi-002")
    victim["id"] = "blind-index/hmac-sha512/bi-001"
    assert len(res) == len(r["typescript"]["results"])
    expect(r, "python: duplicate result ids: ['blind-index/hmac-sha512/bi-001']",
           "1 id(s) only typescript ran: ['blind-index/hmac-sha512/bi-002']")


def test_skipped_result_is_a_finding() -> None:
    r = pair()
    r["python"]["results"][0]["status"] = "skipped"
    expect(r, "python: 1 skipped result(s)")


def test_both_cores_skipping_the_same_family_is_not_agreement() -> None:
    r = pair()
    for name in c.CORES:
        for x in r[name]["results"]:
            if x["id"].startswith("envelope/"):
                x["status"] = "skipped"
    expect(r, "python: 4 skipped", "typescript: 4 skipped",
           "python: manifest files with no result at all: ['envelope/aes-gcm.json']")


def test_partial_second_pass() -> None:
    r = pair()
    r["typescript"]["results"] = [x for x in r["typescript"]["results"]
                                  if x["id"] != "envelope/aes-gcm/env-001#decrypt" + c.ASYNC]
    expect(r, "typescript: async_companions is true but 1 first-pass result(s) have no twin: "
              "['envelope/aes-gcm/env-001#decrypt']")
    # And the synchronous comparison alone could not have seen it.
    assert not any("only" in f for f in findings(r))


def test_flag_true_with_no_async_results() -> None:
    r = pair()
    r["python"] = report(twins=False)
    r["python"]["async_companions"] = True
    expect(r, "python: async_companions is true but the report carries no '#async' results")


def test_flag_false_with_async_results() -> None:
    r = pair()
    r["python"]["async_companions"] = False
    expect(r, "python: async_companions is false but the report carries 4 '#async' results")


def test_out_of_band_not_passing() -> None:
    r = pair()
    r["typescript"]["out_of_band"][1]["status"] = "fail"
    expect(r, "typescript: out-of-band entries not passing: ['oob/surrogate-refusal']")


# --------------------------------------------------------------------------
# the two reports against each other and the manifest
# --------------------------------------------------------------------------

def test_one_core_drops_a_family() -> None:
    r = pair()
    drop(r["typescript"], "blind-index/")
    expect(r, "2 id(s) only python ran", "typescript: manifest files with no result at all")


def test_both_cores_drop_the_same_family() -> None:
    # The case two-report comparison cannot see: the id sets still agree.
    r = pair()
    for name in c.CORES:
        drop(r[name], "envelope/")
    fail = findings(r)
    assert not any("only" in f for f in fail), fail
    expect(r, "python: manifest files with no result at all: ['envelope/aes-gcm.json']",
           "typescript: manifest files with no result at all: ['envelope/aes-gcm.json']")


def test_both_cores_run_nothing() -> None:
    empty = {"results": [], "out_of_band": [], "async_companions": False}
    expect({"python": empty, "typescript": copy.deepcopy(empty)},
           "a synchronous id set is empty (python 0, typescript 0)")


def test_out_of_band_divergence() -> None:
    r = pair()
    r["python"]["out_of_band"].append({"id": "oob/python-only", "status": "pass"})
    expect(r, "out-of-band ids differ between cores: ['oob/python-only']")


def test_manifest_prefix_needs_the_slash() -> None:
    # 'envelope/aes-gcm-siv/...' must not count as reaching 'envelope/aes-gcm.json'.
    manifest = {"files": MANIFEST["files"] + [{"path": "envelope/aes-gcm-siv.json"}]}
    r = pair()
    for name in c.CORES:
        r[name]["results"].append({"id": "envelope/aes-gcm-sivX/env-001", "status": "pass"})
        r[name]["results"].append({"id": "envelope/aes-gcm-sivX/env-001" + c.ASYNC, "status": "pass"})
    expect(r, "manifest files with no result at all: ['envelope/aes-gcm-siv.json']", manifest=manifest)


# --------------------------------------------------------------------------
# the entry point the workflow calls, against files on disk
# --------------------------------------------------------------------------

def _run(reports: dict[str, str | None]) -> int:
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        (root / "MANIFEST.json").write_text(json.dumps(MANIFEST), "utf-8")
        for name, text in reports.items():
            if text is not None:
                (root / f"conformance-{name}.json").write_text(text, "utf-8")
        return c.main(["--reports", d, "--manifest", str(root / "MANIFEST.json")])


def test_main_passes_on_agreeing_files() -> None:
    assert _run({n: json.dumps(report()) for n in c.CORES}) == 0


def test_main_fails_on_a_zero_byte_report() -> None:
    # What an aborted harness leaves behind the shell redirect.
    assert _run({"python": json.dumps(report()), "typescript": ""}) == 1


def test_main_fails_on_a_missing_report() -> None:
    assert _run({"python": json.dumps(report()), "typescript": None}) == 1


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for n, f in tests:
        try:
            f()
        except AssertionError as e:
            failed += 1
            print(f"FAIL {n}: {e}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
