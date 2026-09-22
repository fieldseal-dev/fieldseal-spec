"""Guards in the cross-core result-id comparison (docs/08 §9; #114 review item 10).

Each guard was verified by hand when the job was written, and a guard nobody
exercises is one a refactor can delete silently. Every test starts from a set
of synthetic reports that agree, confirms the baseline passes, then breaks one
thing and asserts the finding it should produce. Most use the two shipped
cores; the three-core section at the end is what WS-L (docs/26 §1 item 4)
added when the number of cores stopped being fixed.

Runs without pytest and without any core:

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


def cores(*names: str) -> dict[str, Any]:
    """Agreeing reports for the named cores; the two shipped ones by default."""
    return {n: report() for n in (names or c.DEFAULT_CORES)}


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
    fail, log = c.compare(cores(), MANIFEST)
    assert fail == [], fail
    assert any("identical across 2 cores: 4 synchronous result ids" in line for line in log), log


def test_agreeing_reports_without_async_pass() -> None:
    assert findings({"python": report(twins=False), "typescript": report(twins=False)}) == []


# --------------------------------------------------------------------------
# one report on its own
# --------------------------------------------------------------------------

def test_unreadable_report() -> None:
    r = cores()
    r["typescript"] = json.JSONDecodeError("Expecting value", "", 0)
    expect(r, "typescript: report unreadable (JSONDecodeError")


def test_report_missing_a_key() -> None:
    r = cores()
    del r["python"]["out_of_band"]
    expect(r, "python: report unreadable (KeyError")


def test_duplicate_id_masking_a_dropped_one() -> None:
    # Same result count as the other core, one id repeated in place of one
    # missing: anything counting results would call these equal.
    r = cores()
    res = r["python"]["results"]
    victim = next(x for x in res if x["id"] == "blind-index/hmac-sha512/bi-002")
    victim["id"] = "blind-index/hmac-sha512/bi-001"
    assert len(res) == len(r["typescript"]["results"])
    expect(r, "python: duplicate result ids: ['blind-index/hmac-sha512/bi-001']",
           "1 id(s) python did not run, run by typescript: ['blind-index/hmac-sha512/bi-002']")


def test_skipped_result_is_a_finding() -> None:
    r = cores()
    r["python"]["results"][0]["status"] = "skipped"
    expect(r, "python: 1 skipped result(s)")


def test_both_cores_skipping_the_same_family_is_not_agreement() -> None:
    r = cores()
    for name in c.DEFAULT_CORES:
        for x in r[name]["results"]:
            if x["id"].startswith("envelope/"):
                x["status"] = "skipped"
    expect(r, "python: 4 skipped", "typescript: 4 skipped",
           "python: manifest files with no result at all: ['envelope/aes-gcm.json']")


def test_partial_second_pass() -> None:
    r = cores()
    r["typescript"]["results"] = [x for x in r["typescript"]["results"]
                                  if x["id"] != "envelope/aes-gcm/env-001#decrypt" + c.ASYNC]
    expect(r, "typescript: async_companions is true but 1 first-pass result(s) have no twin: "
              "['envelope/aes-gcm/env-001#decrypt']")
    # And the synchronous comparison alone could not have seen it.
    assert not any("did not run" in f for f in findings(r))


def test_flag_true_with_no_async_results() -> None:
    r = cores()
    r["python"] = report(twins=False)
    r["python"]["async_companions"] = True
    expect(r, "python: async_companions is true but the report carries no '#async' results")


def test_flag_false_with_async_results() -> None:
    r = cores()
    r["python"]["async_companions"] = False
    expect(r, "python: async_companions is false but the report carries 4 '#async' results")


def test_out_of_band_not_passing() -> None:
    r = cores()
    r["typescript"]["out_of_band"][1]["status"] = "fail"
    expect(r, "typescript: out-of-band entries not passing: ['oob/surrogate-refusal']")


# --------------------------------------------------------------------------
# the two reports against each other and the manifest
# --------------------------------------------------------------------------

def test_one_core_drops_a_family() -> None:
    r = cores()
    drop(r["typescript"], "blind-index/")
    expect(r, "2 id(s) typescript did not run, run by python", "typescript: manifest files with no result at all")


def test_both_cores_drop_the_same_family() -> None:
    # The case two-report comparison cannot see: the id sets still agree.
    r = cores()
    for name in c.DEFAULT_CORES:
        drop(r[name], "envelope/")
    fail = findings(r)
    assert not any("did not run" in f for f in fail), fail
    expect(r, "python: manifest files with no result at all: ['envelope/aes-gcm.json']",
           "typescript: manifest files with no result at all: ['envelope/aes-gcm.json']")


def test_both_cores_run_nothing() -> None:
    empty = {"results": [], "out_of_band": [], "async_companions": False}
    expect({"python": empty, "typescript": copy.deepcopy(empty)},
           "a synchronous id set is empty: python, typescript (python 0, typescript 0)")


def test_out_of_band_divergence() -> None:
    r = cores()
    r["python"]["out_of_band"].append({"id": "oob/python-only", "status": "pass"})
    expect(r, "out-of-band ids differ between cores: typescript lacks ['oob/python-only']")


def test_unreadable_manifest_is_a_finding() -> None:
    r = cores()
    drop(r["typescript"], "blind-index/")
    expect(r, "manifest unreadable (FileNotFoundError", "2 id(s) typescript did not run, run by python",
           manifest=FileNotFoundError("vectors/MANIFEST.json"))
    expect(cores(), "manifest unreadable (KeyError", manifest={"entries": []})


def test_manifest_prefix_needs_the_slash() -> None:
    # 'envelope/aes-gcm-siv/...' must not count as reaching 'envelope/aes-gcm.json'.
    manifest = {"files": MANIFEST["files"] + [{"path": "envelope/aes-gcm-siv.json"}]}
    r = cores()
    for name in c.DEFAULT_CORES:
        r[name]["results"].append({"id": "envelope/aes-gcm-sivX/env-001", "status": "pass"})
        r[name]["results"].append({"id": "envelope/aes-gcm-sivX/env-001" + c.ASYNC, "status": "pass"})
    expect(r, "manifest files with no result at all: ['envelope/aes-gcm-siv.json']", manifest=manifest)


# --------------------------------------------------------------------------
# the entry point the workflow calls, against files on disk
# --------------------------------------------------------------------------

def _run(reports: dict[str, str | None], manifest: str | None = json.dumps(MANIFEST),
         core_names: str | None = None) -> int:
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        if manifest is not None:
            (root / "MANIFEST.json").write_text(manifest, "utf-8")
        for name, text in reports.items():
            if text is not None:
                (root / f"conformance-{name}.json").write_text(text, "utf-8")
        argv = ["--reports", d, "--manifest", str(root / "MANIFEST.json")]
        return c.main(argv + (["--cores", core_names] if core_names else []))


def test_main_passes_on_agreeing_files() -> None:
    assert _run({n: json.dumps(report()) for n in c.DEFAULT_CORES}) == 0


def test_main_fails_on_a_zero_byte_report() -> None:
    # What an aborted harness leaves behind the shell redirect.
    assert _run({"python": json.dumps(report()), "typescript": ""}) == 1


def test_main_fails_on_a_missing_report() -> None:
    assert _run({"python": json.dumps(report()), "typescript": None}) == 1


def test_main_fails_cleanly_on_a_missing_manifest() -> None:
    # #161 review: this used to escape main() as a traceback, burying any
    # report finding; alongside an unreadable report it was never read at all.
    assert _run({n: json.dumps(report()) for n in c.DEFAULT_CORES}, manifest=None) == 1
    assert _run({"python": json.dumps(report()), "typescript": ""}, manifest=None) == 1


# --------------------------------------------------------------------------
# three cores (WS-L): the comparison is against the union, not a pair
# --------------------------------------------------------------------------

THREE = ("python", "typescript", "java")


def test_three_agreeing_reports_pass() -> None:
    fail, log = c.compare(cores(*THREE), MANIFEST)
    assert fail == [], fail
    assert any("identical across 3 cores: 4 synchronous result ids" in line for line in log), log


def test_third_core_drops_a_family() -> None:
    r = cores(*THREE)
    drop(r["java"], "blind-index/")
    expect(r, "2 id(s) java did not run, run by python, typescript",
           "java: manifest files with no result at all: ['blind-index/hmac-sha512.json']")
    # Nobody else is accused of anything.
    assert not any(f.startswith(("2 id(s) python", "2 id(s) typescript")) for f in findings(r))


def test_third_core_runs_an_extra_id() -> None:
    r = cores(*THREE)
    r["java"]["results"].append({"id": "envelope/aes-gcm/env-002", "status": "pass"})
    r["java"]["results"].append({"id": "envelope/aes-gcm/env-002" + c.ASYNC, "status": "pass"})
    expect(r, "1 id(s) python did not run, run by java: ['envelope/aes-gcm/env-002']",
           "1 id(s) typescript did not run, run by java: ['envelope/aes-gcm/env-002']")


def test_missing_ids_are_grouped_by_who_ran_them() -> None:
    # java lacks bi-001 (run by both others) and bi-002 (run by python only):
    # two findings, neither claiming a core ran an id it did not.
    r = cores(*THREE)
    drop(r["java"], "blind-index/")
    drop(r["typescript"], "blind-index/hmac-sha512/bi-002")
    expect(r, "1 id(s) java did not run, run by python, typescript: ['blind-index/hmac-sha512/bi-001']",
           "1 id(s) java did not run, run by python: ['blind-index/hmac-sha512/bi-002']",
           "1 id(s) typescript did not run, run by python: ['blind-index/hmac-sha512/bi-002']")


def test_one_of_three_unreadable_the_rest_still_compared() -> None:
    r = cores(*THREE)
    r["typescript"] = json.JSONDecodeError("Expecting value", "", 0)
    drop(r["java"], "envelope/")
    expect(r, "typescript: report unreadable (JSONDecodeError",
           "2 id(s) java did not run, run by python")


def test_third_core_out_of_band_differs() -> None:
    r = cores(*THREE)
    r["java"]["out_of_band"] = r["java"]["out_of_band"][:1]
    expect(r, "out-of-band ids differ between cores: java lacks ['oob/surrogate-refusal']")


def test_main_with_three_cores() -> None:
    three = {n: json.dumps(report()) for n in THREE}
    assert _run(three, core_names="python,typescript,java") == 0
    # The default still reads only the two shipped cores' files.
    assert _run(three) == 0


def test_main_fails_when_a_named_core_has_no_report() -> None:
    two = {n: json.dumps(report()) for n in c.DEFAULT_CORES}
    assert _run(two, core_names="python,typescript,java") == 1


def test_main_rejects_fewer_than_two_cores_and_repeats() -> None:
    for bad in ("python", "python,python"):
        try:
            _run({"python": json.dumps(report())}, core_names=bad)
        except SystemExit as e:
            assert e.code == 2, (bad, e.code)
        else:
            raise AssertionError(f"--cores {bad} was accepted")


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
