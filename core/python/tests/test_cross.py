"""The cross producer and consumer at `cross/v3` (docs/08 §4.7, spec §7.2,
#213): the declared suite travels in each index case's declaration, and the
consumer builds the declaration from it, fails without it, and fails on a
schema it does not recognise (`cross/v2` included).
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cross_consume  # noqa: E402
import cross_produce  # noqa: E402


def _consume(tmp_path: Path, doc: dict) -> dict:
    f = tmp_path / "cross-python.json"
    f.write_text(json.dumps(doc), "utf-8")
    return cross_consume.consume([f])


def _failures(verdict: dict) -> list[dict]:
    return [p for p in verdict["pairs"] if p["status"] != "pass"]


def test_the_producer_emits_v3_with_the_ff02_case_and_the_consumer_passes_it(
        tmp_path):
    doc = cross_produce.produce()
    assert doc["schema"] == "fieldseal-vectors/cross/v3"
    ff02 = [c for c in doc["index_cases"]
            if c["declaration"]["suite_id"] == "0xFF02"]
    assert [c["id"] for c in ff02] == [
        "cross/python/index/exact-ascii-suite-ff02"]
    assert all("suite_id" in c["declaration"] for c in doc["index_cases"])
    verdict = _consume(tmp_path, doc)
    assert _failures(verdict) == []
    assert verdict["summary"]["index"] == len(doc["index_cases"])


def test_the_ff02_case_differs_from_the_same_value_under_ff01(tmp_path):
    doc = cross_produce.produce()
    by_case = {c["id"].rsplit("/", 1)[1]: c for c in doc["index_cases"]}
    assert (by_case["exact-ascii-suite-ff02"]["index"]
            != by_case["exact-ascii"]["index"])


def test_a_v3_index_case_without_suite_id_fails(tmp_path):
    doc = cross_produce.produce()
    broken = copy.deepcopy(doc)
    del broken["index_cases"][0]["declaration"]["suite_id"]
    failed = _failures(_consume(tmp_path, broken))
    assert [p["id"] for p in failed] == [broken["index_cases"][0]["id"]]
    assert "suite_id" in failed[0]["reason"]


def test_a_consumer_does_not_substitute_the_write_suite(tmp_path):
    doc = cross_produce.produce()
    broken = copy.deepcopy(doc)
    for c in broken["index_cases"]:
        if c["declaration"]["suite_id"] == "0xFF02":
            c["declaration"]["suite_id"] = "0xFF01"
    failed = _failures(_consume(tmp_path, broken))
    assert [p["id"] for p in failed] == [
        "cross/python/index/exact-ascii-suite-ff02"]
    assert "index differs" in failed[0]["reason"]


def test_cross_v2_and_unknown_schemas_fail_closed(tmp_path):
    doc = cross_produce.produce()
    for schema in ("fieldseal-vectors/cross/v2",
                   "fieldseal-vectors/cross/v4", None):
        broken = dict(doc, schema=schema)
        failed = _failures(_consume(tmp_path, broken))
        assert [p["kind"] for p in failed] == ["document"], schema
        assert "unrecognised producer schema" in failed[0]["reason"]
