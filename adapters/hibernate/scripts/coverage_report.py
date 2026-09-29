"""The Hibernate adapter's docs/14 §4 conformance report, generated from its coverage matrix.

The coverage matrix in adapters/hibernate/README.md names, on every row, the tests that prove
it. This reads that table and the JUnit XML of the last `./gradlew test`, and takes each row's
status from the tests it names: `pass` when every named test ran and passed, `fail` when one
failed or is missing, `not-implemented` for an honest ❌ row that names none, and `unverified`
for a row that claims behaviour and names no test. Only `pass` and `not-implemented` are
acceptable; anything else, or a failing test anywhere in the run, exits 1. The claim and the
documentation cannot drift apart that way (docs/14 §4, "An adapter's report").

A citation is `Class.method` (every test that method produced, parameterized or dynamic,
counts) or `Class` alone (every test in the class). A skipped test fails its row unless it was
skipped for a platform capability (docs/08 §5 item 7), which the codec harness says in its
skip message.

Usage, from anywhere, after a test run:

    python adapters/hibernate/scripts/coverage_report.py > conformance-hibernate.json
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent  # adapters/hibernate
REPO = ROOT.parent.parent
PACKAGE = "dev.fieldseal.hibernate."


def matrix():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## Coverage matrix", 1)[1].split("\n## ", 1)[0]
    rows = []
    for line in section.splitlines():
        if not line.startswith("| ") or line.startswith("| Path") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if len(cells) != 3:
            raise SystemExit(f"coverage matrix: a row without three cells: {line}")
        path, behaviour, tests = cells
        cited = re.findall(r"`([A-Za-z0-9_.]+)`", tests)
        rows.append({"path": path, "behaviour": behaviour, "tests": cited})
    return rows


def results():
    """{(class simple name, test name): status} from the JUnit XML."""
    out = {}
    for f in sorted((ROOT / "build/test-results/test").glob("TEST-*.xml")):
        for case in ET.parse(f).getroot().iter("testcase"):
            cls = case.get("classname", "")
            if cls.startswith(PACKAGE):
                cls = cls[len(PACKAGE):]
            if case.find("failure") is not None or case.find("error") is not None:
                status = "fail"
            elif case.find("skipped") is not None:
                msg = case.find("skipped").get("message") or ""
                status = "skipped-capability" if "capability not held" in msg else "skipped"
            else:
                status = "pass"
            out[(cls, case.get("name"))] = status
    return out


def matches(name, method):
    return (name == method + "()" or name.startswith(method + "(")
            or name.startswith(method + "["))


def row_status(row, run):
    if not row["tests"]:
        return "not-implemented" if row["behaviour"].startswith("❌") else "unverified", []
    problems = []
    for cite in row["tests"]:
        cls, _, method = cite.partition(".")
        hits = [s for (c, n), s in run.items() if c == cls and (not method or matches(n, method))]
        if not hits:
            problems.append(f"{cite}: no such test ran")
        elif "fail" in hits:
            problems.append(f"{cite}: failed")
        elif "skipped" in hits:
            problems.append(f"{cite}: skipped, and not for a capability")
        elif "pass" not in hits:
            problems.append(f"{cite}: nothing passed")
    return ("fail" if problems else "pass"), problems


def version(key):
    toml = (ROOT / "gradle/libs.versions.toml").read_text(encoding="utf-8")
    m = re.search(rf'^{re.escape(key)} = "([^"]+)"', toml, re.M)
    return m.group(1) if m else "unknown"


def commit():
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main():
    run = results()
    if not run:
        sys.exit("no JUnit results under build/test-results/test: run ./gradlew test first")
    rows, problems = [], []
    for r in matrix():
        status, why = row_status(r, run)
        rows.append({**r, "status": status})
        problems += [f"{r['path']}: {p}" for p in why]
        if status == "unverified":
            problems.append(f"{r['path']}: claims behaviour and names no test")
    failing = sorted(f"{c}.{n}" for (c, n), s in run.items() if s == "fail")
    problems += [f"failing test {t}" for t in failing]
    counts = {s: sum(1 for r in rows if r["status"] == s)
              for s in ("pass", "fail", "not-implemented", "unverified")}
    ok = not problems
    codec = [s for (c, n), s in run.items() if c == "CodecVectorsTest" and n.startswith("codec[")]
    manifest = json.loads((REPO / "vectors/MANIFEST.json").read_text(encoding="utf-8"))
    report = {
        "schema": "fieldseal-conformance/v1",
        "implementation": {"name": "hibernate-adapter", "version": "0.0.0-SNAPSHOT",
                           "commit": commit(), "language": "java"},
        "vector_suite_version": manifest["vector_suite_version"],
        "spec_version": manifest["spec_version"],
        "claimed_levels": {"L1": ok, "L2": ok, "L3": ok, "L3-row": False, "L4": False},
        "suites_supported": ["0xFF01"],
        "provisional_suites": True,
        "environment": {
            "database": os.environ.get("FIELDSEAL_TEST_DB", "h2"),
            "orm": "Hibernate ORM " + version("hibernate"),
            "os": sys.platform,
        },
        "pinned_decisions": {
            "codec-renderings":
                "spec §3.6, all eight logical types, from the attribute's Java type (docs/29 "
                "§2.2), pinned by the codec/ family in MANIFEST.adapter_files and run through "
                f"the adapter's own codec: {codec.count('pass')} pass, "
                f"{codec.count('skipped-capability')} skipped for a capability Java lacks "
                "(date-as-utc-midnight-instant, millisecond-instants). Java conventions: "
                "BigDecimal read back canonically, OffsetDateTime read back at UTC, a "
                "sub-microsecond Instant refused rather than truncated.",
            "storage-forms": "binary only: the column is VARBINARY (bytea on Postgres) and "
                             "holds the envelope.",
            "l2-surface":
                "L2 (a): the index is its own byte[] attribute, queried through "
                "FieldsealQueries, which re-verifies every candidate under the index's "
                "normalizer (spec §7.5); list, count, first and exists are exact. HQL and "
                "Criteria predicates on an index attribute are refused outside the finder.",
            "tenant-source":
                "the session's tenant identifier (SessionBuilder.tenantIdentifier or a "
                "CurrentTenantIdentifierResolver): a String as its UTF-8 bytes, a byte[] as is, "
                "anything else refused; a tenant-bound column with none fails closed.",
        },
        "harness_notes": [
            "This package runs no vector families and claims no L0: it contains no cryptography "
            "(AD-1, spec §11.3). The families, and the pinned_decisions keys docs/14 §4 obliges a "
            "core to carry, belong to the Java core's own report. The keys above are this "
            "adapter's own, which docs/14 §4 permits.",
            "coverage_matrix is parsed out of README.md and each row's status is the status of "
            "the tests that row names. A row naming a test that did not run fails this report.",
            "L3 is claimed because the tenant comes from the ORM's per-operation context, the "
            "session, which is what spec §10.1's ✅ for Hibernate asks for. L3-row is not built.",
            "The suite runs against H2 and PostgreSQL as separate CI legs; this report describes "
            "the leg that produced it (environment.database).",
        ],
        "results": [],
        "held_out": [],
        "out_of_band": [],
        "async_companions": False,
        "coverage_matrix": {
            "source": "adapters/hibernate/README.md#coverage-matrix",
            "rows": rows,
            "summary": {"rows": len(rows), **{k.replace("-", "_"): v for k, v in counts.items()},
                        "tests_named": sum(len(r["tests"]) for r in rows)},
        },
        "suite": {"total": len(run), "passed": sum(1 for s in run.values() if s == "pass"),
                  "failed": len(failing),
                  "skipped": sum(1 for s in run.values() if s.startswith("skipped"))},
        "summary": {"pass": sum(1 for s in run.values() if s == "pass"),
                    "fail": len(failing) + counts["fail"] + counts["unverified"],
                    "skipped": sum(1 for s in run.values() if s.startswith("skipped")),
                    "held_out": 0},
    }
    sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    for p in problems:
        print(f"coverage matrix: {p}", file=sys.stderr)
    print(f"coverage matrix: {len(rows)} rows, {counts['pass']} pass, "
          f"{counts['not-implemented']} not implemented, {len(problems)} problems",
          file=sys.stderr)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
