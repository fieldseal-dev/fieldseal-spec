"""Both cores report the same result ids (docs/08 §9, line 414).

The `cross-core-result-ids` job in `.github/workflows/conformance.yml` runs
this over the two docs/14 §4 reports the core jobs upload. It lived inline in
the workflow until 2026-09-19, where its guards could only be checked by hand;
`test_compare_result_ids.py` next to it now checks each one against synthetic
reports.

Stdlib only: the job installs neither core. Usage, from a directory holding
`conformance-python.json`, `conformance-typescript.json` and the checkout's
`vectors/MANIFEST.json`:

    python tools/conformance/compare_result_ids.py

Exit status is 1 on any finding, 0 otherwise.

What this does NOT catch, stated so the docs do not overclaim: a drop that
hits both cores identically AND is removed from the manifest. The manifest
cross-check closes the both-cores half; a family deleted from MANIFEST.json as
well is a suite change, and that belongs to `suite-integrity` and
`vectors-reproducible`.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

ASYNC = "#async"
STRIP = -len(ASYNC)
CORES = ("python", "typescript")


def load_report(path: pathlib.Path) -> Any:
    """The parsed report (or manifest), or the exception that stopped it parsing.

    Reachable because the job runs on a red core: a harness that aborts leaves
    the shell redirect's 0-byte file behind.
    """
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception as e:  # noqa: BLE001 -- any failure is a finding, not a crash
        return e


def compare(reports: dict[str, Any], manifest: Any) -> tuple[list[str], list[str]]:
    """Return (failures, log lines) for the two reports against the manifest.

    `reports` maps a core name to its parsed report, or to the exception
    `load_report` returned for it; `manifest` may likewise be an exception.
    """
    fail: list[str] = []
    log: list[str] = []
    sync_ids: dict[str, set[str]] = {}
    oob_ids: dict[str, set[str]] = {}

    for name in CORES:
        r = reports[name]
        try:
            if isinstance(r, Exception):
                raise r
            results, oob = r["results"], r["out_of_band"]
            flag = r["async_companions"]
        except Exception as e:  # noqa: BLE001
            fail.append(f"{name}: report unreadable ({type(e).__name__}: {e})")
            continue

        # The duplicate-id invariant has no other home: pytest suffixes a
        # duplicated test id and the TS harness collapses results in a Map, so
        # neither core's own run can see one. Without this, a duplicated id
        # can mask a dropped one wherever results are counted.
        ids = [x["id"] for x in results]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            fail.append(f"{name}: duplicate result ids: {dupes[:10]}")

        # A skipped result is not coverage and must not enter the comparison
        # as though it were: two cores skipping the same family would
        # otherwise look like agreement. Both cores declare 0xFF01 for every
        # vector today, so any skip at all is a change that should be seen
        # rather than averaged away.
        skipped = sorted(x["id"] for x in results if x["status"] == "skipped")
        if skipped:
            fail.append(f"{name}: {len(skipped)} skipped result(s), which is coverage silently lost: {skipped[:5]}")

        live = [x["id"] for x in results if x["status"] != "skipped"]
        second = [i for i in live if i.endswith(ASYNC)]
        sync_ids[name] = {i for i in live if not i.endswith(ASYNC)}

        # docs/14 line 126 defines the flag over both halves: the companions
        # exist, AND every first-pass result is twinned. Checking only that
        # '#async' results are present would pass a partial second pass -- 182
        # synchronous, 69 twins -- because stripping the suffix cannot shrink
        # the synchronous set, so the comparison below would still see
        # 182 == 182. The suffix is appended last at the pass boundary, so
        # composed ids ('<id>#decrypt#async') strip correctly.
        if flag:
            if not second:
                fail.append(f"{name}: async_companions is true but the report carries no '{ASYNC}' results")
            else:
                untwinned = sorted(sync_ids[name] - {i[:STRIP] for i in second})
                if untwinned:
                    fail.append(f"{name}: async_companions is true but {len(untwinned)} first-pass result(s) have no twin: {untwinned[:5]}")
        elif second:
            fail.append(f"{name}: async_companions is false but the report carries {len(second)} '{ASYNC}' results")

        # out_of_band carries the checks no vector can (spec §3.5's length
        # bound, docs/09 §7.1's surrogate refusal). No per-core test asserts
        # these exist.
        bad = sorted(o["id"] for o in oob if o["status"] != "pass")
        if bad:
            fail.append(f"{name}: out-of-band entries not passing: {bad}")
        oob_ids[name] = {o["id"] for o in oob if not o["id"].endswith(ASYNC)}

        log.append(f"{name}: {len(results)} results ({len(second)} '{ASYNC}', {len(sync_ids[name])} synchronous, "
                   f"{len(skipped)} skipped), {len(oob)} out-of-band, async_companions={flag}")

    if len(sync_ids) == 2:
        py, ts = sync_ids["python"], sync_ids["typescript"]
        # Two empty sets are equal: without this the job passes if both cores
        # stop running the suite entirely.
        if not py or not ts:
            fail.append(f"a synchronous id set is empty (python {len(py)}, typescript {len(ts)})")
        for a, b in (("python", "typescript"), ("typescript", "python")):
            only = sorted(sync_ids[a] - sync_ids[b])
            if only:
                fail.append(f"{len(only)} id(s) only {a} ran: {only[:10]}")

        only_oob = oob_ids["python"] ^ oob_ids["typescript"]
        if only_oob:
            fail.append(f"out-of-band ids differ between cores: {sorted(only_oob)}")

        # The both-cores half of the problem. Comparing two reports cannot see
        # a family neither ran, so the expected families come from the suite
        # itself. Presence per manifest file, not a count: results-per-vector
        # varies by family, that expansion is the per-core harness's business,
        # and a hard-coded total would fail every legitimate addition to the
        # suite. An unreadable manifest is a finding like an unreadable
        # report, not a traceback that buries the findings above it.
        try:
            if isinstance(manifest, Exception):
                raise manifest
            paths = [f["path"] for f in manifest["files"]]
        except Exception as e:  # noqa: BLE001
            fail.append(f"manifest unreadable ({type(e).__name__}: {e})")
            paths = []
        for name, ids_ in sync_ids.items():
            absent = [p for p in paths
                      if not any(i.startswith(p[:-len(".json")] + "/") for i in ids_)]
            if absent:
                fail.append(f"{name}: manifest files with no result at all: {absent}")

        if not fail:
            log.append(f"\nidentical: {len(py)} synchronous result ids and {len(oob_ids['python'])} "
                       f"out-of-band ids, empty symmetric difference; all "
                       f"{len(paths)} manifest files reached by both cores")

    return fail, log


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--reports", type=pathlib.Path, default=pathlib.Path("."),
                    help="directory holding conformance-<core>.json (default: .)")
    ap.add_argument("--manifest", type=pathlib.Path, default=pathlib.Path("vectors/MANIFEST.json"))
    args = ap.parse_args(argv)

    reports = {name: load_report(args.reports / f"conformance-{name}.json") for name in CORES}
    manifest = load_report(args.manifest)
    fail, log = compare(reports, manifest)
    for line in log:
        print(line)
    if fail:
        print("\ndocs/08 line 414 says the cores report identical ids on the synchronous pass:")
        for f in fail:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
