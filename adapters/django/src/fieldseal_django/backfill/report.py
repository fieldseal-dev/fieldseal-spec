"""What the tool prints (PROCEDURE §9).

These are requirements on output, not on documentation. Nothing here ever
prints a plaintext value, an envelope, an index value or key material:
counts, codes, identifiers and the `config` document only.
"""

from __future__ import annotations

import json
from typing import Any

from . import state
from .encrypt import Limits, Outcome

#: PROCEDURE §9 text 1, verbatim.
PREEXISTING_BACKUPS = """\
This table already holds data. Encrypting it now does not encrypt the copies
that already exist: every backup, snapshot, replica and export made before this
run still holds these values in plaintext, and destroying a key later will not
erase them. Crypto-shredding claims are permanently void for every backup that
predates this migration. NIST SP 800-88r2 section 3.2.2 allows cryptographic
erase only where no sensitive data was previously stored in plaintext form.
Re-run with --acknowledge-preexisting-backups to proceed."""

NOT_CONVERTED = ("The table is NOT fully converted: this run left values it "
                 "did not encrypt.")


def start_lines(run: state.Run, resumed: bool, limits: Limits) -> list[str]:
    """§9 item 3."""
    return [
        f"run {run.run_id}: job {run.job}, "
        f"{'resumed' if resumed else 'new'}, table {run.table_name}",
        f"config: {run.config}",
        f"limits: batch_size={limits.batch_size} "
        f"rows_per_second={limits.rows_per_second:g} "
        f"max_failures={limits.max_failures}",
        "replication-lag throttling: not active (this frontend does not "
        "implement it; throttle with --rows-per-second)",
    ]


def final(outcome: Outcome) -> dict[str, Any]:
    """§9 item 4, as the JSON document."""
    run = outcome.run
    run_seconds = max(0.0, (state.parse_time(run.updated_at)
                            - state.parse_time(run.started_at)).total_seconds())
    return {
        "run_id": run.run_id,
        "job": run.job,
        "status": run.status,
        "fully_converted": run.status == "complete"
        and run.values_failed == 0 and run.values_anomalous == 0,
        "stopped_by_max_failures": outcome.stopped_by_max_failures,
        "batch_seq": run.batch_seq,
        "rows_scanned": run.rows_scanned,
        "values_written": run.values_written,
        "values_current": run.values_current,
        "values_null": run.values_null,
        "values_anomalous": run.values_anomalous,
        "values_failed": run.values_failed,
        "failures_by_code": outcome.failures_by_code,
        "process": {
            "rows_scanned": outcome.process_rows,
            "seconds": round(outcome.process_seconds, 3),
            "rows_per_second": _rate(outcome.process_rows,
                                     outcome.process_seconds),
        },
        "run": {
            "seconds": run_seconds,
            "rows_per_second": _rate(run.rows_scanned, run_seconds),
        },
    }


def _rate(rows: int, seconds: float) -> float | None:
    return round(rows / seconds, 3) if seconds > 0 else None


def final_lines(outcome: Outcome) -> list[str]:
    """§9 item 4, human-readable, then the same report as one JSON line."""
    doc = final(outcome)
    lines = []
    if doc["values_failed"] or doc["values_anomalous"]:
        lines.append(NOT_CONVERTED)
    if outcome.stopped_by_max_failures:
        lines.append(
            "Stopped: --max-failures was reached. The run is still `running` "
            "and its cursor is past the rows that failed; resume it once the "
            "cause is fixed.")
    lines.append(f"run {doc['run_id']}: status {doc['status']}, "
                 f"{doc['batch_seq']} batch(es)")
    lines.append(
        f"rows scanned {doc['rows_scanned']}; values written "
        f"{doc['values_written']}, current {doc['values_current']}, null "
        f"{doc['values_null']}, anomalous {doc['values_anomalous']}, failed "
        f"{doc['values_failed']}")
    for code, n in doc["failures_by_code"].items():
        lines.append(f"  failed with {code}: {n}")
    for label in ("process", "run"):
        part = doc[label]
        rate = part["rows_per_second"]
        lines.append(
            f"{label}: {part['seconds']} s, "
            f"{'n/a' if rate is None else rate} rows/s measured")
    if doc["status"] == "complete":
        lines.append(
            "`complete` means the cursor reached the end of the table, not "
            "that every value was converted.")
    lines.append(json.dumps(doc, sort_keys=True))
    return lines
