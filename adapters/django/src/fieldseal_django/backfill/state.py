"""The two state tables (PROCEDURE §3), through a raw cursor.

They live in the **target** database, so a batch's data writes and its
progress record commit in one transaction. Neither table ever holds a
plaintext value, an envelope, an index value or key material.

Raw SQL rather than models: the statements are the procedure's own (§5.2
step 3 is one `UPDATE`, given verbatim), and a model would bring a migration
the adapter does not otherwise ship.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from django.db import IntegrityError, transaction

from . import BackfillError

RUNS = "fieldseal_backfill_runs"
FAILURES = "fieldseal_backfill_failures"

#: PROCEDURE §3, as written. Postgres and SQLite both take these spellings.
_DDL = (
    f"""CREATE TABLE {RUNS} (
    run_id             VARCHAR(36)   NOT NULL PRIMARY KEY,
    procedure_version  INTEGER       NOT NULL,
    job                VARCHAR(16)   NOT NULL,
    table_uuid         CHAR(32)      NOT NULL,
    running_table_uuid CHAR(32),
    table_name         VARCHAR(255)  NOT NULL,
    config_hash        CHAR(64)      NOT NULL,
    config             TEXT          NOT NULL,
    status             VARCHAR(16)   NOT NULL,
    batch_seq          BIGINT        NOT NULL,
    cursor_value       TEXT,
    rows_scanned       BIGINT        NOT NULL,
    values_written     BIGINT        NOT NULL,
    values_current     BIGINT        NOT NULL,
    values_null        BIGINT        NOT NULL,
    values_anomalous   BIGINT        NOT NULL,
    values_failed      BIGINT        NOT NULL,
    started_at         VARCHAR(20)   NOT NULL,
    updated_at         VARCHAR(20)   NOT NULL,
    completed_at       VARCHAR(20),
    frontend           VARCHAR(64)   NOT NULL,
    UNIQUE (running_table_uuid)
)""",
    f"""CREATE TABLE {FAILURES} (
    run_id       VARCHAR(36)   NOT NULL,
    row_key      TEXT          NOT NULL,
    column_uuid  CHAR(32)      NOT NULL,
    error_code   VARCHAR(32)   NOT NULL,
    batch_seq    BIGINT        NOT NULL,
    recorded_at  VARCHAR(20)   NOT NULL,
    PRIMARY KEY (run_id, row_key, column_uuid)
)""",
)

_RUN_COLUMNS = (
    "run_id", "procedure_version", "job", "table_uuid", "running_table_uuid",
    "table_name", "config_hash", "config", "status", "batch_seq",
    "cursor_value", "rows_scanned", "values_written", "values_current",
    "values_null", "values_anomalous", "values_failed", "started_at",
    "updated_at", "completed_at", "frontend",
)
_FAILURE_COLUMNS = (
    "run_id", "row_key", "column_uuid", "error_code", "batch_seq",
    "recorded_at",
)
COUNTS = ("rows_scanned", "values_written", "values_current", "values_null",
          "values_anomalous", "values_failed")


@dataclass(frozen=True)
class Run:
    run_id: str
    procedure_version: int
    job: str
    table_uuid: str
    running_table_uuid: str | None
    table_name: str
    config_hash: str
    config: str
    status: str
    batch_seq: int
    cursor_value: str | None
    rows_scanned: int
    values_written: int
    values_current: int
    values_null: int
    values_anomalous: int
    values_failed: int
    started_at: str
    updated_at: str
    completed_at: str | None
    frontend: str


class RunHeld(BackfillError):
    """Another run is `running` on the table (§3's unique constraint)."""

    def __init__(self, holder: str | None) -> None:
        self.holder = holder
        super().__init__(
            f"run {holder or '(unknown)'} is already running on this table. "
            "Resume it with `fieldseal_backfill resume`, or mark it abandoned "
            "with `fieldseal_backfill abandon`, and start again.")


def now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text: str) -> dt.datetime:
    return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.UTC)


def init(connection: Any) -> list[str]:
    """Create whichever state table is missing. Returns the names created."""
    existing = set(connection.introspection.table_names())
    created = []
    with transaction.atomic(using=connection.alias):
        with connection.cursor() as cur:
            for name, ddl in zip((RUNS, FAILURES), _DDL, strict=True):
                if name not in existing:
                    cur.execute(ddl)
                    created.append(name)
    return created


def require_tables(connection: Any) -> None:
    """Refuse to run when a table is missing or lacks a column (§3)."""
    existing = set(connection.introspection.table_names())
    with connection.cursor() as cur:
        for name, wanted in ((RUNS, _RUN_COLUMNS),
                             (FAILURES, _FAILURE_COLUMNS)):
            if name not in existing:
                raise BackfillError(
                    f"the state table {name} does not exist in database "
                    f"{connection.alias!r}. Create both with "
                    "`fieldseal_backfill init`, or by your own migration "
                    "from tools/backfill/PROCEDURE.md §3.")
            have = {col.name for col in
                    connection.introspection.get_table_description(cur, name)}
            missing = sorted(set(wanted) - have)
            if missing:
                raise BackfillError(
                    f"the state table {name} lacks {', '.join(missing)} "
                    "(tools/backfill/PROCEDURE.md §3).")


def insert_run(connection: Any, run: Run) -> None:
    """Record a new `running` run, or report the run that holds the table.

    The refusal is the database's, not a read before the insert: two starts
    at once cannot both pass (§3).
    """
    sql = (f"INSERT INTO {RUNS} ({', '.join(_RUN_COLUMNS)}) "
           f"VALUES ({', '.join(['%s'] * len(_RUN_COLUMNS))})")
    try:
        with transaction.atomic(using=connection.alias):
            with connection.cursor() as cur:
                cur.execute(sql, [getattr(run, c) for c in _RUN_COLUMNS])
    except IntegrityError:
        with connection.cursor() as cur:
            cur.execute(
                f"SELECT run_id FROM {RUNS} WHERE running_table_uuid = %s",
                [run.table_uuid])
            row = cur.fetchone()
        raise RunHeld(row[0] if row else None) from None


def load_run(connection: Any, run_id: str) -> Run | None:
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT {', '.join(_RUN_COLUMNS)} FROM {RUNS} WHERE run_id = %s",
            [run_id])
        row = cur.fetchone()
    return None if row is None else Run(*row)


def claim(connection: Any, run_id: str, batch_seq: int) -> bool:
    """§5.2 step 3. False when another process owns the run or it has ended.

    Also locks the run row until commit, so two processes cannot interleave.
    """
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {RUNS} SET batch_seq = batch_seq + 1 "
            "WHERE run_id = %s AND batch_seq = %s AND status = 'running'",
            [run_id, batch_seq])
        return bool(cur.rowcount == 1)


def record(
    connection: Any,
    run_id: str,
    *,
    batch_seq: int,
    counts: dict[str, int],
    cursor_value: str | None,
    failures: list[tuple[str, str, str]],
    complete: bool,
) -> None:
    """§5.2 step 7: the batch's failure rows, counts, cursor and status.

    `failures` is `(row_key, column_uuid, error_code)`. No message text is
    stored: an error message can carry part of a value (§7.4).
    """
    at = now()
    sets = [f"{name} = {name} + %s" for name in COUNTS]
    params: list[Any] = [counts[name] for name in COUNTS]
    sets.append("updated_at = %s")
    params.append(at)
    if cursor_value is not None:
        sets.append("cursor_value = %s")
        params.append(cursor_value)
    if complete:
        # One statement for the status and the release of the table (§3).
        sets.append("status = 'complete'")
        sets.append("running_table_uuid = NULL")
        sets.append("completed_at = %s")
        params.append(at)
    with connection.cursor() as cur:
        if failures:
            cur.executemany(
                f"INSERT INTO {FAILURES} ({', '.join(_FAILURE_COLUMNS)}) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [[run_id, key, column, code, batch_seq, at]
                 for key, column, code in failures])
        cur.execute(
            f"UPDATE {RUNS} SET {', '.join(sets)} WHERE run_id = %s",
            [*params, run_id])


def abandon(connection: Any, run_id: str) -> bool:
    """Mark a `running` run abandoned and release its table, in one statement."""
    with transaction.atomic(using=connection.alias):
        with connection.cursor() as cur:
            cur.execute(
                f"UPDATE {RUNS} SET status = 'abandoned', "
                "running_table_uuid = NULL, updated_at = %s "
                "WHERE run_id = %s AND status = 'running'",
                [now(), run_id])
            return bool(cur.rowcount == 1)


def failures_by_code(connection: Any, run_id: str) -> dict[str, int]:
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT error_code, COUNT(*) FROM {FAILURES} "
            "WHERE run_id = %s GROUP BY error_code ORDER BY error_code",
            [run_id])
        return {code: int(n) for code, n in cur.fetchall()}
