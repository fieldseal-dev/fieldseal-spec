"""The three state tables (PROCEDURE §3), through a raw cursor.

They live in the **target** database, so a batch's data writes and its
progress record commit in one transaction. No table ever holds a
plaintext value, an envelope, an index value or key material.

Raw SQL rather than models: the statements are the procedure's own (§5.2
step 3 is one `UPDATE`, given verbatim), and a model would bring a migration
the adapter does not otherwise ship.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from django.db import IntegrityError, transaction

from . import BackfillError

RUNS = "fieldseal_backfill_runs"
FAILURES = "fieldseal_backfill_failures"
COLUMNS = "fieldseal_backfill_columns"

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
    f"""CREATE TABLE {COLUMNS} (
    run_id            VARCHAR(36)   NOT NULL,
    column_uuid       CHAR(32)      NOT NULL,
    values_written    BIGINT        NOT NULL,
    values_current    BIGINT        NOT NULL,
    values_null       BIGINT        NOT NULL,
    values_anomalous  BIGINT        NOT NULL,
    values_failed     BIGINT        NOT NULL,
    PRIMARY KEY (run_id, column_uuid)
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
#: The five per-value counts: the run row's, and each column row's (§3).
VALUE_COUNTS = ("values_written", "values_current", "values_null",
                "values_anomalous", "values_failed")
COUNTS = ("rows_scanned", *VALUE_COUNTS)
_COLUMN_COLUMNS = ("run_id", "column_uuid", *VALUE_COUNTS)


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


class _RunRowRefused(Exception):
    """The run row's insert hit a constraint (internal)."""


def now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text: str) -> dt.datetime:
    return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.UTC)


def init(connection: Any) -> list[str]:
    """Create whichever state table is missing. Returns the names created.

    Never alters a table that exists, so a database that has only the two
    version-2 tables gets the columns table and nothing else (§3, §12).
    """
    existing = set(connection.introspection.table_names())
    created = []
    with transaction.atomic(using=connection.alias):
        with connection.cursor() as cur:
            for name, ddl in zip((RUNS, FAILURES, COLUMNS), _DDL, strict=True):
                if name not in existing:
                    cur.execute(ddl)
                    created.append(name)
    return created


def require_tables(connection: Any) -> None:
    """Refuse to run when a table is missing or lacks a column (§3)."""
    existing = set(connection.introspection.table_names())
    absent = [n for n in (RUNS, FAILURES, COLUMNS) if n not in existing]
    if absent:
        raise BackfillError(
            f"the state table{'s' if len(absent) > 1 else ''} "
            f"{', '.join(absent)} {'do' if len(absent) > 1 else 'does'} not "
            f"exist in database {connection.alias!r}. Create "
            f"{'them' if len(absent) > 1 else 'it'} with "
            "`fieldseal_backfill init` (it creates what is missing and "
            "alters nothing that exists), or by your own migration from "
            "tools/backfill/PROCEDURE.md §3.")
    with connection.cursor() as cur:
        for name, wanted in ((RUNS, _RUN_COLUMNS),
                             (FAILURES, _FAILURE_COLUMNS),
                             (COLUMNS, _COLUMN_COLUMNS)):
            have = {col.name for col in
                    connection.introspection.get_table_description(cur, name)}
            missing = sorted(set(wanted) - have)
            if missing:
                raise BackfillError(
                    f"the state table {name} lacks {', '.join(missing)} "
                    "(tools/backfill/PROCEDURE.md §3). `fieldseal_backfill "
                    "init` does not alter an existing table; add the "
                    "column by your own migration.")


def insert_run(connection: Any, run: Run, column_uuids: Sequence[str]) -> None:
    """Record a new `running` run, or report the run that holds the table.

    The run row and one zero-count row per column of the run (§3) are one
    transaction. The refusal is the database's, not a read before the
    insert: two starts at once cannot both pass (§3). The run row goes in
    first, so a refused start never reaches the column rows, and the
    transaction would take them back if it did.
    """
    sql = (f"INSERT INTO {RUNS} ({', '.join(_RUN_COLUMNS)}) "
           f"VALUES ({', '.join(['%s'] * len(_RUN_COLUMNS))})")
    column_sql = (f"INSERT INTO {COLUMNS} ({', '.join(_COLUMN_COLUMNS)}) "
                  f"VALUES ({', '.join(['%s'] * len(_COLUMN_COLUMNS))})")
    try:
        with transaction.atomic(using=connection.alias):
            with connection.cursor() as cur:
                try:
                    cur.execute(sql, [getattr(run, c) for c in _RUN_COLUMNS])
                except IntegrityError:
                    # Only the run row's refusal is "the table is held".
                    raise _RunRowRefused from None
                # An error here is what it is, not a held table: it
                # propagates, and the transaction takes the run row back.
                cur.executemany(
                    column_sql,
                    [[run.run_id, uuid_hex, *([0] * len(VALUE_COUNTS))]
                     for uuid_hex in column_uuids])
    except _RunRowRefused:
        raise RunHeld(running_run(connection, run.table_uuid)) from None


def running_run(connection: Any, table_uuid: str) -> str | None:
    """The `run_id` of the run `running` on the table, if any (§3)."""
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT run_id FROM {RUNS} WHERE running_table_uuid = %s",
            [table_uuid])
        row = cur.fetchone()
    return None if row is None else str(row[0])


def load_column_counts(
    connection: Any, run_id: str,
) -> dict[str, dict[str, int]]:
    """A run's per-column counts (§3), by `column_uuid`."""
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT column_uuid, {', '.join(VALUE_COUNTS)} FROM {COLUMNS} "
            "WHERE run_id = %s ORDER BY column_uuid", [run_id])
        return {row[0]: dict(zip(VALUE_COUNTS, map(int, row[1:]), strict=True))
                for row in cur.fetchall()}


def load_run(connection: Any, run_id: str) -> Run | None:
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT {', '.join(_RUN_COLUMNS)} FROM {RUNS} WHERE run_id = %s",
            [run_id])
        row = cur.fetchone()
    return None if row is None else Run(*row)


def converting_runs(connection: Any, table_uuid: str) -> list[Run]:
    """Every `encrypt` run on the table that wrote a value, in any status.

    PROCEDURE §4, *On a new `encrypt` run*: these are the runs whose index
    declarations a new run must match. A run that wrote nothing converted
    nothing, and does not count.
    """
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT {', '.join(_RUN_COLUMNS)} FROM {RUNS} "
            "WHERE table_uuid = %s AND job = 'encrypt' "
            "AND values_written > 0 ORDER BY started_at, run_id",
            [table_uuid])
        rows = cur.fetchall()
    return [Run(*row) for row in rows]


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
    column_counts: dict[str, dict[str, int]],
    cursor_value: str | None,
    failures: list[tuple[str, str, str]],
    complete: bool,
) -> None:
    """§5.2 step 7: the batch's failure rows, counts, cursor and status.

    `column_counts` is the same five value counts per `column_uuid`, added to
    the column rows in the same transaction, so that at every commit each
    count summed over a run's column rows equals the run row's (§3).
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
        column_sets = ", ".join(f"{name} = {name} + %s"
                                for name in VALUE_COUNTS)
        for column, added in column_counts.items():
            cur.execute(
                f"UPDATE {COLUMNS} SET {column_sets} "
                "WHERE run_id = %s AND column_uuid = %s",
                [*(added[name] for name in VALUE_COUNTS), run_id, column])
            if cur.rowcount != 1:
                # Not a DatabaseError, so it is not retried: the run has no
                # row for this column and the batch is rolled back.
                raise BackfillError(
                    f"run {run_id} has no {COLUMNS} row for column "
                    f"{column}, so the batch's per-column counts cannot be "
                    "recorded (PROCEDURE §3). Nothing was written by this "
                    "batch.")


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
