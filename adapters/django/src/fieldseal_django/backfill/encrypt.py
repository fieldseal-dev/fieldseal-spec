"""The `encrypt` job (PROCEDURE §5, §6): plaintext becomes envelopes.

One batch is one transaction: claim the run, select and lock the rows, read
each target column's stored bytes, classify with `is_ciphertext` alone, write
the pending values through `FieldsealQuerySet.bulk_update` so the envelope
and its blind index go in one statement, and record the counts and the
cursor. A process killed at any point leaves the whole batch or none of it.

**What this frontend does not do.** A tenant-bound column's values are
recorded as `CONTEXT_UNAVAILABLE` and left as they were: the adapter takes
the tenant from a context variable, and the procedure does not yet say how a
run records where a row's tenant comes from (#244). In place on a `base64`
column is refused at start (#245). Replication-lag throttling is not
implemented.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from django.core.exceptions import ValidationError
from django.db import Error as DatabaseError
from django.db import connections, router, transaction
from fieldseal.errors import FieldsealError, InvalidArgument

from .. import __version__
from ..apps import get_client
from ..errors import FieldsealNotSupported
from ..fields import Encrypted
from ..query import FieldsealManager
from . import PROCEDURE_VERSION, BackfillError, config, cursor, state
from .ratelimit import TokenBucket

#: PROCEDURE §7.4: the codes a core error may be recorded under.
_CORE_CODES = frozenset({
    "KEY_UNAVAILABLE", "SUITE_NOT_ALLOWED", "AAD_MISMATCH", "TAG_INVALID",
    "COMMITMENT_INVALID", "UNKNOWN_FORMAT_VERSION", "NOT_CIPHERTEXT",
    "LENGTH_EXCEEDED", "SUITE_PROVISIONAL", "MODE_VIOLATION",
    "INVALID_ARGUMENT",
})

#: PROCEDURE §5.4: consecutive database errors before the process exits.
_MAX_DB_ERRORS = 8


@dataclass(frozen=True)
class Limits:
    """The operator settings. Not stored, not hashed, changeable on resume."""

    batch_size: int = 200
    rows_per_second: float = 200.0
    max_failures: int = 100

    def __post_init__(self) -> None:
        if self.batch_size < 1:
            raise BackfillError("--batch-size must be at least 1")
        if not self.rows_per_second > 0:
            raise BackfillError(
                "--rows-per-second must be greater than 0. There is always "
                "a limit (PROCEDURE §5.3).")
        if self.max_failures < 1:
            raise BackfillError("--max-failures must be at least 1")


@dataclass
class Hooks:
    """Points a test stops or interleaves a run at. Unused in production."""

    after_select: Callable[[list[cursor.Row]], None] | None = None
    before_commit: Callable[[int], None] | None = None
    between_batches: Callable[[int], None] | None = None


@dataclass(frozen=True)
class Plan:
    """A table, its key, its target columns and the `config` they make."""

    model: Any
    alias: str
    pk: Any
    key_type: str
    #: `(Encrypted field, legacy source field or None)`.
    targets: list[tuple[Any, Any]]
    config: dict[str, Any]
    config_text: str
    config_hash: str


@dataclass
class Outcome:
    """What one process did, for the final report (PROCEDURE §9 item 4)."""

    run: state.Run
    resumed: bool
    stopped_by_max_failures: bool
    process_rows: int
    process_seconds: float
    failures_by_code: dict[str, int] = field(default_factory=dict)


def plan(model: Any, columns: list[str] | None,
         sources: dict[str, str]) -> Plan:
    """Resolve and check what a run over `model` would do. Writes nothing."""
    name = model.__name__
    meta = getattr(model, "fieldseal", None)
    if meta is None:
        raise BackfillError(
            f"{name} has no `fieldseal = FieldsealMeta(table_uuid=...)`.")
    encrypted = {f.name: f for f in model._meta.fields
                 if isinstance(f, Encrypted)}
    names = list(encrypted) if columns is None else columns
    if not names:
        raise BackfillError(f"{name} declares no Encrypted column.")
    unknown = sorted(set(names) - set(encrypted))
    if unknown:
        raise BackfillError(
            f"{', '.join(unknown)}: not an Encrypted column of {name}.")
    stray = sorted(set(sources) - set(names))
    if stray:
        raise BackfillError(
            f"--source names {', '.join(stray)}, which this run does not "
            "cover.")

    indexed = sorted(c for c in names if encrypted[c].index is not None)
    if indexed and not isinstance(model._default_manager, FieldsealManager):
        raise BackfillError(
            f"{name}'s default manager is a "
            f"{type(model._default_manager).__name__}, not a FieldsealManager, "
            f"and {', '.join(indexed)} carries a blind index. The backfill "
            "writes through `bulk_update` on that manager, and a plain "
            "manager leaves the index unwritten (docs/12 §6).")

    plain = {f.name: f for f in model._meta.concrete_fields
             if not isinstance(f, Encrypted)}
    targets = []
    for column in names:
        target = encrypted[column]
        source = None
        if column in sources:
            source = plain.get(sources[column])
            if source is None:
                raise BackfillError(
                    f"--source {column}={sources[column]}: {sources[column]} "
                    f"is not a plaintext column of {name}.")
        elif target.storage == "base64":
            raise BackfillError(
                f"{name}.{column} is stored as base64, and this run would "
                "encrypt it in place. The adapter's permissive read of a "
                "base64 column decodes legacy text as base64 before the core "
                "sees it, so the value read back is not the value stored "
                "(#245). Use the two-column shape: --source "
                f"{column}=<legacy column>.")
        targets.append((target, source))

    client = get_client()
    mode = client.read_mode
    if mode == "readonly":
        raise BackfillError(
            "the client is `readonly`, and `encrypt` writes "
            "(PROCEDURE §2 item 4).")
    in_place = [f.name for f, s in targets if s is None]
    if in_place and mode != "permissive":
        raise BackfillError(
            f"{', '.join(in_place)}: encrypting in place reads the legacy "
            "value through the adapter, and in `strict` that read raises "
            "NOT_CIPHERTEXT. Set FIELDSEAL['READ_MODE'] = 'permissive' for "
            "this process, or name a legacy column with --source "
            "(PROCEDURE §2 item 4).")

    pk, key_type = cursor.key_field(model)
    document = config.build(
        job="encrypt",
        table_uuid=meta.table_uuid_bytes,
        write_suite=client.write_suite,
        cursor=[(pk.column, key_type)],
        targets=[(f, None if s is None else s.column) for f, s in targets],
        indexes=client.indexes,
    )
    text = config.serialize(document)
    return Plan(
        model=model,
        alias=router.db_for_write(model),
        pk=pk,
        key_type=key_type,
        targets=targets,
        config=document,
        config_text=text,
        config_hash=config.digest(text),
    )


def plan_for(run: state.Run, models: list[Any]) -> Plan:
    """The plan a stored run resumes under, rebuilt from the live code.

    The column set and each column's legacy source are the run's own, read
    from its stored `config`; everything else is rebuilt from the live client
    and declarations and compared (PROCEDURE §4, *On resume*).
    """
    if run.procedure_version != PROCEDURE_VERSION:
        raise BackfillError(
            f"run {run.run_id} was written under procedure version "
            f"{run.procedure_version}. This frontend implements version "
            f"{PROCEDURE_VERSION} and will not resume it.")
    if run.job != "encrypt":
        raise BackfillError(
            f"run {run.run_id} is a `{run.job}` job, which this frontend "
            "does not implement.")
    stored = json.loads(run.config)
    model = next(
        (m for m in models
         if getattr(getattr(m, "fieldseal", None), "table_uuid_bytes",
                    b"").hex() == run.table_uuid), None)
    if model is None:
        raise BackfillError(
            f"no installed model has table_uuid {run.table_uuid}. "
            "Differs: table_uuid.")
    by_uuid = {f.column_uuid.hex(): f for f in model._meta.fields
               if isinstance(f, Encrypted)}
    by_column = {f.column: f for f in model._meta.concrete_fields}
    columns, sources, gone = [], {}, []
    for entry in stored["columns"]:
        target = by_uuid.get(entry["column_uuid"])
        if target is None:
            gone.append(f"columns[{entry['column_uuid']}]")
            continue
        columns.append(target.name)
        if entry["source"] is not None:
            source = by_column.get(entry["source"])
            if source is None:
                gone.append(f"columns[{entry['column_uuid']}].source")
                continue
            sources[target.name] = source.name
    if gone:
        raise BackfillError(_refusal(run.run_id, gone))
    live = plan(model, columns, sources)
    differing = config.differences(stored, live.config)
    if differing or live.config_hash != run.config_hash:
        raise BackfillError(_refusal(run.run_id, differing or ["config"]))
    return live


def _refusal(run_id: str, members: list[str]) -> str:
    return (f"run {run_id} cannot be resumed: the configuration it was "
            "started with differs from the live one, so the rest of the "
            "table would be written differently from the part already "
            f"done (PROCEDURE §4). Differs: {', '.join(members)}.")


def table_has_rows(p: Plan) -> bool:
    connection = connections[p.alias]
    q = connection.ops.quote_name
    with connection.cursor() as cur:
        cur.execute(f"SELECT 1 FROM {q(p.model._meta.db_table)} LIMIT 1")
        return cur.fetchone() is not None


def new_run(p: Plan) -> state.Run:
    """Insert the run row. Raises `state.RunHeld` if the table is taken."""
    at = state.now()
    run = state.Run(
        run_id=str(uuid.uuid4()),
        procedure_version=PROCEDURE_VERSION,
        job="encrypt",
        table_uuid=p.config["table_uuid"],
        running_table_uuid=p.config["table_uuid"],
        table_name=p.model._meta.db_table,
        config_hash=p.config_hash,
        config=p.config_text,
        status="running",
        batch_seq=0,
        cursor_value=None,
        rows_scanned=0,
        values_written=0,
        values_current=0,
        values_null=0,
        values_anomalous=0,
        values_failed=0,
        started_at=at,
        updated_at=at,
        completed_at=None,
        frontend=f"django/{__version__}",
    )
    state.insert_run(connections[p.alias], run)
    return run


def check_connection(connection: Any) -> None:
    """The batch must be its own transaction, and on SQLite an immediate one."""
    if connection.in_atomic_block:
        raise BackfillError(
            "the backfill was started inside a transaction. A batch is one "
            "transaction of its own (PROCEDURE §5.2); run it outside "
            "`atomic()`.")
    if connection.vendor == "sqlite":
        connection.ensure_connection()
        if getattr(connection, "transaction_mode", None) != "IMMEDIATE":
            raise BackfillError(
                "on SQLite a batch must take the write lock when it begins "
                "(PROCEDURE §5.2 step 2). Set "
                "DATABASES[...]['OPTIONS']['transaction_mode'] = 'IMMEDIATE' "
                "for this process.")


class LostRun(BackfillError):
    """§5.2 step 3 changed no row."""

    def __init__(self, run_id: str) -> None:
        super().__init__(
            f"run {run_id} is owned by another process, or has ended "
            "(PROCEDURE §5.2 step 3). Nothing was written by this batch.")


class Runner:
    """One process's work on one run."""

    def __init__(
        self,
        p: Plan,
        run: state.Run,
        limits: Limits,
        *,
        resumed: bool = False,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        hooks: Hooks | None = None,
    ) -> None:
        self.plan = p
        self.limits = limits
        self.resumed = resumed
        self.hooks = hooks or Hooks()
        self._connection = connections[p.alias]
        self._manager = p.model._default_manager.using(p.alias)
        self._client = get_client()
        self._clock = clock
        self._sleep = sleep
        self._run_id = run.run_id
        # The `batch_seq` this process last read or wrote (§5.2 step 3).
        self._batch_seq = run.batch_seq
        self._after = (None if run.cursor_value is None
                       else cursor.decode_key(p.key_type, run.cursor_value))
        self._failures = 0
        self._rows = 0

    def run(self) -> Outcome:
        check_connection(self._connection)
        bucket = TokenBucket(self.limits.rows_per_second,
                             self.limits.batch_size, self._clock, self._sleep)
        started = self._clock()
        errors = 0
        stopped = False
        while True:
            bucket.take(self.limits.batch_size)
            try:
                done = self._batch()
            except DatabaseError as e:
                # §5.4. The rolled-back batch changed nothing, so the retry
                # starts from the same cursor with the same `batch_seq`.
                errors += 1
                if errors >= _MAX_DB_ERRORS:
                    raise BackfillError(
                        f"{errors} consecutive database errors, the last a "
                        f"{type(e).__name__}. The run is still `running`; "
                        "resume it when the database is healthy.") from None
                self._sleep(min(60.0, 2.0 ** (errors - 1)))
                continue
            errors = 0
            if done:
                break
            # §7.4: tested once per batch, and the batch that reached it is
            # committed, so the resume starts beyond the rows that failed.
            if self._failures >= self.limits.max_failures:
                stopped = True
                break
            if self.hooks.between_batches is not None:
                self.hooks.between_batches(self._batch_seq)
        seconds = self._clock() - started
        final = state.load_run(self._connection, self._run_id)
        assert final is not None
        return Outcome(
            run=final,
            resumed=self.resumed,
            stopped_by_max_failures=stopped,
            process_rows=self._rows,
            process_seconds=seconds,
            failures_by_code=state.failures_by_code(
                self._connection, self._run_id),
        )

    # -- one batch (PROCEDURE §5.2 steps 2 to 8) ----------------------------

    def _batch(self) -> bool:
        p = self.plan
        n = self.limits.batch_size
        with transaction.atomic(using=p.alias):
            if not state.claim(self._connection, self._run_id,
                               self._batch_seq):
                raise LostRun(self._run_id)
            seq = self._batch_seq + 1
            rows = cursor.select_batch(
                self._connection, p.model, p.pk, p.targets,
                after=self._after, limit=n, lock=True)
            if self.hooks.after_select is not None:
                self.hooks.after_select(rows)
            counts, failures = self._process(rows)
            done = len(rows) < n
            last = rows[-1].key if rows else None
            state.record(
                self._connection, self._run_id,
                batch_seq=seq,
                counts=counts,
                cursor_value=(None if last is None
                              else cursor.encode_key(p.key_type, last)),
                failures=failures,
                complete=done,
            )
            if self.hooks.before_commit is not None:
                self.hooks.before_commit(seq)
        # Committed. Nothing above this line may be kept from a batch that
        # rolled back.
        self._batch_seq = seq
        if last is not None:
            self._after = last
        self._failures += len(failures)
        self._rows += len(rows)
        return done

    def _process(
        self, rows: list[cursor.Row],
    ) -> tuple[dict[str, int], list[tuple[str, str, str]]]:
        p = self.plan
        counts = dict.fromkeys(state.COUNTS, 0)
        counts["rows_scanned"] = len(rows)
        failures: list[tuple[str, str, str]] = []

        # §6.2, from the stored bytes alone: no decrypt and no key.
        pending: list[tuple[cursor.Row, int]] = []
        for row in rows:
            for i, (target, source) in enumerate(p.targets):
                kind = self._classify(row, i, target, source)
                if kind == "pending":
                    pending.append((row, i))
                else:
                    counts[f"values_{kind}"] += 1

        legacy = self._legacy_values(pending)
        for row, i in pending:
            target, source = p.targets[i]
            code = self._encrypt(row, i, target, source, legacy)
            if code is None:
                counts["values_written"] += 1
            else:
                counts["values_failed"] += 1
                failures.append((cursor.encode_key(p.key_type, row.key),
                                 target.column_uuid.hex(), code))
        return counts, failures

    def _classify(self, row: cursor.Row, i: int, target: Any,
                  source: Any) -> str:
        stored = row.stored[i]
        if stored is not None:
            blob = cursor.stored_bytes(stored, target.storage)
            if blob is not None and self._client.is_ciphertext(blob):
                return "current"
            # Two columns: the target holds something this tool did not put
            # there. In place: the legacy value.
            return "pending" if source is None else "anomalous"
        if source is None or row.source_null[i]:
            return "null"
        return "pending"

    def _legacy_values(
        self, pending: list[tuple[cursor.Row, int]],
    ) -> dict[Any, tuple[Any, ...]]:
        """The legacy columns of the pending rows, by the ORM's ordinary read."""
        p = self.plan
        names = [s.name for _, s in p.targets if s is not None]
        keys = {row.key for row, i in pending if p.targets[i][1] is not None}
        if not names or not keys:
            return {}
        found = self._manager.filter(pk__in=keys).values_list("pk", *names)
        return {record[0]: record[1:] for record in found}

    def _encrypt(self, row: cursor.Row, i: int, target: Any, source: Any,
                 legacy: dict[Any, tuple[Any, ...]]) -> str | None:
        """§6.3 for one value. Returns None, or the failure's error code.

        A database error is not caught: it aborts the batch (§5.2 step 6).
        """
        p = self.plan
        if target._is_tenant_bound():
            # The frontend has no way to learn the row's tenant, and a row is
            # never written under a context that was guessed (§6.3, #244).
            return "CONTEXT_UNAVAILABLE"
        try:
            if source is None:
                # In place: the adapter's own permissive read, applied to the
                # bytes this batch selected and locked.
                value = target.from_db_value(
                    row.stored[i], None, self._connection)
            else:
                names = [s.name for _, s in p.targets if s is not None]
                record = legacy.get(row.key)
                if record is None:
                    return "INTERNAL"
                value = record[names.index(source.name)]
            obj = p.model(pk=row.key)
            setattr(obj, target.attname, value)
            # A savepoint, because Django's `bulk_update` runs in
            # `atomic(savepoint=False)`: without one, a refusal raised while
            # the statement is compiled would mark the whole batch for
            # rollback.
            with transaction.atomic(using=p.alias):
                updated = self._manager.bulk_update([obj], [target.name])
            return None if updated == 1 else "INTERNAL"
        except DatabaseError:
            raise
        except Exception as e:  # noqa: BLE001 - a value failure, by its code
            return _error_code(e)


def _error_code(e: Exception) -> str:
    """PROCEDURE §7.4. Only ever a code: a message can carry a value."""
    if isinstance(e, FieldsealNotSupported):
        return "RENDERING_REFUSED"
    if isinstance(e, ValidationError):
        # `EncryptedIndex.derive` raises this for a value the index refuses.
        return ("INVALID_ARGUMENT" if isinstance(e.__cause__, InvalidArgument)
                else "INTERNAL")
    if isinstance(e, FieldsealError) and e.code in _CORE_CODES:
        return str(e.code)
    return "INTERNAL"
