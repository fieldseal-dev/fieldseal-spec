"""The backfill frontend's `encrypt` job, against a live database.

`tools/backfill/PROCEDURE.md` §10 lists the scenarios every frontend runs,
and a test for each one this frontend can build cites its id in its name
(`test_bf01_...`). Not here, and why:

- BF-11, BF-12, BF-13, BF-15k: **blocked** on the header accessor of
  PROCEDURE §11's D-1 (#241), as in every frontend.
- BF-15: `verify` is not built yet.

"Bytes unchanged" means the column's stored bytes, read with a raw cursor,
compare equal before and after. Every test runs outside a transaction
(`transaction=True`): a batch is its own transaction, and the runner refuses
to start inside another.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import json
import pathlib
import re
import threading
import time
import uuid
from io import StringIO

import pytest
from django.apps import apps as django_apps
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import OperationalError, connection, connections, transaction
from django.test.utils import isolate_apps, override_settings

from fieldseal_django import Encrypted, FieldsealMeta, tenant_scope
from fieldseal_django.apps import get_client, reset_client
from fieldseal_django.backfill import BackfillError, config, cursor, encrypt, state
from fieldseal_django.backfill.census import census
from fieldseal_django.backfill.ratelimit import TokenBucket
from fieldseal_django.backfill.report import PREEXISTING_BACKUPS
from fieldseal_django.query import FieldsealManager
from tests.models import (
    LegacyInPlace,
    LegacyTwoColumn,
    LegacyUuidKey,
    Patient,
    TenantDoc,
)

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.filterwarnings(
        "ignore::fieldseal.errors.FieldsealWarning"),
]

PROCEDURE = (pathlib.Path(__file__).resolve().parents[3]
             / "tools" / "backfill" / "PROCEDURE.md")

#: Small batches and a rate that never binds; BF-14 sets its own.
FAST = encrypt.Limits(batch_size=10, rows_per_second=100_000)

#: A reserved-version value: `fmt_ver` 0x02 and long enough to be one
#: (PROCEDURE §6.3). Not an envelope to `is_ciphertext`; unreadable in
#: every mode.
RESERVED = b"\x02" + b"\x5a" * 150


class Kill(BaseException):
    """A process death. Not an `Exception`, so nothing in the runner may
    catch it and carry on."""


class FakeTime:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


# -- fixtures -----------------------------------------------------------------

@pytest.fixture(autouse=True)
def state_tables():
    """`init` before, and a drop after: the tables are not Django models, so
    the test database's flush does not empty them."""
    state.init(connection)
    yield
    with connection.cursor() as cur:
        cur.execute(f"DROP TABLE {state.RUNS}")
        cur.execute(f"DROP TABLE {state.FAILURES}")


@pytest.fixture
def permissive():
    cfg = dict(settings.FIELDSEAL)
    cfg["READ_MODE"] = "permissive"
    with override_settings(FIELDSEAL=cfg):
        reset_client()
        yield
    reset_client()


class InPlace:
    """The encrypted column itself holds the legacy bytes."""

    name = "in_place"
    model = LegacyInPlace
    field = "secret"
    index = "secret_bidx"
    columns = ["secret"]
    sources: dict[str, str] = {}

    def seed(self, values):
        keys = []
        for value in values:
            obj = self.model.objects.create()
            if value is not None:
                plant(self.model, obj.pk, "secret", value.encode("utf-8"))
            keys.append(obj.pk)
        return keys

    def app_write(self, pk, value):
        self.model.objects.filter(pk=pk).update(secret=value)


class TwoColumn:
    """A legacy plaintext column beside the encrypted one."""

    name = "two_column"
    model = LegacyTwoColumn
    field = "email"
    index = "email_bidx"
    columns = ["email"]
    sources = {"email": "email_legacy"}

    def seed(self, values):
        return [self.model.objects.create(email_legacy=v).pk for v in values]

    def app_write(self, pk, value):
        # Dual-write (docs/04 §11 step 2): the application keeps both.
        self.model.objects.filter(pk=pk).update(
            email=value, email_legacy=value)


@pytest.fixture(params=[InPlace, TwoColumn], ids=lambda s: s.name)
def shape(request):
    if request.param is InPlace:
        request.getfixturevalue("permissive")
    return request.param()


@pytest.fixture
def in_place(permissive):
    return InPlace()


# -- helpers ------------------------------------------------------------------

def _bytes(value):
    return value.tobytes() if isinstance(value, memoryview) else value


def raw(model, pk, column):
    q = connection.ops.quote_name
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT {q(column)} FROM {q(model._meta.db_table)} "
            f"WHERE {q(model._meta.pk.column)} = %s",
            [model._meta.pk.get_db_prep_value(pk, connection)])
        return _bytes(cur.fetchone()[0])


def all_raw(model, column):
    q = connection.ops.quote_name
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT {q(model._meta.pk.column)}, {q(column)} "
            f"FROM {q(model._meta.db_table)}")
        return {model._meta.pk.to_python(k): _bytes(v)
                for k, v in cur.fetchall()}


def plant(model, pk, column, value):
    q = connection.ops.quote_name
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {q(model._meta.db_table)} SET {q(column)} = %s "
            f"WHERE {q(model._meta.pk.column)} = %s", [value, pk])


def emails(n, tag="row"):
    return [f"{tag}-{i:03d}@backfill.example" for i in range(n)]


def begin(shape_or_model, *, columns=None, sources=None):
    """Plan and insert a run, as `fieldseal_backfill encrypt` does."""
    if isinstance(shape_or_model, InPlace | TwoColumn):
        p = encrypt.plan(shape_or_model.model, shape_or_model.columns,
                         shape_or_model.sources)
    else:
        p = encrypt.plan(shape_or_model, columns, sources or {})
    return p, encrypt.new_run(p)


def drive(p, run, *, limits=FAST, hooks=None, resumed=False, clock=None):
    t = clock or FakeTime()
    return encrypt.Runner(p, run, limits, resumed=resumed, clock=t.clock,
                          sleep=t.sleep, hooks=hooks).run()


def go(shape_or_model, **kwargs):
    plan_kwargs = {k: kwargs.pop(k) for k in ("columns", "sources")
                   if k in kwargs}
    p, run = begin(shape_or_model, **plan_kwargs)
    return drive(p, run, **kwargs)


def resume(run_id, **kwargs):
    run = state.load_run(connection, run_id)
    p = encrypt.plan_for(run, list(django_apps.get_models()))
    return drive(p, run, resumed=True, **kwargs)


def kill_after_batch(n):
    def hook(seq):
        if seq == n:
            raise Kill
    return encrypt.Hooks(between_batches=hook)


def non_envelopes(model, field_name):
    pk, _ = cursor.key_field(model)
    f = model._meta.get_field(field_name)
    t = FakeTime()
    counts = census(model, "default", pk, [f], batch_size=7,
                    bucket=TokenBucket(100_000, 7, t.clock, t.sleep))
    return counts[f.column_uuid.hex()]


def in_thread(fn):
    """Run `fn` on its own connection, as a second process would."""
    box: dict = {}

    def body():
        try:
            box["value"] = fn()
        except BaseException as e:  # noqa: BLE001 - reported to the test
            box["error"] = e
        finally:
            connections.close_all()

    thread = threading.Thread(target=body)
    thread.start()
    return thread, box


def state_dump():
    out = []
    with connection.cursor() as cur:
        for table in (state.RUNS, state.FAILURES):
            cur.execute(f"SELECT * FROM {table}")
            out.extend(repr(row) for row in cur.fetchall())
    return "\n".join(out)


_RUN_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def assert_no_leak(text, model, plaintexts, columns):
    """PROCEDURE §9 item 5, over output and both state tables."""
    # A run id is a random UUID the tool makes up, and a 15-bit index is two
    # bytes: its four hex digits turn up inside one by chance (seen: `9be8`).
    # A run id carries no value, so run ids are taken out before the search.
    haystack = _RUN_ID.sub("<run>", text + "\n" + state_dump())
    for value in plaintexts:
        assert value not in haystack
    for column in columns:
        for stored in all_raw(model, column).values():
            if stored is None:
                continue
            blob = stored.encode() if isinstance(stored, str) else stored
            assert blob.hex() not in haystack
            assert base64.b64encode(blob).decode() not in haystack
            assert repr(blob)[2:-1] not in haystack


def command(*args):
    out, err = StringIO(), StringIO()
    try:
        call_command("fieldseal_backfill", *args, stdout=out, stderr=err)
        error = None
    except CommandError as e:
        error = e
    return out.getvalue(), err.getvalue(), error


# -- BF-01: a fresh table ------------------------------------------------------

def test_bf01_encrypt_converts_a_fresh_table(shape):
    values = emails(25)
    keys = shape.seed(values)

    outcome = go(shape)

    run = outcome.run
    assert run.status == "complete" and run.completed_at is not None
    assert run.running_table_uuid is None
    assert (run.rows_scanned, run.values_written) == (25, 25)
    assert run.values_failed == run.values_anomalous == 0
    assert run.batch_seq == 3  # 10 + 10 + 5
    assert non_envelopes(shape.model, shape.field) == {
        "null": 0, "envelope": 25, "non_envelope": 0}
    for pk, value in zip(keys, values, strict=True):
        assert getattr(shape.model.objects.get(pk=pk), shape.field) == value
        assert raw(shape.model, pk, shape.index) is not None
        found = shape.model.objects.filter(**{shape.field: value})
        assert [o.pk for o in found] == [pk]


def test_bf01_the_index_written_is_the_one_a_save_would_write(shape):
    """The same statement writes the blind index (PROCEDURE §6.3 rule 3)."""
    (pk,) = shape.seed(["same@backfill.example"])
    go(shape)
    twin = shape.model.objects.create(**{shape.field: "same@backfill.example"})
    assert raw(shape.model, pk, shape.index) == raw(
        shape.model, twin.pk, shape.index)


def test_a_row_the_default_manager_hides_is_converted(shape, monkeypatch):
    """A soft-delete default manager filters rows out of every queryset it
    hands back. The batch selects with raw SQL and sees them all, so the
    legacy read and the write must not go through that manager: a hidden
    row was classified pending, then neither read nor written."""
    values = emails(3)
    keys = shape.seed(values)
    hidden = keys[1]

    class Hiding(FieldsealManager):
        def get_queryset(self):
            return super().get_queryset().exclude(pk=hidden)

    manager = Hiding()
    manager.model = shape.model
    monkeypatch.setitem(
        shape.model._meta.__dict__, "default_manager", manager)
    assert [o.pk for o in shape.model._default_manager.all()] == [
        keys[0], keys[2]]

    outcome = go(shape)

    assert outcome.run.status == "complete"
    assert (outcome.run.values_written, outcome.run.values_failed) == (3, 0)
    assert outcome.failures_by_code == {}
    assert non_envelopes(shape.model, shape.field) == {
        "null": 0, "envelope": 3, "non_envelope": 0}
    assert getattr(shape.model.objects.get(pk=hidden), shape.field) == values[1]
    found = shape.model.objects.filter(**{shape.field: values[1]})
    assert [o.pk for o in found] == [hidden]


def test_bf01_through_the_command(shape):
    values = emails(12)
    shape.seed(values)
    args = [f"--source={k}={v}" for k, v in shape.sources.items()]
    out, _, error = command(
        "encrypt", f"tests.{shape.model.__name__}", "--columns",
        ",".join(shape.columns), "--batch-size", "5", "--rows-per-second",
        "100000", "--acknowledge-preexisting-backups", *args)
    assert error is None
    report = json.loads(out.splitlines()[-1])
    assert report["status"] == "complete" and report["fully_converted"]
    assert report["values_written"] == 12 and report["batch_seq"] == 3
    assert report["process"]["rows_scanned"] == 12
    # §9 item 3: the run id, the job, new or resumed, config, limits, lag.
    assert f"run {report['run_id']}: job encrypt, new" in out
    assert state.load_run(connection, report["run_id"]).config in out
    assert "batch_size=5" in out and "replication-lag throttling: not" in out


# -- BF-02, BF-03: kills -------------------------------------------------------

def test_bf02_killed_between_batches_then_resumed(shape):
    values = emails(25)
    keys = shape.seed(values)
    p, run = begin(shape)

    with pytest.raises(Kill):
        drive(p, run, hooks=kill_after_batch(1))

    midway = state.load_run(connection, run.run_id)
    assert midway.status == "running" and midway.batch_seq == 1
    assert midway.cursor_value == json.dumps([str(keys[9])])
    converted = {pk: raw(shape.model, pk, shape.field) for pk in keys[:10]}
    assert all(get_client().is_ciphertext(b) for b in converted.values())
    assert not get_client().is_ciphertext(
        raw(shape.model, keys[10], shape.field) or b"")

    outcome = resume(run.run_id)

    assert outcome.resumed and outcome.process_rows == 15
    assert {pk: raw(shape.model, pk, shape.field)
            for pk in keys[:10]} == converted
    final = outcome.run
    assert final.status == "complete"
    assert (final.rows_scanned, final.values_written,
            final.batch_seq) == (25, 25, 3)
    assert non_envelopes(shape.model, shape.field)["non_envelope"] == 0
    for pk, value in zip(keys, values, strict=True):
        assert getattr(shape.model.objects.get(pk=pk), shape.field) == value
        assert [o.pk for o in shape.model.objects.filter(
            **{shape.field: value})] == [pk]


def test_bf03_killed_inside_a_batch_before_commit(shape):
    keys = shape.seed(emails(25))
    p, run = begin(shape)
    seen = {}

    def die_in_second(seq):
        if seq == 2:
            # The data writes of this batch have been issued.
            seen["written"] = raw(shape.model, keys[10], shape.field)
            raise Kill

    with pytest.raises(Kill):
        drive(p, run, hooks=encrypt.Hooks(before_commit=die_in_second))

    assert get_client().is_ciphertext(seen["written"])
    after = state.load_run(connection, run.run_id)
    assert after.batch_seq == 1
    assert after.cursor_value == json.dumps([str(keys[9])])
    assert (after.rows_scanned, after.values_written) == (10, 10)
    for pk in keys[10:]:
        stored = raw(shape.model, pk, shape.field)
        assert not get_client().is_ciphertext(stored or b"")
        assert raw(shape.model, pk, shape.index) is None


# -- BF-04: idempotence --------------------------------------------------------

def test_bf04_a_new_run_over_a_completed_table_writes_nothing(shape):
    shape.seed(emails(25))
    go(shape)
    before = (all_raw(shape.model, shape.field),
              all_raw(shape.model, shape.index))

    outcome = go(shape)

    assert outcome.run.status == "complete"
    assert outcome.run.values_written == 0
    assert outcome.run.values_current == 25
    assert (all_raw(shape.model, shape.field),
            all_raw(shape.model, shape.index)) == before


# -- BF-05, BF-18: refusals on resume -----------------------------------------

def _killed_run(shape):
    shape.seed(emails(25))
    p, run = begin(shape)
    with pytest.raises(Kill):
        drive(p, run, hooks=kill_after_batch(1))
    return run.run_id


def _snapshot(shape, run_id):
    return (all_raw(shape.model, shape.field),
            all_raw(shape.model, shape.index),
            state.load_run(connection, run_id))


@contextlib.contextmanager
def other_write_suite(monkeypatch):
    """The live client reporting another write suite.

    Patched on the client's reflection rather than configured: the only
    other registered suite, 0xFF02, has no backend in this build (G7), so a
    client that really writes under it cannot be constructed here.
    """
    with monkeypatch.context() as m:
        m.setattr(type(get_client()), "write_suite",
                  property(lambda self: 0xFF02))
        yield


def test_bf05_resume_with_a_changed_index_parameter_is_refused(
        shape, monkeypatch):
    run_id = _killed_run(shape)
    before = _snapshot(shape, run_id)
    field = shape.model._meta.get_field(shape.field)
    monkeypatch.setattr(
        field, "index", dataclasses.replace(field.index, truncate_bits=14))
    reset_client()
    try:
        with pytest.raises(BackfillError) as refused:
            resume(run_id)
    finally:
        monkeypatch.undo()
        reset_client()
    assert (f"columns[{field.column_uuid.hex()}].indexes[exact]"
            ".truncate_bits") in str(refused.value)
    assert _snapshot(shape, run_id) == before


def test_bf05_resume_with_a_changed_write_suite_is_refused(
        shape, monkeypatch):
    run_id = _killed_run(shape)
    before = _snapshot(shape, run_id)
    with other_write_suite(monkeypatch):
        with pytest.raises(BackfillError) as refused:
            resume(run_id)
    assert "Differs: write_suite." in str(refused.value)
    assert _snapshot(shape, run_id) == before


def test_bf05_the_command_names_the_member_and_writes_nothing(
        shape, monkeypatch):
    run_id = _killed_run(shape)
    before = _snapshot(shape, run_id)
    with other_write_suite(monkeypatch):
        _, _, error = command("resume", run_id)
    assert "write_suite" in str(error)
    assert _snapshot(shape, run_id) == before


def test_bf18_a_run_row_of_procedure_version_2_is_refused(shape):
    run_id = _killed_run(shape)
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {state.RUNS} SET procedure_version = 2 "
            "WHERE run_id = %s", [run_id])
    before = _snapshot(shape, run_id)

    with pytest.raises(BackfillError, match="procedure version 2"):
        resume(run_id)
    _, _, error = command("resume", run_id)

    assert "procedure version 2" in str(error)
    assert _snapshot(shape, run_id) == before


# -- BF-06, BF-07, BF-19: two connections -------------------------------------

def test_bf06_a_second_process_resuming_mid_batch_exits_at_the_claim(shape):
    shape.seed(emails(30))
    p, run = begin(shape)
    selected, release = threading.Event(), threading.Event()

    def hold(rows):
        if not selected.is_set():
            selected.set()
            assert release.wait(30)

    first, first_box = in_thread(
        lambda: drive(p, run, hooks=encrypt.Hooks(after_select=hold)))
    assert selected.wait(30)
    # The second process read the same run row: batch_seq 0.
    second, second_box = in_thread(lambda: encrypt.Runner(
        p, run, FAST, sleep=lambda s: time.sleep(0.02)).run())
    second.join(0.75)
    waiting = second.is_alive()
    release.set()
    first.join(60)
    second.join(60)

    assert waiting  # held by the first batch's transaction
    assert isinstance(second_box.get("error"), encrypt.LostRun)
    outcome = first_box["value"]
    assert outcome.run.status == "complete"
    assert (outcome.run.rows_scanned, outcome.run.values_written,
            outcome.run.batch_seq) == (30, 30, 4)


def test_bf07_an_application_update_to_a_selected_row_is_not_lost(shape):
    keys = shape.seed(emails(5))
    target = keys[2]
    box: dict = {}

    def interleave(rows):
        assert target in [row.key for row in rows]
        box["thread"], box["result"] = in_thread(
            lambda: shape.app_write(target, "fresh@backfill.example"))
        box["thread"].join(0.75)
        box["blocked"] = box["thread"].is_alive()

    outcome = go(shape, hooks=encrypt.Hooks(after_select=interleave))
    box["thread"].join(60)

    assert "error" not in box["result"]
    assert box["blocked"]  # the batch's lock held the application's write
    assert outcome.run.status == "complete"
    obj = shape.model.objects.get(pk=target)
    assert getattr(obj, shape.field) == "fresh@backfill.example"
    assert get_client().is_ciphertext(raw(shape.model, target, shape.field))
    assert [o.pk for o in shape.model.objects.filter(
        **{shape.field: "fresh@backfill.example"})] == [target]
    assert not shape.model.objects.filter(
        **{shape.field: "row-002@backfill.example"})


def test_bf19_two_starts_at_once_leave_one_run(shape):
    shape.seed(emails(3))
    p = encrypt.plan(shape.model, shape.columns, shape.sources)
    barrier = threading.Barrier(2)

    def start():
        barrier.wait(30)
        return encrypt.new_run(p)

    threads = [in_thread(start) for _ in range(2)]
    for thread, _ in threads:
        thread.join(60)
    boxes = [box for _, box in threads]

    winners = [b["value"] for b in boxes if "value" in b]
    losers = [b["error"] for b in boxes if "error" in b]
    assert len(winners) == 1 and len(losers) == 1
    assert isinstance(losers[0], state.RunHeld)
    assert losers[0].holder == winners[0].run_id
    assert winners[0].run_id in str(losers[0])
    with connection.cursor() as cur:
        cur.execute(f"SELECT run_id FROM {state.RUNS}")
        assert cur.fetchall() == [(winners[0].run_id,)]


def test_an_abandoned_run_releases_its_table(shape):
    run_id = _killed_run(shape)
    with pytest.raises(state.RunHeld):
        begin(shape)

    out, _, error = command("abandon", run_id)

    assert error is None and run_id in out
    abandoned = state.load_run(connection, run_id)
    assert abandoned.status == "abandoned"
    assert abandoned.running_table_uuid is None
    _, _, again = command("resume", run_id)
    assert "`abandoned`" in str(again)
    assert go(shape).run.values_written == 15  # the first ten stay converted


# -- BF-08, BF-09: values the run leaves alone ---------------------------------

def test_bf08_null_values_are_counted_and_left_null(shape):
    keys = shape.seed([None, "kept@backfill.example", None])

    outcome = go(shape)

    assert (outcome.run.values_null, outcome.run.values_written) == (2, 1)
    assert outcome.run.values_failed == 0
    for pk in (keys[0], keys[2]):
        assert raw(shape.model, pk, shape.field) is None
        assert raw(shape.model, pk, shape.index) is None


def test_bf09_a_reserved_version_value_fails_and_is_left_as_it_was(in_place):
    keys = in_place.seed(emails(3))
    plant(LegacyInPlace, keys[1], "secret", RESERVED)

    outcome = go(in_place)

    assert outcome.run.status == "complete"
    assert (outcome.run.values_written, outcome.run.values_failed) == (2, 1)
    assert outcome.failures_by_code == {"UNKNOWN_FORMAT_VERSION": 1}
    assert raw(LegacyInPlace, keys[1], "secret") == RESERVED
    assert raw(LegacyInPlace, keys[1], "secret_bidx") is None
    with connection.cursor() as cur:
        cur.execute(f"SELECT run_id, row_key, column_uuid, error_code, "
                    f"batch_seq FROM {state.FAILURES}")
        assert cur.fetchall() == [(
            outcome.run.run_id, json.dumps([str(keys[1])]),
            LegacyInPlace._meta.get_field("secret").column_uuid.hex(),
            "UNKNOWN_FORMAT_VERSION", 1)]


def test_bf09_the_report_says_the_table_is_not_fully_converted(in_place):
    keys = in_place.seed(emails(3))
    plant(LegacyInPlace, keys[1], "secret", RESERVED)

    out, _, error = command(
        "encrypt", "tests.LegacyInPlace", "--columns", "secret",
        "--rows-per-second", "100000", "--acknowledge-preexisting-backups")

    assert error is None
    lines = out.splitlines()
    final = lines[lines.index(next(
        line for line in lines if line.startswith("replication-lag"))) + 1:]
    assert "NOT fully converted" in final[0]
    report = json.loads(lines[-1])
    assert report["status"] == "complete" and not report["fully_converted"]
    assert report["failures_by_code"] == {"UNKNOWN_FORMAT_VERSION": 1}


@pytest.mark.skipif(connection.vendor != "sqlite", reason="SQLite only")
def test_in_place_on_sqlite_a_text_class_value_is_converted(in_place):
    """SQLite keeps a value's storage class whatever the column is declared
    as, so a column rebuilt from a `CharField` by `AlterField` holds TEXT
    inside a `BLOB` column. The adapter's read handed the core a `str`, and
    every such value was an `INTERNAL` failure, left as it was (#251)."""
    keys = in_place.seed(emails(3))
    plant(LegacyInPlace, keys[1], "secret", "text@backfill.example")
    with connection.cursor() as cur:
        cur.execute("SELECT typeof(secret) FROM tests_legacyinplace "
                    "ORDER BY id")
        assert [r[0] for r in cur.fetchall()] == ["blob", "text", "blob"]

    outcome = go(in_place)

    assert (outcome.run.values_written, outcome.run.values_failed) == (3, 0)
    assert get_client().is_ciphertext(raw(LegacyInPlace, keys[1], "secret"))
    assert LegacyInPlace.objects.get(
        pk=keys[1]).secret == "text@backfill.example"
    assert [o.pk for o in LegacyInPlace.objects.filter(
        secret="text@backfill.example")] == [keys[1]]


def test_a_target_holding_something_else_is_anomalous_and_untouched():
    keys = TwoColumn().seed(emails(3))
    plant(LegacyTwoColumn, keys[0], "email", b"not an envelope")

    outcome = go(TwoColumn())

    assert outcome.run.values_anomalous == 1
    assert outcome.run.values_written == 2
    assert raw(LegacyTwoColumn, keys[0], "email") == b"not an envelope"
    assert raw(LegacyTwoColumn, keys[0], "email_bidx") is None


def test_a_value_the_codec_refuses_fails_alone():
    """The refusal is raised while Django compiles the write, inside
    `bulk_update`'s own `atomic()`. It must stay one value's failure."""
    rows = [LegacyTwoColumn.objects.create(
        email_legacy=f"age-{i}@backfill.example", age_legacy=age)
        for i, age in enumerate(["41", "forty-two", "43", None])]

    outcome = go(LegacyTwoColumn, columns=["email", "age"],
                 sources={"email": "email_legacy", "age": "age_legacy"})

    run = outcome.run
    assert run.status == "complete"
    assert outcome.failures_by_code == {"RENDERING_REFUSED": 1}
    assert (run.rows_scanned, run.values_written, run.values_null,
            run.values_failed) == (4, 6, 1, 1)
    # §3: the counts are per value and add up to the values scanned.
    assert (run.values_written + run.values_current + run.values_null
            + run.values_anomalous + run.values_failed) == 4 * 2
    assert raw(LegacyTwoColumn, rows[1].pk, "age") is None
    got = [LegacyTwoColumn.objects.get(pk=r.pk).age for r in rows]
    assert got == [41, None, 43, None]


def test_a_value_the_index_refuses_is_invalid_argument():
    """U+0378 is unassigned in the pinned Unicode version, and the column's
    index is `refuse` (docs/12 §10)."""
    keys = TwoColumn().seed(["ok@backfill.example", "a\u0378@backfill.example"])

    outcome = go(TwoColumn())

    assert outcome.failures_by_code == {"INVALID_ARGUMENT": 1}
    assert raw(LegacyTwoColumn, keys[1], "email") is None
    assert raw(LegacyTwoColumn, keys[1], "email_bidx") is None
    assert LegacyTwoColumn.objects.get(pk=keys[0]).email == (
        "ok@backfill.example")


def test_a_tenant_bound_column_is_context_unavailable(permissive):
    """The frontend cannot learn a row's tenant, and a row is never written
    under a context it guessed (PROCEDURE §6.3, #244). Not even when a
    tenant happens to be set in the process."""
    with tenant_scope("t1"):
        docs = [TenantDoc.objects.create(body="x") for _ in range(3)]
    for doc in docs:
        plant(TenantDoc, doc.pk, "body", b"legacy body")

    with tenant_scope("t1"):
        outcome = go(TenantDoc, columns=["body"])

    assert outcome.run.values_failed == 3 and outcome.run.values_written == 0
    assert outcome.failures_by_code == {"CONTEXT_UNAVAILABLE": 3}
    assert all(raw(TenantDoc, d.pk, "body") == b"legacy body" for d in docs)


# -- BF-10: the acknowledgement ------------------------------------------------

def _procedure_text_1():
    text = PROCEDURE.read_text(encoding="utf-8")
    after = text[text.index("**1. Before a new `encrypt` run"):]
    return re.search(r"```\n(.*?)\n```", after, re.S).group(1)


def test_bf10_a_populated_table_needs_the_acknowledgement(shape):
    shape.seed(emails(3))
    before = all_raw(shape.model, shape.field)
    args = [f"--source={k}={v}" for k, v in shape.sources.items()]

    out, _, error = command(
        "encrypt", f"tests.{shape.model.__name__}", "--columns",
        ",".join(shape.columns), *args)

    assert error is not None
    assert PREEXISTING_BACKUPS == _procedure_text_1()
    assert out.strip() == _procedure_text_1()
    assert all_raw(shape.model, shape.field) == before
    with connection.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {state.RUNS}")
        assert cur.fetchone()[0] == 0


def test_bf10_an_empty_table_needs_no_acknowledgement():
    out, _, error = command(
        "encrypt", "tests.LegacyTwoColumn", "--source", "email=email_legacy",
        "--columns", "email")
    assert error is None
    assert PREEXISTING_BACKUPS not in out
    assert json.loads(out.splitlines()[-1])["status"] == "complete"


def test_bf10_a_resume_does_not_ask_again(shape):
    run_id = _killed_run(shape)
    out, _, error = command("resume", run_id, "--batch-size", "10",
                            "--rows-per-second", "100000")
    assert error is None
    assert f"run {run_id}: job encrypt, resumed" in out
    assert json.loads(out.splitlines()[-1])["status"] == "complete"


# -- BF-14: the rate limit -----------------------------------------------------

def test_bf14_the_measured_rate_stays_under_a_binding_limit(shape):
    shape.seed(emails(100))
    limits = encrypt.Limits(batch_size=10, rows_per_second=50)

    outcome = go(shape, limits=limits, clock=FakeTime())

    assert outcome.process_rows == 100
    assert outcome.process_seconds >= 1.8  # the limit bound
    # At most the limit over the run, beyond one batch of burst (§5.3).
    assert outcome.process_rows <= 50 * outcome.process_seconds + 10


def test_bf14_on_the_wall_clock():
    TwoColumn().seed(emails(40))
    limits = encrypt.Limits(batch_size=10, rows_per_second=100)
    p, run = begin(TwoColumn())
    started = time.monotonic()

    outcome = encrypt.Runner(p, run, limits).run()

    elapsed = time.monotonic() - started
    assert outcome.run.status == "complete"
    assert 40 <= 100 * elapsed + 10


def test_the_bucket_never_holds_more_than_one_batch():
    t = FakeTime()
    bucket = TokenBucket(10, 5, t.clock, t.sleep)
    bucket.take(5)          # the burst
    assert t.sleeps == []
    t.now += 1000           # idle: the bucket fills to one batch, no more
    bucket.take(5)
    bucket.take(5)
    assert t.sleeps == [0.5]


def test_there_is_no_unlimited_setting():
    for bad in (0, -1, float("nan"), float("inf")):
        with pytest.raises(BackfillError):
            encrypt.Limits(rows_per_second=bad)
    with pytest.raises(BackfillError):
        encrypt.Limits(batch_size=0)
    with pytest.raises(BackfillError):
        encrypt.Limits(max_failures=0)


# -- BF-16: nothing sensitive in output or state -------------------------------

def test_bf16_no_value_envelope_or_index_in_output_or_state(shape):
    values = emails(12, tag="zebra-secret")
    keys = shape.seed(values)
    if isinstance(shape, InPlace):
        plant(shape.model, keys[3], shape.field, RESERVED)
    else:
        shape.model.objects.filter(pk=keys[3]).update(
            email_legacy="zebra-secret\u0378@backfill.example")
        values[3] = "zebra-secret\u0378@backfill.example"
    args = [f"--source={k}={v}" for k, v in shape.sources.items()]
    model = f"tests.{shape.model.__name__}"

    refused = command("encrypt", model, "--columns",
                      ",".join(shape.columns), *args)
    ran = command("encrypt", model, "--columns", ",".join(shape.columns),
                  "--batch-size", "5", "--rows-per-second", "100000",
                  "--acknowledge-preexisting-backups", *args)
    again = command("encrypt", model, "--columns", ",".join(shape.columns),
                    "--rows-per-second", "100000",
                    "--acknowledge-preexisting-backups", *args)

    assert json.loads(ran[0].splitlines()[-1])["values_failed"] == 1
    text = "\n".join(str(part) for result in (refused, ran, again)
                     for part in result)
    assert_no_leak(text, shape.model, values + ["zebra-secret"],
                   [shape.field, shape.index])


def test_the_leak_check_finds_an_index_but_not_inside_a_run_id(in_place):
    """BF-16's own check: it still sees an index in the output, and the
    same four hex digits inside a run id are not one."""
    (pk,) = in_place.seed(["zebra-secret@backfill.example"])
    go(in_place)
    index = raw(LegacyInPlace, pk, "secret_bidx").hex()

    with pytest.raises(AssertionError):
        assert_no_leak(f"index {index}", LegacyInPlace, [], ["secret_bidx"])
    assert_no_leak(f"run c74d6142-{index}-4fbd-a687-2ee885ad95ce",
                   LegacyInPlace, [], ["secret_bidx"])


def test_bf16_a_database_error_is_reported_by_type_only(shape, monkeypatch):
    shape.seed(emails(3, tag="zebra-secret"))
    p, run = begin(shape)

    def broken(*args, **kwargs):
        raise OperationalError("row contains (zebra-secret-000@backfill)")

    monkeypatch.setattr(cursor, "select_batch", broken)
    t = FakeTime()
    with pytest.raises(BackfillError) as stopped:
        drive(p, run, clock=t)

    assert "zebra-secret" not in str(stopped.value)
    assert "OperationalError" in str(stopped.value)
    assert stopped.value.__cause__ is None
    # §5.4: 1 s x 2^k, capped at 60 s, and the eighth failure exits.
    assert t.sleeps[-7:] == [1, 2, 4, 8, 16, 32, 60]
    after = state.load_run(connection, run.run_id)
    assert after.status == "running" and after.batch_seq == 0


def test_a_database_error_retries_the_same_batch(shape, monkeypatch):
    shape.seed(emails(25))
    p, run = begin(shape)
    real = cursor.select_batch
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] in (2, 3):
            raise OperationalError("connection reset")
        return real(*args, **kwargs)

    monkeypatch.setattr(cursor, "select_batch", flaky)
    t = FakeTime()
    outcome = drive(p, run, clock=t)

    assert [s for s in t.sleeps if s >= 1] == [1, 2]
    assert outcome.run.status == "complete"
    assert (outcome.run.rows_scanned, outcome.run.values_written,
            outcome.run.batch_seq) == (25, 25, 3)


# -- BF-17: the configuration hash --------------------------------------------

WORKED_EXAMPLE = (
    '{"columns":[{"column_uuid":"018f3c2e7a1b7c3d8e4f5a6b7c8d9e0f","indexes":'
    '[{"argon2":{"memory_kib":19456,"time_cost":2},"idf":"argon2id",'
    '"index_id":"exact","normalize":"nfc-casefold-v1","on_unindexable":'
    '"refuse","storage":"binary","truncate_bits":24}],"logical_type":'
    '"string","source":null,"storage":"binary"}],"cursor":[{"name":"id",'
    '"type":"int"}],"job":"encrypt","procedure_version":1,"table_uuid":'
    '"018f3c2e7a1b7c3d8e4f5a6b7c8d9e00","write_suite":65281}')
WORKED_HASH = (
    "8d437f03246bc98fba1a649865059069f8f171aadbc7fcf1ce2cec53575682a0")


def test_bf17_the_worked_example():
    procedure = PROCEDURE.read_text(encoding="utf-8")
    assert WORKED_EXAMPLE in procedure and WORKED_HASH in procedure

    class Field:
        column_uuid = bytes.fromhex("018f3c2e7a1b7c3d8e4f5a6b7c8d9e0f")
        logical_type = "string"
        storage = "binary"
        index = type("Decl", (), {"index_id": "exact"})

    class Validated:
        index_id = "exact"
        idf = "argon2id"
        argon2 = type("P", (), {"memory_kib": 19456, "time_cost": 2})
        normalize = "nfc-casefold-v1"
        truncate_bits = 24
        on_unindexable = "refuse"

    table = bytes.fromhex("018f3c2e7a1b7c3d8e4f5a6b7c8d9e00")
    registry = {f"{table.hex()}/{Field.column_uuid.hex()}/exact": Validated}
    built = config.build(
        job="encrypt", table_uuid=table, write_suite=65281,
        cursor=[("id", "int")], targets=[(Field, None)], indexes=registry)

    assert config.serialize(built) == WORKED_EXAMPLE
    assert config.digest(config.serialize(built)) == WORKED_HASH
    # Member order in the input does not matter; the serialization sorts.
    shuffled = json.loads(WORKED_EXAMPLE, object_pairs_hook=lambda p: dict(
        reversed(p)))
    assert config.serialize(shuffled) == WORKED_EXAMPLE


def test_the_run_row_stores_the_document_its_hash_is_of(shape):
    shape.seed(emails(1))
    _, run = begin(shape)
    stored = state.load_run(connection, run.run_id)
    assert config.digest(stored.config) == stored.config_hash
    document = json.loads(stored.config)
    assert document["job"] == "encrypt" and document["write_suite"] == 0xFF01
    assert document["cursor"] == [{"name": "id", "type": "int"}]
    (column,) = document["columns"]
    assert column["source"] == shape.sources.get(shape.field)
    assert column["indexes"] == [{
        "argon2": None, "idf": "hmac-sha512", "index_id": "exact",
        "normalize": "nfc-casefold-v1", "on_unindexable": "refuse",
        "storage": "binary", "truncate_bits": 15}]
    assert stored.frontend.startswith("django/")
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", stored.started_at)


def test_a_name_that_would_need_an_escape_is_refused():
    for bad in ('quo"te', "back\\slash", "caf\u00e9", "tab\t"):
        with pytest.raises(BackfillError):
            config.serialize({"cursor": [{"name": bad, "type": "int"}]})


# -- BF-20: max_failures -------------------------------------------------------

def test_bf20_max_failures_stops_after_the_batch_and_the_resume_moves_on(
        in_place):
    keys = in_place.seed(emails(30))
    for pk in keys[:10]:
        plant(LegacyInPlace, pk, "secret", RESERVED)
    limits = encrypt.Limits(batch_size=10, rows_per_second=100_000,
                            max_failures=5)

    stopped = go(in_place, limits=limits)

    assert stopped.stopped_by_max_failures
    run = stopped.run
    assert run.status == "running" and run.batch_seq == 1
    # The failing batch is committed: all ten failures, and the cursor past
    # every one of them, not only the five that reached the threshold.
    assert run.values_failed == 10
    assert run.cursor_value == json.dumps([str(keys[9])])
    assert stopped.failures_by_code == {"UNKNOWN_FORMAT_VERSION": 10}

    resumed = resume(run.run_id, limits=limits)

    assert not resumed.stopped_by_max_failures
    assert resumed.run.status == "complete"
    assert (resumed.run.values_failed, resumed.run.values_written) == (10, 20)
    assert all(raw(LegacyInPlace, pk, "secret") == RESERVED
               for pk in keys[:10])


def test_bf20_the_command_exits_nonzero_when_stopped(in_place):
    keys = in_place.seed(emails(20))
    for pk in keys[:10]:
        plant(LegacyInPlace, pk, "secret", RESERVED)

    out, _, error = command(
        "encrypt", "tests.LegacyInPlace", "--columns", "secret",
        "--batch-size", "10", "--max-failures", "5", "--rows-per-second",
        "100000", "--acknowledge-preexisting-backups")

    assert error is not None and "still `running`" in str(error)
    report = json.loads(out.splitlines()[-1])
    assert report["status"] == "running"
    assert report["stopped_by_max_failures"]


# -- the cursor ----------------------------------------------------------------

def test_a_uuid_primary_key_is_walked_in_the_databases_order():
    ids = [uuid.uuid4() for _ in range(25)]
    for i, pk in enumerate(ids):
        LegacyUuidKey.objects.create(id=pk, name_legacy=f"name-{i}")

    p, run = begin(LegacyUuidKey, sources={"name": "name_legacy"})
    with pytest.raises(Kill):
        drive(p, run, hooks=kill_after_batch(1))
    midway = state.load_run(connection, run.run_id)
    (key,) = json.loads(midway.cursor_value)
    outcome = resume(run.run_id)

    assert re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", key)
    assert json.loads(run.config)["cursor"] == [{"name": "id", "type": "uuid"}]
    assert (outcome.run.rows_scanned, outcome.run.values_written) == (25, 25)
    for i, pk in enumerate(ids):
        assert LegacyUuidKey.objects.get(pk=pk).name == f"name-{i}"


def test_key_encodings():
    assert cursor.encode_key("int", -4182) == '["-4182"]'
    assert cursor.decode_key("int", '["-4182"]') == -4182
    u = uuid.UUID("018F3C2E-7A1B-7C3D-8E4F-5A6B7C8D9E0F")
    assert cursor.encode_key("uuid", u) == (
        '["018f3c2e-7a1b-7c3d-8e4f-5a6b7c8d9e0f"]')
    assert cursor.decode_key("uuid", cursor.encode_key("uuid", u)) == u
    assert cursor.decode_key("text", cursor.encode_key("text", 'e"u')) == 'e"u'


@isolate_apps("tests")
def test_a_key_of_another_type_is_refused():
    from django.db import models

    class Dated(models.Model):
        day = models.DateField(primary_key=True)
        body = Encrypted(models.TextField(),
                         column_uuid="018f3c2e-0000-7000-8000-0000000000b1")
        fieldseal = FieldsealMeta(
            table_uuid="018f3c2e-0000-7000-8000-0000000000b0")

    with pytest.raises(BackfillError, match="DateField"):
        cursor.key_field(Dated)


# -- refusals at start ---------------------------------------------------------

@isolate_apps("tests")
def test_in_place_on_a_base64_column_is_refused(permissive):
    from django.db import models

    class Text(models.Model):
        name_legacy = models.CharField(max_length=50, null=True)
        name = Encrypted(models.CharField(max_length=50), storage="base64",
                         column_uuid="018f3c2e-0000-7000-8000-0000000000a1")
        fieldseal = FieldsealMeta(
            table_uuid="018f3c2e-0000-7000-8000-0000000000a0")

    with pytest.raises(BackfillError, match="#245"):
        encrypt.plan(Text, None, {})


def test_in_place_needs_a_permissive_client():
    with pytest.raises(BackfillError, match="permissive"):
        encrypt.plan(LegacyInPlace, ["secret"], {})


def test_a_readonly_client_is_refused():
    cfg = dict(settings.FIELDSEAL)
    cfg["READ_MODE"] = "readonly"
    try:
        with override_settings(FIELDSEAL=cfg):
            reset_client()
            with pytest.raises(BackfillError, match="readonly"):
                encrypt.plan(LegacyTwoColumn, ["email"],
                             {"email": "email_legacy"})
    finally:
        reset_client()


def test_columns_and_sources_are_checked():
    with pytest.raises(BackfillError, match="not an Encrypted column"):
        encrypt.plan(LegacyTwoColumn, ["email_legacy"], {})
    with pytest.raises(BackfillError, match="not a plaintext column"):
        encrypt.plan(LegacyTwoColumn, ["email"], {"email": "age"})
    with pytest.raises(BackfillError, match="does not cover"):
        encrypt.plan(LegacyTwoColumn, ["email"],
                     {"email": "email_legacy", "age": "age_legacy"})


def test_a_run_inside_a_transaction_is_refused():
    p, run = begin(TwoColumn())
    with transaction.atomic():
        with pytest.raises(BackfillError, match="inside a transaction"):
            drive(p, run)


@pytest.mark.skipif(connection.vendor != "sqlite", reason="SQLite only")
def test_sqlite_without_begin_immediate_is_refused(monkeypatch):
    p, run = begin(TwoColumn())
    monkeypatch.setattr(connection, "transaction_mode", None)
    with pytest.raises(BackfillError, match="IMMEDIATE"):
        drive(p, run)


def test_missing_state_tables_are_named():
    with connection.cursor() as cur:
        cur.execute(f"DROP TABLE {state.FAILURES}")
    try:
        _, _, error = command(
            "encrypt", "tests.LegacyTwoColumn", "--source",
            "email=email_legacy", "--columns", "email")
        assert state.FAILURES in str(error)
    finally:
        out, _, error = command("init")
    assert error is None and state.FAILURES in out
    out, _, _ = command("init")
    assert "already exist" in out


def test_a_plain_manager_is_refused():
    """`_base_manager.bulk_update` leaves the index stale (docs/12 §6)."""
    class Plain:
        __name__ = "Plain"
        fieldseal = Patient.fieldseal
        _meta = Patient._meta
        _default_manager = Patient._base_manager

    with pytest.raises(BackfillError, match="FieldsealManager"):
        encrypt.plan(Plain, None, {})


def test_differences_name_each_member():
    stored = json.loads(WORKED_EXAMPLE)
    live = json.loads(WORKED_EXAMPLE)
    live["write_suite"] = 65282
    live["cursor"][0]["name"] = "uid"
    live["columns"][0]["indexes"][0]["argon2"]["time_cost"] = 3
    live["columns"].append(dict(live["columns"][0], column_uuid="ff" * 16))
    c = "018f3c2e7a1b7c3d8e4f5a6b7c8d9e0f"
    assert config.differences(stored, live) == [
        f"columns[{c}].indexes[exact].argon2.time_cost",
        f"columns[{'ff' * 16}]",
        "cursor[0].name",
        "write_suite",
    ]
    assert config.differences(stored, json.loads(WORKED_EXAMPLE)) == []
