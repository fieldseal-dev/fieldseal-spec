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
import hashlib
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
from django.db import (
    IntegrityError,
    OperationalError,
    connection,
    connections,
    transaction,
)
from django.test.utils import isolate_apps, override_settings
from fieldseal import ValidatedIndex, index_registry_key
from fieldseal.errors import FieldsealError

from fieldseal_django import Encrypted, FieldsealMeta, tenant_scope
from fieldseal_django.apps import get_client, reset_client
from fieldseal_django.backfill import BackfillError, config, cursor, encrypt, state
from fieldseal_django.backfill.census import census
from fieldseal_django.backfill.ratelimit import TokenBucket
from fieldseal_django.backfill.report import (
    IN_PLACE_CONVERSION,
    PREEXISTING_BACKUPS,
)
from fieldseal_django.query import FieldsealManager
from tests.models import (
    LegacyInPlace,
    LegacyTwoColumn,
    LegacyUuidKey,
    Patient,
    TenantBinaryInPlace,
    TenantInPlace,
    TenantMixed,
    TenantTextInPlace,
    TenantTwoColumn,
    TenantUuidInPlace,
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
        for table in (state.RUNS, state.FAILURES, state.COLUMNS):
            cur.execute(f"DROP TABLE IF EXISTS {table}")


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


def begin(shape_or_model, *, columns=None, sources=None, tenant=None):
    """Plan and insert a run, as `fieldseal_backfill encrypt` does."""
    if isinstance(shape_or_model, InPlace | TwoColumn):
        p = encrypt.plan(shape_or_model.model, shape_or_model.columns,
                         shape_or_model.sources)
    else:
        p = encrypt.plan(shape_or_model, columns, sources or {}, tenant)
    return p, encrypt.new_run(p)


def drive(p, run, *, limits=FAST, hooks=None, resumed=False, clock=None):
    t = clock or FakeTime()
    return encrypt.Runner(p, run, limits, resumed=resumed, clock=t.clock,
                          sleep=t.sleep, hooks=hooks).run()


def go(shape_or_model, **kwargs):
    plan_kwargs = {k: kwargs.pop(k) for k in ("columns", "sources", "tenant")
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
        for table in (state.RUNS, state.FAILURES, state.COLUMNS):
            cur.execute(f"SELECT * FROM {table}")
            out.extend(repr(row) for row in cur.fetchall())
    return "\n".join(out)


_RUN_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def assert_no_leak(text, model, plaintexts, columns):
    """PROCEDURE §9 item 5, over output and every state table."""
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
        "100000", "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion", *args)
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


def test_bf21_resume_with_a_changed_declared_suite_is_refused(
        shape, monkeypatch):
    """PROCEDURE §4 (#281): an index's declared suite keys every index value
    the run writes, independently of `write_suite` (spec §7.2, #213), so the
    resume is refused by the index's own `suite_id` member. `0xFF02` is a
    real declaration here, not a patched reflection: derivation needs the
    suite's KDF only, which this build has (`SuiteTwoDoc`)."""
    run_id = _killed_run(shape)
    before = _snapshot(shape, run_id)
    field = shape.model._meta.get_field(shape.field)
    assert field.index.suite_id == 0xFF01
    monkeypatch.setattr(
        field, "index", dataclasses.replace(field.index, suite_id=0xFF02))
    reset_client()
    try:
        assert get_client().write_suite == 0xFF01
        with pytest.raises(BackfillError) as refused:
            resume(run_id)
        _, _, error = command("resume", run_id)
    finally:
        monkeypatch.undo()
        reset_client()
    member = f"columns[{field.column_uuid.hex()}].indexes[exact].suite_id"
    assert member in str(refused.value)
    assert "write_suite" not in str(refused.value)
    assert member in str(error)
    assert _snapshot(shape, run_id) == before


#: What the frontend recorded for each shape before #281, verbatim: produced
#: by the frontend at `b466188` (the commit before the change) and copied
#: here, with the hash it stored. Literal so that a later change to
#: `serialize` or `digest` cannot quietly change what "a pre-#281 run" means.
PRE_281 = {
    "in_place": (
        '{"columns":[{"column_uuid":"018f3c2e000070008000000000000051",'
        '"indexes":[{"argon2":null,"idf":"hmac-sha512","index_id":"exact",'
        '"normalize":"nfc-casefold-v1","on_unindexable":"refuse","storage":'
        '"binary","truncate_bits":15}],"logical_type":"string","source":null,'
        '"storage":"binary"}],"cursor":[{"name":"id","type":"int"}],"job":'
        '"encrypt","procedure_version":1,"table_uuid":'
        '"018f3c2e000070008000000000000050","write_suite":65281}',
        "1bfffb152108161c9947b20113766911028596b86946aff9a15742edd75f88fc"),
    "two_column": (
        '{"columns":[{"column_uuid":"018f3c2e000070008000000000000061",'
        '"indexes":[{"argon2":null,"idf":"hmac-sha512","index_id":"exact",'
        '"normalize":"nfc-casefold-v1","on_unindexable":"refuse","storage":'
        '"binary","truncate_bits":15}],"logical_type":"string","source":'
        '"email_legacy","storage":"binary"}],"cursor":[{"name":"id","type":'
        '"int"}],"job":"encrypt","procedure_version":1,"table_uuid":'
        '"018f3c2e000070008000000000000060","write_suite":65281}',
        "1e1093d53e39ad0062a3b21787f5d9da806d83e7b903cfb18cebfe0e4accab4c"),
}


def _record_pre_281(shape, run_id):
    text, digest = PRE_281[shape.name]
    assert hashlib.sha256(text.encode("ascii")).hexdigest() == digest
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {state.RUNS} SET config = %s, config_hash = %s, "
            "procedure_version = 1 WHERE run_id = %s",
            [text, digest, run_id])


def test_bf21_a_run_recorded_before_281_is_refused_on_resume(shape):
    """A run recorded before #281 is a version-1 run, and since version 2
    (PROCEDURE §12) every version-1 run is refused on resume by its version:
    the exception #281 took is not taken again. What makes it a refusal is
    the version, and the document it stored is no longer compared."""
    run_id = _killed_run(shape)
    _record_pre_281(shape, run_id)
    before = _snapshot(shape, run_id)

    with pytest.raises(BackfillError, match="procedure version 1"):
        resume(run_id)

    assert _snapshot(shape, run_id) == before


def test_the_old_worked_example_is_a_pre_281_document():
    """Version 1's worked example before #281, by its own published hash: a
    document without `suite_id` is what a version-1 run recorded then."""
    old = V1_WORKED_EXAMPLE.replace('"suite_id":65282,', "")
    assert old != V1_WORKED_EXAMPLE
    assert hashlib.sha256(old.encode("ascii")).hexdigest() == (
        "8d437f03246bc98fba1a649865059069f8f171aadbc7fcf1ce2cec53575682a0")
    assert config.differences(
        json.loads(old), json.loads(V1_WORKED_EXAMPLE)
    ) == ["columns[018f3c2e7a1b7c3d8e4f5a6b7c8d9e0f].indexes[exact]"
          f".suite_id{config.NOT_RECORDED}"]


def test_bf21_the_suite_is_read_from_the_validated_registry(shape):
    """PROCEDURE §4: index members come from the client's validated
    registry, never the declaration as written. The registry is made to
    disagree with the declaration, which the core itself never does, so a
    `config.build` that read `field.index.suite_id` would fail here."""
    field = shape.model._meta.get_field(shape.field)
    table = shape.model.fieldseal.table_uuid_bytes
    key = index_registry_key(table, field.column_uuid, "exact")
    registry = dict(get_client().indexes)
    assert field.index.suite_id == registry[key].suite_id == 0xFF01
    registry[key] = dataclasses.replace(registry[key], suite_id=0xFF02)

    built = config.build(
        job="encrypt", table_uuid=table, write_suite=0xFF01,
        cursor=[("id", "int")], targets=[(field, None, None)],
        indexes=registry)

    (column,) = built["columns"]
    assert column["indexes"][0]["suite_id"] == 0xFF02


#: `ValidatedIndex` members the configuration deliberately leaves out, and
#: why: `key` is the registry key, which `column_uuid` and `index_id` already
#: carry; the population and the override flag decide whether a declaration
#: is accepted, not what is stored (PROCEDURE §4).
NOT_IN_CONFIG = {"key", "projected_population", "overridden"}


def test_every_validated_index_member_is_recorded_or_excluded(shape):
    """#281's root cause: the index entry is written out by hand, and a
    member the core added (the declared suite) was missed. A member added
    to `ValidatedIndex` now fails here until it is recorded or excluded
    above with a reason."""
    members = {f.name for f in dataclasses.fields(ValidatedIndex)}
    p = encrypt.plan(shape.model, shape.columns, shape.sources)
    (index,) = p.config["columns"][0]["indexes"]
    recorded = set(index) - {"storage"}  # storage is the column's, §7.11
    assert recorded | NOT_IN_CONFIG == members
    assert not recorded & NOT_IN_CONFIG


# -- BF-22: a new run after an abandoned one ----------------------------------

def _run_rows(shape):
    table = shape.model.fieldseal.table_uuid_bytes.hex()
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT run_id FROM {state.RUNS} WHERE table_uuid = %s "
            "ORDER BY run_id", [table])
        return [r[0] for r in cur.fetchall()]


def test_bf22_a_new_run_after_abandon_with_a_changed_suite_is_refused(
        shape, monkeypatch):
    """PROCEDURE §4, *On a new `encrypt` run*: the resume refusal of BF-21
    cannot be walked around by abandoning the run and starting another. The
    abandoned run's converted values are `current` to a new run and their
    indexes are never re-derived, so the new run would index the rest under
    another suite."""
    run_id = _killed_run(shape)
    assert state.load_run(connection, run_id).values_written > 0
    _, _, error = command("abandon", run_id)
    assert error is None
    before = (all_raw(shape.model, shape.field),
              all_raw(shape.model, shape.index), _run_rows(shape))
    field = shape.model._meta.get_field(shape.field)
    monkeypatch.setattr(
        field, "index", dataclasses.replace(field.index, suite_id=0xFF02))
    reset_client()
    try:
        with pytest.raises(BackfillError) as refused:
            begin(shape)
    finally:
        monkeypatch.undo()
        reset_client()

    message = str(refused.value)
    assert run_id in message and "(abandoned)" in message
    assert (f"columns[{field.column_uuid.hex()}].indexes[exact].suite_id"
            in message)
    assert (all_raw(shape.model, shape.field),
            all_raw(shape.model, shape.index), _run_rows(shape)) == before


def test_bf22_an_abandoned_run_that_wrote_nothing_does_not_count(
        shape, monkeypatch):
    shape.seed(emails(5))
    _, run = begin(shape)
    assert state.abandon(connection, run.run_id)
    field = shape.model._meta.get_field(shape.field)
    monkeypatch.setattr(
        field, "index", dataclasses.replace(field.index, suite_id=0xFF02))
    reset_client()
    try:
        p, second = begin(shape)
        outcome = drive(p, second)
    finally:
        monkeypatch.undo()
        reset_client()
    assert outcome.run.status == "complete"
    assert outcome.run.values_written == 5


def test_bf22_a_new_run_after_a_pre_281_run_is_refused(shape):
    """PROCEDURE §12: a run recorded before #281 that converted values blocks
    a new run on its table too, since which suite its indexes were derived
    under cannot be told. The refusal says the member was not recorded."""
    run_id = _killed_run(shape)
    _record_pre_281(shape, run_id)
    assert state.abandon(connection, run_id)
    with pytest.raises(BackfillError) as refused:
        begin(shape)
    message = str(refused.value)
    assert f".suite_id{config.NOT_RECORDED}" in message
    assert "under a construction of the configuration without that member" \
        in message
    assert "#281" not in message


def test_bf22_a_new_run_with_the_same_declarations_starts(shape):
    run_id = _killed_run(shape)
    assert state.abandon(connection, run_id)
    p, run = begin(shape)
    outcome = drive(p, run)
    assert outcome.run.status == "complete"
    assert outcome.run.values_written + outcome.run.values_current == 25


@contextlib.contextmanager
def renamed_index(shape, monkeypatch):
    """The column's one index declared under another `index_id`: to the
    comparison, the recorded index is removed and a new one added. The
    sibling column derives through the source field's declaration, so it
    follows the rename."""
    field = shape.model._meta.get_field(shape.field)
    with monkeypatch.context() as m:
        m.setattr(field, "index",
                  dataclasses.replace(field.index, index_id="renamed"))
        reset_client()
        try:
            yield f"columns[{field.column_uuid.hex()}].indexes"
        finally:
            m.undo()
            reset_client()


def test_differences_mark_an_index_on_one_side_only():
    stored = json.loads(WORKED_EXAMPLE)
    live = json.loads(WORKED_EXAMPLE)
    (index,) = live["columns"][0]["indexes"]
    live["columns"][0]["indexes"] = [dict(index, index_id="other")]
    c = "018f3c2e7a1b7c3d8e4f5a6b7c8d9e0f"
    found = config.differences(stored, live)
    assert found == [f"columns[{c}].indexes[exact]{config.REMOVED}",
                     f"columns[{c}].indexes[other]{config.ADDED}"]
    assert config.unrecorded_note(found) == ""


def test_bf05_resume_with_an_index_added_and_removed_is_refused(
        shape, monkeypatch):
    run_id = _killed_run(shape)
    before = _snapshot(shape, run_id)
    with renamed_index(shape, monkeypatch) as at:
        with pytest.raises(BackfillError) as refused:
            resume(run_id)
    message = str(refused.value)
    assert f"{at}[exact]{config.REMOVED}" in message
    assert f"{at}[renamed]{config.ADDED}" in message
    assert "not recorded" not in message
    assert _snapshot(shape, run_id) == before


def test_bf22_a_new_run_with_an_index_added_and_removed_is_refused(
        shape, monkeypatch):
    """BF-22's other half: an index present in only one of the two. The
    abandoned run's converted values have an index under `exact` and none
    under `renamed`, and a new run would never derive the second for them."""
    run_id = _killed_run(shape)
    assert state.abandon(connection, run_id)
    rows = _run_rows(shape)
    with renamed_index(shape, monkeypatch) as at:
        with pytest.raises(BackfillError) as refused:
            begin(shape)
    message = str(refused.value)
    assert run_id in message
    assert f"{at}[exact]{config.REMOVED}" in message
    assert f"{at}[renamed]{config.ADDED}" in message
    assert _run_rows(shape) == rows


def test_bf22_the_command_names_the_run_and_member_and_writes_nothing(
        shape, monkeypatch):
    """BF-22 through `manage.py fieldseal_backfill encrypt`, as BF-21 is
    checked through `resume`: the refusal reaches the operator, names the
    earlier run and the member, and inserts no run row."""
    run_id = _killed_run(shape)
    _, _, error = command("abandon", run_id)
    assert error is None
    before = (all_raw(shape.model, shape.field),
              all_raw(shape.model, shape.index), _run_rows(shape))
    field = shape.model._meta.get_field(shape.field)
    args = [f"--source={k}={v}" for k, v in shape.sources.items()]
    monkeypatch.setattr(
        field, "index", dataclasses.replace(field.index, suite_id=0xFF02))
    reset_client()
    try:
        _, _, error = command(
            "encrypt", f"tests.{shape.model.__name__}",
            "--columns", ",".join(shape.columns),
            "--rows-per-second", "100000",
            "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion", *args)
    finally:
        monkeypatch.undo()
        reset_client()
    assert isinstance(error, CommandError)
    assert run_id in str(error)
    assert (f"columns[{field.column_uuid.hex()}].indexes[exact].suite_id"
            in str(error))
    assert (all_raw(shape.model, shape.field),
            all_raw(shape.model, shape.index), _run_rows(shape)) == before


def test_bf05_the_command_names_the_member_and_writes_nothing(
        shape, monkeypatch):
    run_id = _killed_run(shape)
    before = _snapshot(shape, run_id)
    with other_write_suite(monkeypatch):
        _, _, error = command("resume", run_id)
    assert "write_suite" in str(error)
    assert _snapshot(shape, run_id) == before


@pytest.mark.parametrize("version", [1, 2, 4])
def test_bf18_a_run_row_of_another_procedure_version_is_refused(
        shape, version):
    run_id = _killed_run(shape)
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {state.RUNS} SET procedure_version = %s "
            "WHERE run_id = %s", [version, run_id])
    before = _snapshot(shape, run_id)

    with pytest.raises(BackfillError,
                       match=f"procedure version {version}"):
        resume(run_id)
    _, _, error = command("resume", run_id)

    assert f"procedure version {version}" in str(error)
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
        "--rows-per-second", "100000", "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion")

    assert error is None
    lines = out.splitlines()
    final = lines[lines.index(next(
        line for line in lines if line.startswith("replication-lag"))) + 1:]
    assert "NOT fully converted" in final[0]
    report = json.loads(lines[-1])
    assert report["status"] == "complete" and not report["fully_converted"]
    assert report["failures_by_code"] == {"UNKNOWN_FORMAT_VERSION": 1}


def test_in_place_reads_are_plaintext_reads_and_a_raising_receiver_is_harmless(
        in_place):
    """#246: the in-place read is the adapter's permissive read, so each
    legacy value it converts is one plaintext read for its column, in the
    per-field count as in the core's (`docs/12` §4). A `plaintext_read`
    receiver that raises is logged, not raised: it must not turn every row
    into `INTERNAL` and convert nothing."""
    from fieldseal_django.signals import plaintext_read, plaintext_read_counts

    in_place.seed(emails(3))
    key = (LegacyInPlace._meta.label, "secret")
    before = plaintext_read_counts().get(key, 0)
    core_before = get_client().plaintext_reads

    def receiver(**kwargs):
        raise RuntimeError("metrics backend down")

    plaintext_read.connect(receiver, weak=False)
    try:
        outcome = go(in_place)
    finally:
        plaintext_read.disconnect(receiver)

    assert (outcome.run.values_written, outcome.run.values_failed) == (3, 0)
    assert plaintext_read_counts().get(key, 0) - before == 3
    assert get_client().plaintext_reads - core_before == 3


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


@isolate_apps("tests")
def test_in_place_on_a_base64_column_legacy_text_is_converted(permissive):
    """#245: refused at start until the adapter's read stopped decoding
    legacy text. The column itself holds the legacy text, and the read now
    passes it through as stored, so the in-place shape converts it like
    `binary` does. No blind index here: the client's index registry is built
    from the project's models, which an `isolate_apps` model is not one of;
    the in-place index derivation is the same path `LegacyInPlace` covers."""
    from django.db import models

    class Text(models.Model):
        name = Encrypted(
            models.CharField(max_length=50),
            storage="base64",
            null=True,
            column_uuid="018f3c2e-0000-7000-8000-0000000000b1",
        )
        fieldseal = FieldsealMeta(
            table_uuid="018f3c2e-0000-7000-8000-0000000000b0")

        class Meta:
            db_table = "tests_legacy245_base64_in_place"

    literals = ["Zm9v", "abcdabcd", "Anna", "ada@example.com",
                "Ada Lovelace"]
    with connection.schema_editor() as editor:
        editor.create_model(Text)
    try:
        keys = [Text.objects.create().pk for _ in literals]
        null_key = Text.objects.create().pk
        for key, literal in zip(keys, literals, strict=True):
            plant(Text, key, "name", literal)

        outcome = go(Text)

        assert (outcome.run.values_written, outcome.run.values_failed) == (
            5, 0)
        assert outcome.run.values_null == 1
        for key in keys:
            converted = raw(Text, key, "name")
            assert isinstance(converted, str)
            assert get_client().is_ciphertext(
                base64.b64decode(converted, validate=True))
        assert raw(Text, null_key, "name") is None
        cfg = dict(settings.FIELDSEAL)
        cfg["READ_MODE"] = "strict"
        with override_settings(FIELDSEAL=cfg):
            reset_client()
            assert [Text.objects.get(pk=key).name for key in keys] == literals
    finally:
        reset_client()
        with connection.schema_editor() as editor:
            editor.delete_model(Text)


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


# (the tenant-bound scenarios, BF-23 to BF-27, are at the end of the file)


# -- BF-10: the acknowledgement ------------------------------------------------

def _procedure_text_1():
    text = PROCEDURE.read_text(encoding="utf-8")
    after = text[text.index("**1. Before a new `encrypt` run"):]
    return re.search(r"```\n(.*?)\n```", after, re.S).group(1)


def test_bf10_a_populated_table_needs_the_acknowledgement(shape):
    shape.seed(emails(3))
    before = all_raw(shape.model, shape.field)
    args = [f"--source={k}={v}" for k, v in shape.sources.items()]

    # Text 6 is BF-27's: acknowledged here, so that this prints text 1 alone.
    out, _, error = command(
        "encrypt", f"tests.{shape.model.__name__}", "--columns",
        ",".join(shape.columns), "--acknowledge-in-place-conversion", *args)

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
                  "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion", *args)
    again = command("encrypt", model, "--columns", ",".join(shape.columns),
                    "--rows-per-second", "100000",
                    "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion", *args)

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

def _procedure_worked_example():
    """The §4 worked example and its hash, read out of PROCEDURE.md."""
    text = PROCEDURE.read_text(encoding="utf-8")
    after = text[text.index("**Worked example.**"):]
    example = re.search(r"```json\n(.*?)\n```", after, re.S).group(1)
    digest = re.search(r"```\n([0-9a-f]{64})\n```", after).group(1)
    return example, digest


WORKED_EXAMPLE, WORKED_HASH = _procedure_worked_example()

#: Version 1's example, which a version-3 frontend does not reproduce
#: (§4, §12).
V1_WORKED_EXAMPLE = (
    '{"columns":[{"column_uuid":"018f3c2e7a1b7c3d8e4f5a6b7c8d9e0f","indexes":'
    '[{"argon2":{"memory_kib":19456,"time_cost":2},"idf":"argon2id",'
    '"index_id":"exact","normalize":"nfc-casefold-v1","on_unindexable":'
    '"refuse","storage":"binary","suite_id":65282,"truncate_bits":24}],'
    '"logical_type":"string","source":null,"storage":"binary"}],"cursor":'
    '[{"name":"id","type":"int"}],"job":"encrypt","procedure_version":1,'
    '"table_uuid":"018f3c2e7a1b7c3d8e4f5a6b7c8d9e00","write_suite":65281}')


def test_bf17_the_worked_example():
    # The pins are literal as well, so that a change to the document that
    # moves the example and its hash together cannot pass unseen.
    assert WORKED_HASH == (
        "2e58854bc411b68fb134d81996fd9a7f94966f4d1898e816a0067d26888e6408")
    assert '"procedure_version":3' in WORKED_EXAMPLE
    assert hashlib.sha256(WORKED_EXAMPLE.encode("ascii")).hexdigest() \
        == WORKED_HASH
    # Version 2's example, by its own published hash: `config` gained no
    # member in version 3, so only this value, and the hash, changed.
    v2 = WORKED_EXAMPLE.replace('"procedure_version":3',
                                '"procedure_version":2')
    assert v2 != WORKED_EXAMPLE
    assert hashlib.sha256(v2.encode("ascii")).hexdigest() == (
        "7f5e7f264f8af0c1ce5740eeab6d9d95e68c5fbf814a327cd047317633ccb92b")

    class Field:
        column_uuid = bytes.fromhex("018f3c2e7a1b7c3d8e4f5a6b7c8d9e0f")
        logical_type = "string"
        storage = "binary"
        index = type("Decl", (), {"index_id": "exact"})

    class Plain:
        column_uuid = bytes.fromhex("018f3c2e7a1b7c3d8e4f5a6b7c8d9e10")
        logical_type = "date"
        storage = "base64"
        index = None

    class Validated:
        index_id = "exact"
        idf = "argon2id"
        argon2 = type("P", (), {"memory_kib": 19456, "time_cost": 2})
        normalize = "nfc-casefold-v1"
        truncate_bits = 24
        on_unindexable = "refuse"
        suite_id = 0xFF02

    table = bytes.fromhex("018f3c2e7a1b7c3d8e4f5a6b7c8d9e00")
    registry = {f"{table.hex()}/{Field.column_uuid.hex()}/exact": Validated}
    built = config.build(
        job="encrypt", table_uuid=table, write_suite=65281,
        cursor=[("id", "int")],
        # Listed out of order: the document sorts its columns.
        targets=[(Plain, "birth_date_legacy", None),
                 (Field, None, {"column": "tenant_id", "type": "int"})],
        indexes=registry)

    assert config.serialize(built) == WORKED_EXAMPLE
    assert config.digest(config.serialize(built)) == WORKED_HASH
    # Member order in the input does not matter; the serialization sorts.
    shuffled = json.loads(WORKED_EXAMPLE, object_pairs_hook=lambda p: dict(
        reversed(p)))
    assert config.serialize(shuffled) == WORKED_EXAMPLE
    # A frontend that leaves out a null `tenant` does not reproduce it.
    without = json.loads(WORKED_EXAMPLE)
    del without["columns"][1]["tenant"]
    assert config.digest(config.serialize(without)) != WORKED_HASH


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
        "storage": "binary", "suite_id": 0xFF01, "truncate_bits": 15}]
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
        "100000", "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion")

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
def test_plan_accepts_in_place_on_a_base64_column(permissive):
    """#245: refused at start until the adapter's read stopped decoding
    legacy text. In place is the same shape as `binary` now."""
    from django.db import models

    class Text(models.Model):
        name_legacy = models.CharField(max_length=50, null=True)
        name = Encrypted(models.CharField(max_length=50), storage="base64",
                         column_uuid="018f3c2e-0000-7000-8000-0000000000a1")
        fieldseal = FieldsealMeta(
            table_uuid="018f3c2e-0000-7000-8000-0000000000a0")

    p = encrypt.plan(Text, None, {})
    assert p.targets == [(Text._meta.get_field("name"), None)]

    cfg = dict(settings.FIELDSEAL)
    cfg["READ_MODE"] = "strict"
    with override_settings(FIELDSEAL=cfg):
        reset_client()
        with pytest.raises(BackfillError, match="permissive"):
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


def test_a_connection_without_autocommit_is_refused(monkeypatch):
    """With `AUTOCOMMIT = False`, `atomic()` is a savepoint in a transaction
    the connection opened itself and commits nothing, so the start's insert
    and comparison (#308) and each batch would not be transactions of their
    own. Patched on the wrapper, as below, so the proxy is not touched."""
    wrapper = connections[connection.alias]
    monkeypatch.setattr(wrapper, "get_autocommit", lambda: False)
    with pytest.raises(BackfillError, match="autocommit"):
        encrypt.check_connection(wrapper)


@pytest.mark.skipif(connection.vendor != "sqlite", reason="SQLite only")
def test_sqlite_without_begin_immediate_is_refused(monkeypatch):
    p, run = begin(TwoColumn())
    # Patch the wrapper, not `connection`. `django.db.connection` is a
    # `ConnectionProxy`: it resolves `transaction_mode` through `__getattr__`,
    # and forwards `setattr`/`delattr` to the wrapper. pytest 9.2 (pytest#10644)
    # records the old value from `target.__dict__`, where the proxy has no such
    # key, so its undo *deletes* the name -- through the proxy, deleting it from
    # the wrapper for the rest of the session, after which every `atomic()`,
    # `schema_editor()` and flush on this connection raises `AttributeError`.
    # The wrapper carries the attribute from `get_connection_params()`, so
    # targeting it records and restores the real value.
    monkeypatch.setattr(connections[connection.alias], "transaction_mode", None)
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


def test_require_tables_refuses_a_missing_columns_table_and_names_init():
    """PROCEDURE §3: a database that holds only the two version-2 tables is
    refused, and the refusal names the way to upgrade it."""
    with connection.cursor() as cur:
        cur.execute(f"DROP TABLE {state.COLUMNS}")
    with pytest.raises(BackfillError) as refused:
        state.require_tables(connection)
    assert state.COLUMNS in str(refused.value)
    assert "init" in str(refused.value)
    _, _, error = command(
        "encrypt", "tests.LegacyTwoColumn", "--source", "email=email_legacy",
        "--columns", "email")
    assert state.COLUMNS in str(error) and "init" in str(error)


def test_require_tables_refuses_a_columns_table_that_lacks_a_column():
    with connection.cursor() as cur:
        cur.execute(f"DROP TABLE {state.COLUMNS}")
        cur.execute(
            f"CREATE TABLE {state.COLUMNS} (run_id VARCHAR(36) NOT NULL, "
            "column_uuid CHAR(32) NOT NULL, values_written BIGINT NOT NULL, "
            "values_current BIGINT NOT NULL, values_null BIGINT NOT NULL, "
            "values_anomalous BIGINT NOT NULL, "
            "PRIMARY KEY (run_id, column_uuid))")
    with pytest.raises(BackfillError) as refused:
        state.require_tables(connection)
    assert "values_failed" in str(refused.value)
    assert state.COLUMNS in str(refused.value)
    # `init` does not alter a table that exists, and says what to do.
    assert state.init(connection) == []
    with pytest.raises(BackfillError, match="values_failed"):
        state.require_tables(connection)


def test_init_creates_the_columns_table_on_a_database_with_the_two_old_ones():
    """The upgrade path (PROCEDURE §3, §12): `init` creates the table that
    is missing and leaves the other two, and what they hold, as they are."""
    shape = TwoColumn()
    shape.seed(emails(3))
    p, run = begin(shape)
    with connection.cursor() as cur:
        cur.execute(f"DROP TABLE {state.COLUMNS}")

    out, _, error = command("init")

    assert error is None and state.COLUMNS in out
    assert state.RUNS not in out and state.FAILURES not in out
    state.require_tables(connection)
    assert state.load_column_counts(connection, run.run_id) == {}
    # Nothing in the run row changed: the run is as it was.
    assert state.load_run(connection, run.run_id) == run


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
        f"columns[{'ff' * 16}]{config.ADDED}",
        "cursor[0].name",
        "write_suite",
    ]
    assert config.differences(stored, json.loads(WORKED_EXAMPLE)) == []


# -- the row's tenant (PROCEDURE §5.5; #244) -----------------------------------

class TenantShape:
    """`TenantInPlace`: the tenant is the row's `tenant` column."""

    name = "tenant_in_place"
    model = TenantInPlace
    field = "secret"
    index = "secret_bidx"
    columns = ["secret"]
    sources: dict[str, str] = {}


TENANT_RUN = {"columns": ["secret"], "tenant": "tenant"}


def seed_tenants(model, rows):
    """`(tenant, legacy value or None)` rows, legacy bytes planted raw."""
    keys = []
    for tenant, value in rows:
        obj = model.objects.create(tenant=tenant)
        if value is not None:
            plant(model, obj.pk, "secret", value.encode("utf-8"))
        keys.append(obj.pk)
    return keys


def tenant_rows(n=25):
    """Two tenants, alternating, with every value distinct."""
    return [((1, 2)[i % 2], f"tenant-secret-{i:03d}") for i in range(n)]


def tenant_snapshot(run_id):
    return (all_raw(TenantInPlace, "secret"),
            all_raw(TenantInPlace, "secret_bidx"),
            state.load_run(connection, run_id))


def killed_tenant_run(rows=None):
    seed_tenants(TenantInPlace, rows or tenant_rows())
    p, run = begin(TenantInPlace, **TENANT_RUN)
    with pytest.raises(Kill):
        drive(p, run, hooks=kill_after_batch(1))
    return run.run_id


def run_rows():
    with connection.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {state.RUNS}")
        return cur.fetchone()[0]


def _tenant_uuid_hex():
    return TenantInPlace._meta.get_field("secret").column_uuid.hex()


def test_bf23_each_value_is_written_under_its_own_rows_tenant(permissive):
    """Two tenants and a NULL-tenant row, with a tenant bound in the process
    around the whole run: the bound one is never used (§6.3), so every value
    decrypts under its own row's tenant and not under another's."""
    shared = "Shared-Value"
    rows = [(1, shared), (2, shared), (1, "only-one"), (2, "only-two"),
            (None, "nobody"), (1, None)]
    keys = seed_tenants(TenantInPlace, rows)
    legacy_null = raw(TenantInPlace, keys[4], "secret")

    with tenant_scope("other"):
        outcome = go(TenantInPlace, **TENANT_RUN)

    run = outcome.run
    assert run.status == "complete"
    assert (run.rows_scanned, run.values_written, run.values_failed,
            run.values_null) == (6, 4, 1, 1)
    assert outcome.failures_by_code == {"CONTEXT_UNAVAILABLE": 1}
    assert raw(TenantInPlace, keys[4], "secret") == legacy_null
    assert raw(TenantInPlace, keys[4], "secret_bidx") is None
    for (tenant, value), pk in zip(rows, keys, strict=True):
        if tenant is None or value is None:
            continue
        other = str(3 - tenant)
        with tenant_scope(str(tenant)):
            assert TenantInPlace.objects.get(pk=pk).secret == value
            assert [o.pk for o in
                    TenantInPlace.objects.filter(secret=value)] == [pk]
        with tenant_scope(other):
            with pytest.raises(FieldsealError):
                TenantInPlace.objects.get(pk=pk)
            assert pk not in [o.pk for o in
                              TenantInPlace.objects.filter(secret=value)]


def test_bf23_a_uuid_tenant_is_written_under_its_hyphenated_form(permissive):
    """SQLite stores a UUID as 32 hex digits and PostgreSQL has a type for
    it; the tenant is the same 36 characters from either (§5.5)."""
    a, b = uuid.uuid4(), uuid.uuid4()
    keys = []
    for tenant, value in ((a, "uuid-one"), (b, "uuid-two"), (None, "none")):
        obj = TenantUuidInPlace.objects.create(tenant=tenant)
        plant(TenantUuidInPlace, obj.pk, "secret", value.encode())
        keys.append(obj.pk)

    outcome = go(TenantUuidInPlace, columns=["secret"], tenant="tenant")

    assert outcome.failures_by_code == {"CONTEXT_UNAVAILABLE": 1}
    assert outcome.run.values_written == 2
    with tenant_scope(str(a)):
        assert TenantUuidInPlace.objects.get(pk=keys[0]).secret == "uuid-one"
    with tenant_scope(str(b)):
        assert TenantUuidInPlace.objects.get(pk=keys[1]).secret == "uuid-two"
        with pytest.raises(FieldsealError):
            TenantUuidInPlace.objects.get(pk=keys[0])
    document = json.loads(state.load_run(connection, outcome.run.run_id).config)
    assert document["columns"][0]["tenant"] == {
        "column": "tenant", "type": "uuid"}


def test_a_tenant_run_killed_and_resumed_keeps_the_stored_tenant(permissive):
    """The resume takes the tenant column from the stored `config` and has
    no `--tenant` of its own (§5.5)."""
    rows = tenant_rows()
    run_id = killed_tenant_run(rows)
    keys = sorted(all_raw(TenantInPlace, "secret"))

    out, _, error = command("resume", run_id, "--batch-size", "10",
                            "--rows-per-second", "100000")

    assert error is None
    assert json.loads(out.splitlines()[-1])["status"] == "complete"
    for (tenant, value), pk in zip(rows, keys, strict=True):
        with tenant_scope(str(tenant)):
            assert TenantInPlace.objects.get(pk=pk).secret == value
    _, _, error = command("resume", run_id, "--tenant", "region")
    assert error is not None  # `resume` has no `--tenant`: the run's own


def test_config_records_the_tenant_per_column(permissive):
    p = encrypt.plan(TenantInPlace, ["secret"], {}, "tenant")
    assert p.config["columns"][0]["tenant"] == {
        "column": "tenant", "type": "int"}
    assert p.tenant is TenantInPlace._meta.get_field("tenant")
    # A column that is not tenant-bound records `null`.
    plain = encrypt.plan(LegacyInPlace, ["secret"], {})
    assert plain.config["columns"][0]["tenant"] is None
    assert plain.tenant is None


# -- BF-24: resume with the tenant changed -------------------------------------

def _alt_tenant_model(tenant_field):
    """`TenantInPlace`'s declaration, with the tenant column replaced (or,
    for None, absent): the live code after a change to the model."""
    from django.db import models

    from fieldseal_django import BlindIndex

    attrs = {
        "__module__": "tests.models",
        "secret": Encrypted(
            models.CharField(max_length=100),
            column_uuid="018f3c2e-0000-7000-8000-0000000000f1", null=True,
            index=BlindIndex(
                suite_id=0xFF01, index_id="exact", idf="hmac-sha512",
                normalize="nfc-casefold-v1", truncate_bits=15,
                projected_population=100_000)),
        "secret_bidx": Encrypted.index_column("secret"),
        "fieldseal": FieldsealMeta(
            table_uuid="018f3c2e-0000-7000-8000-0000000000f0",
            tenant_bound=True),
    }
    if tenant_field is not None:
        attrs["tenant"] = tenant_field
    return type("TenantInPlace", (models.Model,), attrs)


@isolate_apps("tests")
def test_bf24_resume_with_the_tenant_columns_type_changed_is_refused(
        permissive):
    from django.db import models

    run_id = killed_tenant_run()
    before = tenant_snapshot(run_id)
    alt = _alt_tenant_model(models.CharField(max_length=20, null=True))
    run = state.load_run(connection, run_id)

    with pytest.raises(BackfillError) as refused:
        encrypt.plan_for(run, [alt])

    assert f"columns[{_tenant_uuid_hex()}].tenant" in str(refused.value)
    assert tenant_snapshot(run_id) == before


@isolate_apps("tests")
def test_bf24_resume_with_the_tenant_column_gone_is_refused(permissive):
    run_id = killed_tenant_run()
    before = tenant_snapshot(run_id)
    run = state.load_run(connection, run_id)

    with pytest.raises(BackfillError) as refused:
        encrypt.plan_for(run, [_alt_tenant_model(None)])

    assert f"columns[{_tenant_uuid_hex()}].tenant" in str(refused.value)
    assert tenant_snapshot(run_id) == before


def test_bf24_resume_with_the_column_no_longer_tenant_bound_is_refused(
        permissive, monkeypatch):
    run_id = killed_tenant_run()
    before = tenant_snapshot(run_id)
    field = TenantInPlace._meta.get_field("secret")
    monkeypatch.setattr(field, "tenant_bound", False)

    with pytest.raises(BackfillError) as refused:
        resume(run_id)
    _, _, error = command("resume", run_id)

    assert f"columns[{_tenant_uuid_hex()}].tenant" in str(refused.value)
    assert f"columns[{_tenant_uuid_hex()}].tenant" in str(error)
    assert tenant_snapshot(run_id) == before


def test_bf24_resume_with_a_column_tenant_bound_since_is_refused(
        in_place, monkeypatch):
    """The other direction: recorded without a tenant, tenant-bound now."""
    in_place.seed(emails(25))
    p, run = begin(in_place)
    with pytest.raises(Kill):
        drive(p, run, hooks=kill_after_batch(1))
    before = _snapshot(in_place, run.run_id)
    field = LegacyInPlace._meta.get_field("secret")
    monkeypatch.setattr(field, "tenant_bound", True)

    with pytest.raises(BackfillError) as refused:
        resume(run.run_id)

    assert (f"columns[{field.column_uuid.hex()}].tenant"
            in str(refused.value))
    assert _snapshot(in_place, run.run_id) == before


# -- BF-25: a new run after an abandoned one, tenant column changed ------------

def test_bf25_a_new_run_with_another_tenant_column_is_refused(permissive):
    run_id = killed_tenant_run()
    assert state.load_run(connection, run_id).values_written > 0
    _, _, error = command("abandon", run_id)
    assert error is None
    before = (tenant_snapshot(run_id)[:2], run_rows())

    with pytest.raises(BackfillError) as refused:
        begin(TenantInPlace, columns=["secret"], tenant="region")
    _, _, error = command(
        "encrypt", "tests.TenantInPlace", "--columns", "secret",
        "--tenant", "region", "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion")

    for message in (str(refused.value), str(error)):
        assert run_id in message and "(abandoned)" in message
        assert f"columns[{_tenant_uuid_hex()}].tenant" in message
    assert (tenant_snapshot(run_id)[:2], run_rows()) == before


def test_bf25_a_new_run_with_the_same_tenant_column_starts(permissive):
    run_id = killed_tenant_run()
    assert state.abandon(connection, run_id)
    p, run = begin(TenantInPlace, **TENANT_RUN)
    outcome = drive(p, run)
    assert outcome.run.status == "complete"
    assert outcome.run.values_written + outcome.run.values_current == 25


def test_a_new_run_after_a_version_1_run_compares_indexes_only(shape):
    """PROCEDURE §12: a version-1 run recorded no `tenant`, so its `tenant`
    is not compared. Its indexes are, and match."""
    run_id = _killed_run(shape)
    assert state.load_run(connection, run_id).values_written > 0
    document = json.loads(state.load_run(connection, run_id).config)
    document["procedure_version"] = 1
    for column in document["columns"]:
        del column["tenant"]
    text = config.serialize(document)
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {state.RUNS} SET config = %s, config_hash = %s, "
            "procedure_version = 1 WHERE run_id = %s",
            [text, config.digest(text), run_id])
    assert state.abandon(connection, run_id)

    p, run = begin(shape)
    outcome = drive(p, run)

    assert outcome.run.status == "complete"
    assert outcome.run.values_written + outcome.run.values_current == 25


def test_a_new_run_after_a_run_of_another_version_is_refused(shape):
    run_id = _killed_run(shape)
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {state.RUNS} SET procedure_version = 4 "
            "WHERE run_id = %s", [run_id])
    assert state.abandon(connection, run_id)
    rows = _run_rows(shape)

    with pytest.raises(BackfillError) as refused:
        begin(shape)

    assert run_id in str(refused.value)
    assert "procedure version 4" in str(refused.value)
    assert _run_rows(shape) == rows


# -- BF-26: refusals at start --------------------------------------------------

def _refused_at_start(*args, match):
    before = run_rows()
    _, _, error = command(
        "encrypt", "tests.TenantInPlace", "--columns", "secret", *args)
    assert isinstance(error, CommandError) and match in str(error)
    assert run_rows() == before == 0


def test_bf26_a_tenant_bound_column_without_a_tenant_column(permissive):
    seed_tenants(TenantInPlace, tenant_rows(3))
    with pytest.raises(BackfillError, match="names no tenant column"):
        encrypt.plan(TenantInPlace, ["secret"], {})
    _refused_at_start("--acknowledge-preexisting-backups",
                      "--acknowledge-in-place-conversion",
                      match="names no tenant column")


def test_bf26_a_tenant_column_for_a_run_with_no_tenant_bound_column(
        permissive):
    in_place = InPlace()
    in_place.seed(emails(3))
    with pytest.raises(BackfillError, match="tenant-bound"):
        encrypt.plan(LegacyInPlace, ["secret"], {}, "id")
    _, _, error = command(
        "encrypt", "tests.LegacyInPlace", "--columns", "secret",
        "--tenant", "id", "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion")
    assert isinstance(error, CommandError) and "tenant-bound" in str(error)
    assert run_rows() == 0


def test_bf26_a_tenant_column_the_adapter_encrypts(permissive):
    seed_tenants(TenantInPlace, tenant_rows(3))
    for name in ("secret", "secret_bidx"):
        with pytest.raises(BackfillError, match="encrypts"):
            encrypt.plan(TenantInPlace, ["secret"], {}, name)
        _refused_at_start("--tenant", name,
                          "--acknowledge-preexisting-backups",
                          "--acknowledge-in-place-conversion",
                          match="encrypts")


def test_bf26_an_unknown_or_unsupported_tenant_column(permissive):
    with pytest.raises(BackfillError, match="not a column"):
        encrypt.plan(TenantInPlace, ["secret"], {}, "nope")
    with pytest.raises(BackfillError, match="DateTimeField"):
        encrypt.plan(TenantInPlace, ["secret"], {}, "stamp")
    _refused_at_start("--tenant", "stamp", match="DateTimeField")


# -- the tenant column's type, and its rendering (§5.5) ------------------------

def test_tenant_type_maps_the_declared_type():
    assert cursor.tenant_type(TenantInPlace._meta.get_field("tenant")) == "int"
    assert cursor.tenant_type(
        TenantUuidInPlace._meta.get_field("tenant")) == "uuid"
    assert cursor.tenant_type(
        LegacyTwoColumn._meta.get_field("email_legacy")) == "text"
    assert cursor.tenant_type(LegacyInPlace._meta.get_field("id")) == "int"


@isolate_apps("tests")
def test_tenant_type_maps_binary_and_a_foreign_key_through_its_target():
    from django.db import models

    class Org(models.Model):
        id = models.UUIDField(primary_key=True)

    class Code(models.Model):
        code = models.CharField(max_length=5, primary_key=True)

    class Blob(models.Model):
        raw = models.BinaryField()
        org = models.ForeignKey(Org, on_delete=models.CASCADE)
        code = models.ForeignKey(Code, on_delete=models.CASCADE)
        when = models.DateField()
        flag = models.BooleanField()

    assert cursor.tenant_type(Blob._meta.get_field("raw")) == "binary"
    assert cursor.tenant_type(Blob._meta.get_field("org")) == "uuid"
    assert cursor.tenant_type(Blob._meta.get_field("code")) == "text"
    for name in ("when", "flag"):
        with pytest.raises(BackfillError):
            cursor.tenant_type(Blob._meta.get_field(name))


def test_tenant_rendering_of_each_type():
    one = uuid.UUID("0123456789abcdef0123456789ABCDEF")
    hyphenated = b"01234567-89ab-cdef-0123-456789abcdef"

    # text: UTF-8. Empty has no tenant (below).
    assert cursor.tenant_bytes("text", "t\u00e9nant") == b"t\xc3\xa9nant"
    # binary: the stored bytes, whatever the driver wraps them in.
    for stored in (b"\x00\xff\x10", bytearray(b"\x00\xff\x10"),
                   memoryview(b"\x00\xff\x10")):
        assert cursor.tenant_bytes("binary", stored) == b"\x00\xff\x10"
    # int: decimal ASCII, a sign only when negative, no leading zeros.
    assert cursor.tenant_bytes("int", 42) == b"42"
    assert cursor.tenant_bytes("int", -7) == b"-7"
    assert cursor.tenant_bytes("int", 0) == b"0"
    # uuid: lowercase and hyphenated from a `uuid.UUID` (PostgreSQL), from
    # SQLite's 32 hex digits, and from the hyphenated text.
    assert cursor.tenant_bytes("uuid", one) == hyphenated
    assert cursor.tenant_bytes("uuid", one.hex) == hyphenated
    assert cursor.tenant_bytes("uuid", str(one)) == hyphenated
    assert cursor.tenant_bytes("uuid", one.hex.upper()) == hyphenated
    # NULL has no tenant, for every type.
    for kind in ("text", "binary", "int", "uuid"):
        assert cursor.tenant_bytes(kind, None) is None


def test_an_empty_tenant_is_no_tenant():
    """§5.5: a provider may map `b""` to the scope of no tenant, so an
    empty text or binary value fails closed like NULL."""
    assert cursor.tenant_bytes("text", "") is None
    for empty in (b"", bytearray(), memoryview(b"")):
        assert cursor.tenant_bytes("binary", empty) is None


def test_uuid_text_is_32_hex_or_canonical_and_nothing_else():
    good = "0123456789abcdef0123456789abcdef"
    assert cursor.tenant_bytes("uuid", good) is not None
    for bad in ("0x0123456789abcdef0123456789abcd",
                " 0123456789abcdef0123456789abcde",
                "urn:0123456789abcdef0123456789abcdef",
                "0123-4567-89ab-cdef0123-456789abcdef",
                "{01234567-89ab-cdef-0123-456789abcdef}",
                good + "\n", good[:-1] + "g"):
        assert cursor.tenant_bytes("uuid", bad) is None, bad


def test_a_stored_value_of_the_wrong_type_has_no_tenant():
    """SQLite keeps a value's old storage class after an `AlterField`;
    coercing it would bind a tenant nobody has (§5.5)."""
    wrong = {
        "binary": [5, "abc", 7.9, True],
        "text": [b"abc", memoryview(b"abc"), 5, 7.9],
        "int": [7.9, "7", b"7", True, False],
        "uuid": [5, b"0123", 7.9, "not-a-uuid", "0123", "{" + "a" * 30 + "}",
                 uuid.uuid4().bytes],
    }
    for kind, values in wrong.items():
        for value in values:
            assert cursor.tenant_bytes(kind, value) is None, (kind, value)


# -- BF-27: a conversion the adapter names (§6.1, §9 item 6) -------------------

def _procedure_text_6():
    text = PROCEDURE.read_text(encoding="utf-8")
    after = text[text.index("**6. Before a new in-place `encrypt` run"):]
    return re.search(r"```\n(.*?)\n```", after, re.S).group(1)


def test_the_in_place_conversion_text_is_the_procedures():
    assert IN_PLACE_CONVERSION == _procedure_text_6()


@pytest.mark.skipif(connection.vendor != "postgresql",
                    reason="PostgreSQL only: the conversion route PROCEDURE "
                           "§6.1 names is Django's AlterField into bytea "
                           "(#252); SQLite names no column")
def test_bf27_an_in_place_binary_column_needs_the_conversion_flag(permissive):
    seed_tenants(TenantInPlace, tenant_rows(5))
    before = all_raw(TenantInPlace, "secret")
    base = ("encrypt", "tests.TenantInPlace", "--columns", "secret",
            "--tenant", "tenant", "--rows-per-second", "100000")

    # Text 1 acknowledged, text 6 not.
    out, _, error = command(*base, "--acknowledge-preexisting-backups")
    assert error is not None
    assert "--acknowledge-in-place-conversion" in str(error)
    assert IN_PLACE_CONVERSION in out and PREEXISTING_BACKUPS not in out
    assert "tests.TenantInPlace.secret" in out
    assert (all_raw(TenantInPlace, "secret"), run_rows()) == (before, 0)

    # Neither: both printed before the refusal, both flags named.
    out, _, error = command(*base)
    assert PREEXISTING_BACKUPS in out and IN_PLACE_CONVERSION in out
    assert "--acknowledge-preexisting-backups" in str(error)
    assert "--acknowledge-in-place-conversion" in str(error)
    assert (all_raw(TenantInPlace, "secret"), run_rows()) == (before, 0)

    # Both flags: the run starts.
    out, _, error = command(*base, "--acknowledge-preexisting-backups",
                            "--acknowledge-in-place-conversion")
    assert error is None
    assert json.loads(out.splitlines()[-1])["values_written"] == 5


@pytest.mark.skipif(connection.vendor != "postgresql", reason="PostgreSQL only")
def test_bf27_an_empty_table_and_a_two_column_run_need_no_flag(permissive):
    out, _, error = command(
        "encrypt", "tests.TenantInPlace", "--columns", "secret",
        "--tenant", "tenant")
    assert error is None and IN_PLACE_CONVERSION not in out
    LegacyTwoColumn.objects.create(email_legacy="a@b.example")
    out, _, error = command(
        "encrypt", "tests.LegacyTwoColumn", "--columns", "email",
        "--source", "email=email_legacy", "--rows-per-second", "100000",
        "--acknowledge-preexisting-backups")
    assert error is None and IN_PLACE_CONVERSION not in out


@pytest.mark.skipif(connection.vendor != "sqlite", reason="SQLite only")
def test_bf27_is_not_applicable_on_sqlite(permissive):
    """SQLite's conversion keeps the value (§6.1 names no column there), so
    the flag is not asked for, and the run starts without it."""
    seed_tenants(TenantInPlace, tenant_rows(5))
    assert encrypt.in_place_conversion_columns(
        encrypt.plan(TenantInPlace, ["secret"], {}, "tenant")) == []

    out, _, error = command(
        "encrypt", "tests.TenantInPlace", "--columns", "secret",
        "--tenant", "tenant", "--rows-per-second", "100000",
        "--acknowledge-preexisting-backups")

    assert error is None
    assert IN_PLACE_CONVERSION not in out
    assert json.loads(out.splitlines()[-1])["values_written"] == 5


@isolate_apps("tests")
def test_in_place_conversion_columns_name_every_in_place_target_on_postgres(
        permissive, monkeypatch):
    """The binding's rule, whichever database the suite runs on: every
    in-place target, `base64` included (a `base64` column converted from
    `bytea` by a path the guard cannot see holds `\\x41`-style text)."""
    from django.db import models

    class Text(models.Model):
        name = Encrypted(models.CharField(max_length=50), storage="base64",
                         column_uuid="018f3c2e-0000-7000-8000-0000000000a1")
        fieldseal = FieldsealMeta(
            table_uuid="018f3c2e-0000-7000-8000-0000000000a0")

    binary = encrypt.plan(TenantInPlace, ["secret"], {}, "tenant")
    base64_plan = encrypt.plan(Text, None, {})
    two = encrypt.plan(LegacyTwoColumn, ["email"], {"email": "email_legacy"})
    real = connections[binary.alias].vendor
    assert real != "sqlite" or encrypt.in_place_conversion_columns(
        base64_plan) == []

    monkeypatch.setattr(type(connections[binary.alias]), "vendor",
                        "postgresql")
    assert encrypt.in_place_conversion_columns(binary) == ["secret"]
    assert encrypt.in_place_conversion_columns(base64_plan) == ["name"]
    assert encrypt.in_place_conversion_columns(two) == []
    monkeypatch.setattr(type(connections[binary.alias]), "vendor", "sqlite")
    assert encrypt.in_place_conversion_columns(base64_plan) == []


# -- the tenant in the two-column shape; NULL tenants; wrong types -------------

def test_bf23_the_two_column_shape_writes_under_each_rows_tenant():
    rows = [(1, "a-one"), (2, "a-two"), (1, "b-one"), (2, "b-two")]
    keys = [TenantTwoColumn.objects.create(tenant=t, secret_legacy=v).pk
            for t, v in rows]

    outcome = go(TenantTwoColumn, columns=["secret"],
                 sources={"secret": "secret_legacy"}, tenant="tenant")

    assert outcome.run.status == "complete"
    assert outcome.run.values_written == 4 and outcome.run.values_failed == 0
    for (tenant, value), pk in zip(rows, keys, strict=True):
        with tenant_scope(str(tenant)):
            assert TenantTwoColumn.objects.get(pk=pk).secret == value
        with tenant_scope(str(3 - tenant)):
            with pytest.raises(FieldsealError):
                TenantTwoColumn.objects.get(pk=pk)


def test_a_null_tenant_row_with_nothing_pending_is_not_a_failure(permissive):
    """§5.5: a NULL tenant fails only a tenant-bound `pending` value. A
    value already an envelope is `current`, a NULL value is `null`."""
    with tenant_scope("1"):
        sealed = TenantInPlace.objects.create(tenant=None, secret="sealed")
    TenantInPlace.objects.create(tenant=None)
    envelope = raw(TenantInPlace, sealed.pk, "secret")
    assert get_client().is_ciphertext(envelope)

    outcome = go(TenantInPlace, **TENANT_RUN)

    run = outcome.run
    assert (run.values_current, run.values_null) == (1, 1)
    assert run.values_failed == run.values_written == 0
    assert raw(TenantInPlace, sealed.pk, "secret") == envelope


@pytest.mark.skipif(connection.vendor != "sqlite",
                    reason="SQLite keeps a value's storage class")
def test_bf23_a_tenant_of_the_wrong_storage_class_is_context_unavailable(
        permissive):
    """A column converted by an `AlterField` keeps its old values' storage
    class on SQLite. A text or a real in an integer tenant column has no
    tenant, and is a failure with the bytes unchanged, not a coerced one."""
    keys = seed_tenants(TenantInPlace, [
        (1, "fine"), (1, "text-tenant"), (1, "real-tenant")])
    plant(TenantInPlace, keys[1], "tenant", "abc")
    plant(TenantInPlace, keys[2], "tenant", 7.9)
    legacy = {pk: raw(TenantInPlace, pk, "secret") for pk in keys[1:]}

    outcome = go(TenantInPlace, **TENANT_RUN)

    assert outcome.run.values_written == 1
    assert outcome.failures_by_code == {"CONTEXT_UNAVAILABLE": 2}
    for pk, stored in legacy.items():
        assert raw(TenantInPlace, pk, "secret") == stored


@pytest.mark.skipif(connection.vendor != "sqlite",
                    reason="SQLite keeps a value's storage class")
def test_an_integer_in_a_uuid_tenant_column_is_context_unavailable(
        permissive):
    obj = TenantUuidInPlace.objects.create(tenant=uuid.uuid4())
    plant(TenantUuidInPlace, obj.pk, "secret", b"legacy")
    plant(TenantUuidInPlace, obj.pk, "tenant", 5)

    outcome = go(TenantUuidInPlace, columns=["secret"], tenant="tenant")

    assert outcome.failures_by_code == {"CONTEXT_UNAVAILABLE": 1}
    assert raw(TenantUuidInPlace, obj.pk, "secret") == b"legacy"


@pytest.mark.parametrize("unsupported", ["datetime", "encrypted"])
@isolate_apps("tests")
def test_resume_with_the_tenant_column_now_encrypted_or_unsupported_is_refused(
        permissive, unsupported):
    """The recorded tenant column is now an `Encrypted` field, or a type
    §5.5 does not take: a refusal naming the member, not `tenant_type`'s."""
    from django.db import models

    run_id = killed_tenant_run()
    run = state.load_run(connection, run_id)
    member = f"columns[{_tenant_uuid_hex()}].tenant"
    field = (models.DateTimeField(null=True) if unsupported == "datetime"
             else Encrypted(models.IntegerField(), null=True,
                            column_uuid="018f3c2e-0000-7000-8000-0000000000f9"))

    with pytest.raises(BackfillError) as refused:
        encrypt.plan_for(run, [_alt_tenant_model(field)])

    assert str(refused.value).count(member) == 1


# -- text and binary tenant columns, end to end (BF-23) ------------------------

@pytest.mark.parametrize("model, one, two, empty", [
    (TenantTextInPlace, "acme", "Zürich", ""),
    (TenantBinaryInPlace, b"\x00\x01\xfe", b"\xff\x10", b""),
], ids=["text", "binary"])
def test_bf23_a_text_or_binary_tenant_is_written_as_stored(
        permissive, model, one, two, empty):
    """`str` is its UTF-8 bytes and bytes are as stored (§5.5). NULL and
    empty tenants are failures with the bytes unchanged."""
    shared = "Shared-Value"
    rows = [(one, shared), (two, shared), (one, "only-one"),
            (two, "only-two"), (None, "nobody"), (empty, "empty-tenant")]
    keys = []
    for tenant, value in rows:
        obj = model.objects.create(tenant=tenant)
        plant(model, obj.pk, "secret", value.encode())
        keys.append(obj.pk)
    unchanged = {pk: raw(model, pk, "secret") for pk in keys[4:]}

    outcome = go(model, columns=["secret"], tenant="tenant")

    assert outcome.run.values_written == 4
    assert outcome.failures_by_code == {"CONTEXT_UNAVAILABLE": 2}
    for pk, stored in unchanged.items():
        assert raw(model, pk, "secret") == stored
        assert raw(model, pk, "secret_bidx") is None
    for (tenant, value), pk in zip(rows[:4], keys[:4], strict=True):
        other = two if tenant == one else one
        with tenant_scope(tenant):
            assert model.objects.get(pk=pk).secret == value
            assert [o.pk for o in model.objects.filter(secret=value)] == [pk]
        with tenant_scope(other):
            with pytest.raises(FieldsealError):
                model.objects.get(pk=pk)
            assert pk not in [o.pk for o in model.objects.filter(secret=value)]


# -- §12: the version-1 warning ------------------------------------------------

def _as_version_1(run_id):
    document = json.loads(state.load_run(connection, run_id).config)
    document["procedure_version"] = 1
    for column in document["columns"]:
        del column["tenant"]
    text = config.serialize(document)
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {state.RUNS} SET config = %s, config_hash = %s, "
            "procedure_version = 1 WHERE run_id = %s",
            [text, config.digest(text), run_id])
    assert state.abandon(connection, run_id)


def test_a_version_1_run_that_converted_values_warns_for_a_tenant_bound_column(
        permissive):
    run_id = killed_tenant_run()
    _as_version_1(run_id)

    out, _, error = command(
        "encrypt", "tests.TenantInPlace", "--columns", "secret",
        "--tenant", "tenant", "--rows-per-second", "100000",
        "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion")

    assert error is None
    assert json.loads(out.splitlines()[-1])["status"] == "complete"
    (warning,) = [ln for ln in out.splitlines() if ln.startswith("warning:")]
    assert run_id in warning and "secret" in warning
    assert "cannot tell whether" in warning and "PROCEDURE §12" in warning


def test_a_version_1_run_warns_nothing_when_no_target_is_tenant_bound(shape):
    run_id = _killed_run(shape)
    _as_version_1(run_id)
    args = [f"--source={k}={v}" for k, v in shape.sources.items()]

    out, _, error = command(
        "encrypt", f"tests.{shape.model.__name__}", "--columns",
        ",".join(shape.columns), "--rows-per-second", "100000",
        "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion", *args)

    assert error is None
    assert "warning:" not in out
    assert json.loads(out.splitlines()[-1])["status"] == "complete"


def test_a_version_1_run_warns_only_for_columns_it_covered(permissive):
    """The stored version-1 `columns` list the run's columns. A tenant-bound
    column of the new run that the version-1 run never covered is one it
    cannot have written, so it is not named (PROCEDURE §12)."""
    run_id = killed_tenant_run()
    _as_version_1(run_id)
    document = json.loads(state.load_run(connection, run_id).config)
    for column in document["columns"]:
        column["column_uuid"] = "0" * 32  # a column of another declaration
    text = config.serialize(document)
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {state.RUNS} SET config = %s, config_hash = %s "
            "WHERE run_id = %s", [text, config.digest(text), run_id])

    out, _, error = command(
        "encrypt", "tests.TenantInPlace", "--columns", "secret",
        "--tenant", "tenant", "--rows-per-second", "100000",
        "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion")

    assert error is None
    assert "warning:" not in out
    assert json.loads(out.splitlines()[-1])["status"] == "complete"


@isolate_apps("tests")
def test_resume_of_a_run_recording_two_tenant_columns_is_refused(permissive):
    """This frontend binds one tenant column per run and reads one tenant per
    row for every target. A stored run whose columns name two (another
    frontend's, or a hand edit) is refused, naming the column whose tenant
    is not the first one's, rather than writing it under the first's."""
    from django.db import models

    from fieldseal_django import BlindIndex

    run_id = killed_tenant_run()
    second = "018f3c2e00007000800000000000ff01"
    document = json.loads(state.load_run(connection, run_id).config)
    extra = dict(document["columns"][0], column_uuid=second, indexes=[],
                 tenant={"column": "region", "type": "int"})
    document["columns"] = sorted(document["columns"] + [extra],
                                 key=lambda c: c["column_uuid"])
    text = config.serialize(document)
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {state.RUNS} SET config = %s, config_hash = %s "
            "WHERE run_id = %s", [text, config.digest(text), run_id])
    before = tenant_snapshot(run_id)
    alt = type("TenantInPlace", (models.Model,), {
        "__module__": "tests.models",
        "tenant": models.IntegerField(null=True),
        "region": models.IntegerField(null=True),
        "secret": Encrypted(
            models.CharField(max_length=100),
            column_uuid="018f3c2e-0000-7000-8000-0000000000f1", null=True,
            index=BlindIndex(
                suite_id=0xFF01, index_id="exact", idf="hmac-sha512",
                normalize="nfc-casefold-v1", truncate_bits=15,
                projected_population=100_000)),
        "secret_bidx": Encrypted.index_column("secret"),
        "other": Encrypted(models.CharField(max_length=100),
                           column_uuid=str(uuid.UUID(second)), null=True),
        "fieldseal": FieldsealMeta(
            table_uuid="018f3c2e-0000-7000-8000-0000000000f0",
            tenant_bound=True),
    })

    with pytest.raises(BackfillError) as refused:
        encrypt.plan_for(state.load_run(connection, run_id), [alt])

    message = str(refused.value)
    assert f"columns[{second}].tenant" in message
    assert f"columns[{_tenant_uuid_hex()}].tenant" not in message
    assert tenant_snapshot(run_id) == before


# -- #291: per-column counts (BF-28 to BF-31) ----------------------------------

MIXED_BOTH = {"columns": ["a", "b"], "tenant": "tenant"}


def seed_mixed(n=25, *, tenant=1, region=None):
    """`n` rows: `a` and `b` hold legacy bytes, `tenant` is `tenant` on
    every row (NULL for None), and `region` is `region` (or 1, 2 alternately
    for None)."""
    keys = []
    for i in range(n):
        obj = TenantMixed.objects.create(
            tenant=tenant, region=(1, 2)[i % 2] if region is None else region)
        plant(TenantMixed, obj.pk, "a", f"a-value-{i:03d}".encode())
        plant(TenantMixed, obj.pk, "b", f"b-value-{i:03d}".encode())
        keys.append(obj.pk)
    return keys


def column_hex(name):
    return TenantMixed._meta.get_field(name).column_uuid.hex()


def mixed_runs():
    with connection.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {state.RUNS}")
        return cur.fetchone()[0]


def assert_column_sums(run_id):
    """§3: for each of the five counts, the sum over the run's column rows
    equals the run row's."""
    run = state.load_run(connection, run_id)
    columns = state.load_column_counts(connection, run_id)
    assert columns
    for name in state.VALUE_COUNTS:
        assert sum(c[name] for c in columns.values()) == getattr(run, name), \
            name


def written_by_column(run_id):
    return {k: v["values_written"]
            for k, v in state.load_column_counts(connection, run_id).items()}


def abandoned_unwritten_b_run(n=25):
    """A run over `a` and `b`, killed after one batch and abandoned: every
    row's `tenant` is NULL, so `a` was written and every `b` value failed
    with `CONTEXT_UNAVAILABLE`."""
    seed_mixed(n, tenant=None)
    p, run = begin(TenantMixed, **MIXED_BOTH)
    with pytest.raises(Kill):
        drive(p, run, hooks=kill_after_batch(1))
    _, _, error = command("abandon", run.run_id)
    assert error is None
    return run.run_id


def test_bf28_a_column_a_run_covered_and_never_wrote_is_not_held(permissive):
    """#291's example. `a` is not tenant-bound and is written; `b` is, its
    tenant column is NULL on every row, and every value fails. The run's
    own `values_written` is above zero, but `b` was never written, so
    abandoning the run releases `b`'s tenant column."""
    run_id = abandoned_unwritten_b_run()
    first = state.load_run(connection, run_id)
    assert first.values_written == 10 and first.values_failed == 10
    assert written_by_column(run_id) == {
        column_hex("a"): 10, column_hex("b"): 0}
    assert state.failures_by_code(connection, run_id) == {
        "CONTEXT_UNAVAILABLE": 10}

    # Both columns, under another tenant column for `b`.
    p, second = begin(TenantMixed, **{**MIXED_BOTH, "tenant": "region"})
    outcome = drive(p, second)
    assert outcome.run.status == "complete"
    # `a`'s first ten values are `current` now; `b` was never converted.
    assert written_by_column(second.run_id) == {
        column_hex("a"): 15, column_hex("b"): 25}
    assert outcome.run.values_current == 10
    assert_column_sums(second.run_id)
    for pk, region in TenantMixed.objects.values_list("pk", "region"):
        with tenant_scope(str(region).encode()):
            assert TenantMixed.objects.get(pk=pk).b.startswith("b-value-")


def test_bf28_b_alone_starts_under_another_tenant_column(permissive):
    run_id = abandoned_unwritten_b_run()
    p, run = begin(TenantMixed, columns=["b"], tenant="region")
    outcome = drive(p, run)
    assert outcome.run.status == "complete"
    assert outcome.run.values_written == 25
    assert state.load_run(connection, run_id).status == "abandoned"
    # The tenant column is the one the run now writes under: each value
    # reads back under its row's `region`.
    for pk, region in TenantMixed.objects.values_list("pk", "region"):
        with tenant_scope(str(region).encode()):
            assert TenantMixed.objects.get(pk=pk).b.startswith("b-value-")


def killed_mixed_run(n=25):
    seed_mixed(n)
    p, run = begin(TenantMixed, **MIXED_BOTH)
    with pytest.raises(Kill):
        drive(p, run, hooks=kill_after_batch(1))
    return run.run_id


def mixed_snapshot():
    return (all_raw(TenantMixed, "a"), all_raw(TenantMixed, "b"),
            all_raw(TenantMixed, "b_bidx"), mixed_runs(),
            repr(state_dump()))


def test_bf29_a_written_columns_tenant_is_still_refused(permissive):
    run_id = killed_mixed_run()
    assert written_by_column(run_id) == {
        column_hex("a"): 10, column_hex("b"): 10}
    assert state.abandon(connection, run_id)
    before = mixed_snapshot()

    with pytest.raises(BackfillError) as refused:
        begin(TenantMixed, columns=["b"], tenant="region")
    _, _, error = command(
        "encrypt", "tests.TenantMixed", "--columns", "b", "--tenant",
        "region", "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion")

    for message in (str(refused.value), str(error)):
        assert run_id in message and "(abandoned)" in message
        assert f"columns[{column_hex('b')}].tenant" in message
    assert mixed_snapshot() == before


def test_bf29_a_written_columns_index_is_still_refused(permissive,
                                                       monkeypatch):
    run_id = killed_mixed_run()
    assert state.abandon(connection, run_id)
    before = mixed_snapshot()
    field = TenantMixed._meta.get_field("b")
    monkeypatch.setattr(
        field, "index", dataclasses.replace(field.index, suite_id=0xFF02))
    reset_client()
    try:
        with pytest.raises(BackfillError) as refused:
            begin(TenantMixed, **MIXED_BOTH)
    finally:
        monkeypatch.undo()
        reset_client()
    message = str(refused.value)
    assert run_id in message
    assert f"columns[{column_hex('b')}].indexes[exact].suite_id" in message
    assert mixed_snapshot() == before


def test_bf29_a_changed_index_on_a_covered_unwritten_column_starts(
        permissive, monkeypatch):
    """`b` was covered and nothing in it was written (its tenant column is
    NULL), so another index declaration for it is not refused."""
    abandoned_unwritten_b_run()
    field = TenantMixed._meta.get_field("b")
    monkeypatch.setattr(
        field, "index", dataclasses.replace(field.index, suite_id=0xFF02))
    reset_client()
    try:
        p, second = begin(TenantMixed, **{**MIXED_BOTH, "tenant": "region"})
    finally:
        monkeypatch.undo()
        reset_client()
    assert second.status == "running"
    assert mixed_runs() == 2


def test_bf30_the_per_column_counts_sum_to_the_runs_at_every_commit(
        permissive):
    """Checked inside the transaction just before each commit, and after it,
    over a run killed between batches and resumed (BF-02's shape), then a
    second run over the finished table (every value `current`)."""
    # Rows of three kinds: both columns written; `tenant` NULL, so `b`
    # fails and `a` is written; `a` NULL and `b` written. Then NULLs in b.
    keys = []
    for i in range(25):
        obj = TenantMixed.objects.create(
            tenant=None if i % 5 == 3 else 1, region=1)
        if i % 7 != 0:
            plant(TenantMixed, obj.pk, "a", f"a-{i:03d}".encode())
        if i % 4 != 0:
            plant(TenantMixed, obj.pk, "b", f"b-{i:03d}".encode())
        keys.append(obj.pk)

    seen = []

    def check(_seq):
        assert_column_sums(p_run.run_id)
        seen.append(state.load_run(connection, p_run.run_id).batch_seq)

    p, p_run = begin(TenantMixed, **MIXED_BOTH)
    # The hook runs inside the batch's transaction, before the commit.
    killing = encrypt.Hooks(
        before_commit=lambda seq: check(seq),
        between_batches=lambda seq: (check(seq), kill_after_batch(2)
                                     .between_batches(seq)))
    with pytest.raises(Kill):
        drive(p, p_run, hooks=killing)
    # Two batches committed, and the sums agree after both.
    assert state.load_run(connection, p_run.run_id).batch_seq == 2
    assert_column_sums(p_run.run_id)
    assert len(seen) >= 4

    resumed = resume(p_run.run_id, hooks=encrypt.Hooks(
        before_commit=lambda seq: assert_column_sums(p_run.run_id),
        between_batches=lambda seq: assert_column_sums(p_run.run_id)))
    assert resumed.run.status == "complete"
    assert_column_sums(p_run.run_id)
    totals = state.load_column_counts(connection, p_run.run_id)
    # Every kind of count is exercised, so a column left out of the sum
    # would show: written, null and failed are all above zero somewhere.
    for name in ("values_written", "values_null", "values_failed"):
        assert sum(c[name] for c in totals.values()) > 0, name
    assert totals[column_hex("b")]["values_failed"] > 0
    assert totals[column_hex("a")]["values_failed"] == 0

    # The follow-up run: every converted value is `current` to it, and the
    # sums are checked inside and after each of its commits too.
    p2, second = begin(TenantMixed, **MIXED_BOTH)
    again = drive(p2, second, hooks=encrypt.Hooks(
        before_commit=lambda seq: assert_column_sums(second.run_id),
        between_batches=lambda seq: assert_column_sums(second.run_id)))
    assert again.run.values_current > 0
    assert_column_sums(second.run_id)


def test_bf30_the_column_rows_exist_from_the_insert_with_zero_counts(
        permissive):
    seed_mixed(3)
    p, run = begin(TenantMixed, **MIXED_BOTH)
    assert state.load_column_counts(connection, run.run_id) == {
        column_hex("a"): dict.fromkeys(state.VALUE_COUNTS, 0),
        column_hex("b"): dict.fromkeys(state.VALUE_COUNTS, 0)}


def test_bf30_a_batch_killed_before_commit_moves_no_column_count(permissive):
    """BF-03's shape: the per-column update is in the batch's transaction."""
    seed_mixed(25)
    p, run = begin(TenantMixed, **MIXED_BOTH)

    def die(_seq):
        raise Kill

    with pytest.raises(Kill):
        drive(p, run, hooks=encrypt.Hooks(before_commit=die))

    assert state.load_column_counts(connection, run.run_id) == {
        column_hex("a"): dict.fromkeys(state.VALUE_COUNTS, 0),
        column_hex("b"): dict.fromkeys(state.VALUE_COUNTS, 0)}
    assert state.load_run(connection, run.run_id).values_written == 0


def test_a_batch_whose_column_row_is_missing_is_rolled_back(permissive):
    seed_mixed(5)
    p, run = begin(TenantMixed, **MIXED_BOTH)
    with connection.cursor() as cur:
        cur.execute(f"DELETE FROM {state.COLUMNS} WHERE column_uuid = %s",
                    [column_hex("b")])
    before = all_raw(TenantMixed, "a")
    with pytest.raises(BackfillError, match="no fieldseal_backfill_columns"):
        drive(p, run)
    assert all_raw(TenantMixed, "a") == before
    assert state.load_run(connection, run.run_id).batch_seq == 0


def test_a_refused_start_leaves_no_orphan_column_rows(shape):
    """BF-19's shape: the second start is refused by the unique constraint,
    and the column rows are in the same transaction as the run row, so
    nothing of it is left."""
    shape.seed(emails(3))
    p, run = begin(shape)
    with connection.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {state.COLUMNS}")
        rows = cur.fetchone()[0]

    with pytest.raises(state.RunHeld) as held:
        encrypt.new_run(p)

    assert held.value.holder == run.run_id
    with connection.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {state.COLUMNS}")
        assert cur.fetchone()[0] == rows == len(shape.columns)
        cur.execute(f"SELECT COUNT(*) FROM {state.COLUMNS} WHERE run_id NOT "
                    f"IN (SELECT run_id FROM {state.RUNS})")
        assert cur.fetchone()[0] == 0


def test_the_run_row_and_its_column_rows_are_one_transaction(shape):
    """If a column row cannot be inserted, the run row goes with it."""
    shape.seed(emails(3))
    p = encrypt.plan(shape.model, shape.columns, shape.sources)
    at = state.now()
    run = state.Run(
        run_id=str(uuid.uuid4()), procedure_version=3, job="encrypt",
        table_uuid=p.config["table_uuid"],
        running_table_uuid=p.config["table_uuid"], table_name="t",
        config_hash=p.config_hash, config=p.config_text, status="running",
        batch_seq=0, cursor_value=None, rows_scanned=0, values_written=0,
        values_current=0, values_null=0, values_anomalous=0, values_failed=0,
        started_at=at, updated_at=at, completed_at=None, frontend="test")
    twice = [c["column_uuid"] for c in p.config["columns"]] * 2

    # A column row's failure is what it is, not "the table is held".
    with pytest.raises(IntegrityError):
        state.insert_run(connection, run, twice)

    assert state.load_run(connection, run.run_id) is None
    assert state.load_column_counts(connection, run.run_id) == {}


def plant_version_2(run_id):
    """A version-2 run's state: a version-2 `config`, no column rows."""
    document = json.loads(state.load_run(connection, run_id).config)
    document["procedure_version"] = 2
    text = config.serialize(document)
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {state.RUNS} SET config = %s, config_hash = %s, "
            "procedure_version = 2 WHERE run_id = %s",
            [text, config.digest(text), run_id])
        cur.execute(f"DELETE FROM {state.COLUMNS} WHERE run_id = %s",
                    [run_id])


def test_bf31_a_version_2_run_is_still_compared_per_run(permissive):
    """The run wrote `a` only (its tenant column was NULL on every row), but
    a version-2 run has no per-column count, so it still fixes `b`'s tenant
    column: the limit PROCEDURE §12 states."""
    run_id = abandoned_unwritten_b_run()
    plant_version_2(run_id)
    assert state.load_column_counts(connection, run_id) == {}
    before = mixed_snapshot()

    with pytest.raises(BackfillError) as refused:
        begin(TenantMixed, **{**MIXED_BOTH, "tenant": "region"})

    message = str(refused.value)
    assert run_id in message and "(abandoned)" in message
    assert f"columns[{column_hex('b')}].tenant" in message
    assert mixed_snapshot() == before


def test_bf31_a_version_2_run_with_the_same_declarations_starts(permissive):
    run_id = abandoned_unwritten_b_run()
    plant_version_2(run_id)

    p, second = begin(TenantMixed, **MIXED_BOTH)

    assert second.status == "running"


def damage_column_rows(run_id):
    """The columns table re-created by `init` after a run: no rows for it."""
    with connection.cursor() as cur:
        cur.execute(f"DELETE FROM {state.COLUMNS} WHERE run_id = %s", [run_id])


def test_a_version_3_run_whose_column_counts_do_not_add_up_is_compared_per_run(
        permissive):
    """PROCEDURE §4: not refused, which would be the dead end #291 removed.
    Compared per run, as version 2, and warned about."""
    run_id = abandoned_unwritten_b_run()
    damage_column_rows(run_id)
    warnings = []

    # The same declarations: starts, with the warning.
    p = encrypt.plan(TenantMixed, **{"columns": ["a", "b"], "sources": {},
                                     "tenant": "tenant"})
    second = encrypt.new_run(p, warnings.append)

    assert second.status == "running"
    (warning,) = warnings
    assert run_id in warning and "add up to 0" in warning
    assert "recorded 10 values written" in warning
    assert "compared per run" in warning
    # Per run: `b`'s tenant column is held again, by the run's total.
    state.abandon(connection, second.run_id)
    p = encrypt.plan(TenantMixed, ["a", "b"], {}, "region")
    with pytest.raises(BackfillError) as refused:
        encrypt.new_run(p)
    assert f"columns[{column_hex('b')}].tenant" in str(refused.value)


def test_the_report_gives_the_counts_per_column(permissive):
    seed_mixed(12, tenant=None)
    out, _, error = command(
        "encrypt", "tests.TenantMixed", "--columns", "a,b", "--tenant",
        "tenant", "--rows-per-second", "100000",
        "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion")
    assert error is None
    document = json.loads(out.splitlines()[-1])
    assert document["columns"] == {
        column_hex("a"): {"values_written": 12, "values_current": 0,
                          "values_null": 0, "values_anomalous": 0,
                          "values_failed": 0},
        column_hex("b"): {"values_written": 0, "values_current": 0,
                          "values_null": 0, "values_anomalous": 0,
                          "values_failed": 12}}
    assert f"column {column_hex('b')}: written 0" in out
    assert_no_leak(out, TenantMixed, [f"a-value-{i:03d}" for i in range(12)],
                   ["a", "b"])


def test_bf31_a_version_2_runs_index_declaration_is_compared_too(
        permissive, monkeypatch):
    """The `indexes` half of BF-31. The run wrote nothing in `b`, but with no
    per-column count a version-2 run still fixes `b`'s index declaration."""
    run_id = abandoned_unwritten_b_run()
    plant_version_2(run_id)
    before = mixed_snapshot()
    field = TenantMixed._meta.get_field("b")
    monkeypatch.setattr(
        field, "index", dataclasses.replace(field.index, suite_id=0xFF02))
    reset_client()
    try:
        with pytest.raises(BackfillError) as refused:
            begin(TenantMixed, **MIXED_BOTH)
    finally:
        monkeypatch.undo()
        reset_client()
    message = str(refused.value)
    assert run_id in message
    assert f"columns[{column_hex('b')}].indexes[exact].suite_id" in message
    assert mixed_snapshot() == before


def running_mixed_run():
    """Run R: `a` written, `b` not yet (the first ten rows have no tenant),
    killed after one batch, so it is still `running`."""
    for i in range(25):
        obj = TenantMixed.objects.create(
            tenant=None if i < 10 else 1, region=2)
        plant(TenantMixed, obj.pk, "a", f"a-value-{i:03d}".encode())
        plant(TenantMixed, obj.pk, "b", f"b-value-{i:03d}".encode())
    p, run = begin(TenantMixed, **MIXED_BOTH)
    with pytest.raises(Kill):
        drive(p, run, hooks=kill_after_batch(1))
    assert written_by_column(run.run_id) == {
        column_hex("a"): 10, column_hex("b"): 0}
    return run.run_id


def test_a_running_run_refuses_a_new_start_before_any_comparison(
        permissive, monkeypatch):
    run_id = running_mixed_run()

    def never(*args):
        raise AssertionError("compared while a run was running")

    monkeypatch.setattr(state, "converting_runs", never)
    before = mixed_runs()

    with pytest.raises(state.RunHeld) as held:
        begin(TenantMixed, columns=["b"], tenant="region")
    _, _, error = command(
        "encrypt", "tests.TenantMixed", "--columns", "b", "--tenant",
        "region", "--acknowledge-preexisting-backups",
        "--acknowledge-in-place-conversion")

    assert held.value.holder == run_id
    assert run_id in str(held.value) and run_id in str(error)
    assert mixed_runs() == before


def test_a_run_that_finishes_after_the_check_cannot_be_walked_around(
        permissive, monkeypatch):
    """The interleaving: R (`--tenant tenant`) is running and has written
    `a` and not `b`; a new run under `region` passes a per-column check;
    R then finishes, writing `b` under `tenant`; the new run inserts and
    writes the rest of `b` under `region`. The new run is refused before
    it compares anything, so R's finishing cannot be raced."""
    run_id = running_mixed_run()
    real = state.converting_runs
    finished = []

    def finish_after_the_check(connection, table_uuid):
        runs = real(connection, table_uuid)  # R's `b` count is 0 here
        finished.append(resume(run_id).run)  # R now writes `b` under `tenant`
        return runs

    monkeypatch.setattr(state, "converting_runs", finish_after_the_check)

    with pytest.raises(state.RunHeld) as held:
        begin(TenantMixed, columns=["b"], tenant="region")

    assert held.value.holder == run_id
    assert not finished  # R was never run to its end by the interleaving
    assert state.load_run(connection, run_id).status == "running"
    assert written_by_column(run_id)[column_hex("b")] == 0


def test_bf32_a_run_that_starts_and_completes_during_the_comparison(
        permissive, monkeypatch):
    """#308. R (`b` under `region`) starts; while it compares against
    earlier runs, a whole run X (`b` under `tenant`) starts, writes every
    `b` value and completes. Under the old order (refuse if running, compare,
    then insert), X existed at neither read and no longer held the table at
    the insert, so R would then write `b` under another tenant column with
    nothing raised. R's run row now goes in first, so X's start is refused
    by the unique constraint, naming R, and X writes nothing.

    X runs on R's connection, inside R's open transaction, so it sees R's
    row there. This pins the order (insert, then compare) and not the race
    itself: another connection waiting on the unique index until R's
    transaction ends is the database's behaviour and is not exercised here.
    That the insert and the comparison are one transaction is pinned by
    `test_bf32_a_refused_comparison_inserts_nothing`."""
    seed_mixed(25, tenant=1, region=2)
    real = state.converting_runs
    interleaved: list = []
    refused: list = []
    started: list = []

    def a_whole_run_during_the_comparison(connection_, table_uuid):
        runs = real(connection_, table_uuid)
        if not started:  # once: X's own start compares too
            started.append(True)
            try:
                interleaved.append(go(TenantMixed, columns=["b"],
                                      tenant="tenant"))
            except state.RunHeld as e:
                refused.append(e)
        return runs

    monkeypatch.setattr(state, "converting_runs",
                        a_whole_run_during_the_comparison)

    p, r = begin(TenantMixed, columns=["b"], tenant="region")

    assert interleaved == []
    [held] = refused
    assert held.holder == r.run_id
    assert run_rows() == 1  # R only: X's row was never inserted
    assert state.load_run(connection, r.run_id).status == "running"
    assert written_by_column(r.run_id) == {column_hex("b"): 0}
    assert non_envelopes(TenantMixed, "b")["envelope"] == 0


def test_bf32_a_refused_comparison_inserts_nothing(permissive):
    """The insert now comes first, so a refused comparison must take the run
    row and its column rows back (§4: "insert nothing")."""
    seed_mixed(25, tenant=1, region=2)
    outcome = go(TenantMixed, columns=["b"], tenant="tenant")
    assert outcome.run.status == "complete"
    before = run_rows()
    with connection.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {state.COLUMNS}")
        column_rows = cur.fetchone()[0]

    with pytest.raises(BackfillError, match="columns\\[.*\\]\\.tenant"):
        begin(TenantMixed, columns=["b"], tenant="region")

    assert run_rows() == before
    with connection.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {state.COLUMNS}")
        assert cur.fetchone()[0] == column_rows
    assert state.running_run(connection, outcome.run.table_uuid) is None


@pytest.mark.skipif(connection.vendor != "postgresql",
                    reason="PostgreSQL's isolation levels; SQLite holds the "
                           "write lock from the start")
def test_bf32_the_comparison_reads_committed_on_postgres(permissive,
                                                         monkeypatch):
    """#308: the comparison must see every run committed before each of its
    statements. A connection defaulting to REPEATABLE READ would read every
    run as of the insert's snapshot; the start's transaction sets READ
    COMMITTED for itself."""
    seed_mixed(5, tenant=1, region=2)
    real = state.converting_runs
    seen: list = []

    def isolation(connection_, table_uuid):
        with connection_.cursor() as cur:
            cur.execute("SHOW transaction_isolation")
            seen.append(cur.fetchone()[0])
        return real(connection_, table_uuid)

    monkeypatch.setattr(state, "converting_runs", isolation)
    with connection.cursor() as cur:
        cur.execute("SHOW default_transaction_isolation")
        before = cur.fetchone()[0]
        cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION "
                    "ISOLATION LEVEL REPEATABLE READ")
    try:
        begin(TenantMixed, columns=["b"], tenant="region")
        with connection.cursor() as cur:
            cur.execute("SHOW transaction_isolation")
            after = cur.fetchone()[0]
    finally:
        # The session's own setting, not a fixed level: the connection is
        # shared with the tests that follow.
        with connection.cursor() as cur:
            cur.execute("SELECT set_config('default_transaction_isolation', "
                        "%s, false)", [before])
    assert seen == ["read committed"]
    assert after == "repeatable read"  # the session's own setting is kept


def test_a_column_named_twice_is_refused_at_plan():
    with pytest.raises(BackfillError, match="more than once"):
        encrypt.plan(TenantMixed, ["a", "a"], {}, None)
    before = run_rows()
    _, _, error = command(
        "encrypt", "tests.TenantMixed", "--columns", "a,a")
    assert isinstance(error, CommandError)
    assert "more than once" in str(error) and "already running" not in str(error)
    assert run_rows() == before == 0
