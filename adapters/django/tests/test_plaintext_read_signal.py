"""The `plaintext_read` signal and its per-field counter (`docs/12` §4, §8;
#246).

Spec §10.3: `permissive` and `readonly` return non-envelope input as it is
and SHOULD count those reads. The core counts them for the whole client;
the adapter counts them per model and field, so that a count
`tools/backfill/PROCEDURE.md` §8 needs at zero names its column. These
tests hold the adapter's signal and counter to the core's count, read for
read: once per value passed through, including a
value the codec then refuses (#253), and never for an envelope or for a read
the core refuses.

The legacy values are planted with raw SQL, as rows written before the
column was encrypted would be. The SQLite storage-class and `base64` refusal
paths are covered where those states are made
(`test_legacy_storage_class.py`, `test_legacy_base64_column.py`), by the
same per-field assertion next to each of their core-count assertions.
"""

from __future__ import annotations

import contextlib
import functools
import gc

import pytest
from django.conf import settings
from django.db import connection
from django.test.utils import override_settings
from fieldseal.errors import NotCiphertext, UnknownFormatVersion

from fieldseal_django.apps import get_client, reset_client
from fieldseal_django.errors import FieldsealNotSupported
from fieldseal_django.signals import (
    plaintext_read,
    plaintext_read_counts,
    plaintext_read_receiver_failures,
)

from .models import Patient

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.filterwarnings("ignore::fieldseal.errors.FieldsealWarning"),
]

PASS_THROUGH = ["permissive", "readonly"]

#: `fmt_ver` 0x02 at the minimum plausible envelope length (spec §3.4):
#: `UNKNOWN_FORMAT_VERSION` in every mode, so never a plaintext read.
RESERVED = b"\x02" + b"\x00" * 110


@contextlib.contextmanager
def read_mode(mode):
    cfg = dict(settings.FIELDSEAL)
    cfg["READ_MODE"] = mode
    try:
        with override_settings(FIELDSEAL=cfg):
            reset_client()
            yield get_client()
    finally:
        reset_client()


@contextlib.contextmanager
def received():
    """Every `plaintext_read` sent inside the block, as its kwargs."""
    seen: list[dict] = []

    def receiver(**kwargs):
        seen.append(kwargs)

    plaintext_read.connect(receiver, weak=False)
    try:
        yield seen
    finally:
        plaintext_read.disconnect(receiver)


def plant(pk, column, value):
    """Overwrite one stored value with the ORM out of the way."""
    with connection.cursor() as cur:
        cur.execute(
            f"UPDATE {connection.ops.quote_name(Patient._meta.db_table)} "
            f"SET {connection.ops.quote_name(column)} = %s WHERE id = %s",
            [value, pk])


def patient(**values):
    """A patient written in strict, so every value starts as an envelope."""
    with read_mode("strict"):
        return Patient.objects.create(email="ada@example.com", **values).pk


NOTE = (Patient._meta.label, "note")
AGE = (Patient._meta.label, "age")


@pytest.mark.parametrize("mode", PASS_THROUGH)
def test_a_plaintext_read_is_signalled_once_with_model_and_field(mode):
    """`docs/12` §8: a plaintext read increments the signal exactly once per
    value. The receiver gets the model and the field name, never the
    value."""
    pk = patient(note="seen")
    plant(pk, "note", b"legacy note")
    with read_mode(mode) as client, received() as seen:
        assert Patient.objects.get(pk=pk).note == "legacy note"
        assert client.plaintext_reads == 1
        assert plaintext_read_counts() == {NOTE: 1}
    assert seen == [{"signal": plaintext_read, "sender": Patient,
                     "field": "note"}]


@pytest.mark.parametrize("mode", ["strict", *PASS_THROUGH])
def test_an_envelope_is_not_a_plaintext_read(mode):
    pk = patient(note="seen", age=36)
    with read_mode(mode) as client, received() as seen:
        got = Patient.objects.get(pk=pk)
        assert (got.email, got.note, got.age) == ("ada@example.com", "seen", 36)
        assert client.plaintext_reads == 0
        assert plaintext_read_counts() == {}
    assert seen == []


def test_strict_refuses_and_neither_counts_nor_signals():
    pk = patient(note="seen")
    plant(pk, "note", b"legacy note")
    with read_mode("strict") as client, received() as seen:
        with pytest.raises(NotCiphertext):
            Patient.objects.get(pk=pk)
        assert client.plaintext_reads == 0
        assert plaintext_read_counts() == {}
    assert seen == []


@pytest.mark.parametrize("mode", ["strict", *PASS_THROUGH])
def test_a_reserved_version_is_refused_and_not_a_plaintext_read(mode):
    """`is_ciphertext` answers false for a reserved version, but `decrypt`
    raises on it in every mode (spec §3.4). The signal follows `decrypt`:
    nothing was passed through, so nothing is counted."""
    pk = patient(note="seen")
    plant(pk, "note", RESERVED)
    with read_mode(mode) as client, received() as seen:
        with pytest.raises(UnknownFormatVersion):
            Patient.objects.get(pk=pk)
        assert client.plaintext_reads == 0
        assert plaintext_read_counts() == {}
    assert seen == []


@pytest.mark.parametrize("mode", PASS_THROUGH)
def test_a_value_the_codec_refuses_is_still_counted_and_signalled(mode):
    """The core passed the bytes through and counted them before the codec
    refused them (#253). The per-field count must not read lower than the
    core's on exactly the rows an operator still has to deal with."""
    pk = patient(note="seen")
    plant(pk, "note", b"\xff\xfe not utf-8")
    with read_mode(mode) as client, received() as seen:
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.get(pk=pk)
        assert client.plaintext_reads == 1
        assert plaintext_read_counts() == {NOTE: 1}
    assert [s["field"] for s in seen] == ["note"]


def test_counts_are_per_model_and_field_and_sum_to_the_core_count():
    legacy_note = patient(note="seen", age=36)
    legacy_both = patient(note="seen", age=36)
    clean = patient(note="seen", age=36)
    plant(legacy_note, "note", b"one")
    plant(legacy_both, "note", b"two")
    plant(legacy_both, "age", b"41")
    with read_mode("permissive") as client, received() as seen:
        got = {p.pk: (p.note, p.age) for p in Patient.objects.all()}
        assert got == {legacy_note: ("one", 36), legacy_both: ("two", 41),
                       clean: ("seen", 36)}
        counts = plaintext_read_counts()
        assert counts == {NOTE: 2, AGE: 1}
        assert sum(counts.values()) == client.plaintext_reads == 3
    assert sorted(s["field"] for s in seen) == ["age", "note", "note"]


def test_every_read_of_a_value_is_counted():
    """The count is reads, not rows: the same legacy value read twice is
    two plaintext reads, as it is to the core."""
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    with read_mode("permissive") as client:
        Patient.objects.get(pk=pk)
        list(Patient.objects.filter(pk=pk).values_list("note", flat=True))
        assert client.plaintext_reads == 2
        assert plaintext_read_counts() == {NOTE: 2}


def test_the_snapshot_is_a_copy():
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    with read_mode("permissive"):
        Patient.objects.get(pk=pk)
        before = plaintext_read_counts()
        Patient.objects.get(pk=pk)
        assert before == {NOTE: 1}
        assert plaintext_read_counts() == {NOTE: 2}


def test_the_counts_reset_with_the_client():
    """A rebuilt client starts its core count at zero; the per-field counts
    start with it, so the two always cover the same reads."""
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    with read_mode("permissive"):
        Patient.objects.get(pk=pk)
        assert plaintext_read_counts() == {NOTE: 1}
        reset_client()
        assert plaintext_read_counts() == {}
        assert get_client().plaintext_reads == 0
        Patient.objects.get(pk=pk)
        assert plaintext_read_counts() == {NOTE: 1}


def test_a_supplied_client_keeps_its_counts_across_a_reset():
    """`reset_client` hands a `FIELDSEAL["CLIENT"]` instance back unchanged,
    with its core count. The per-field counts belong to the client object,
    so they are kept with it rather than wiped under it."""
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    with read_mode("permissive") as client:
        cfg = dict(settings.FIELDSEAL)
        cfg["READ_MODE"] = "permissive"
        cfg["CLIENT"] = client
        with override_settings(FIELDSEAL=cfg):
            assert get_client() is client
            Patient.objects.get(pk=pk)
            reset_client()
            assert get_client() is client
            Patient.objects.get(pk=pk)
            assert client.plaintext_reads == 2
            assert plaintext_read_counts() == {NOTE: 2}


def test_a_read_through_a_dropped_client_is_not_counted_for_the_new_one():
    """A read that began on the old client and is recorded after a reset
    counts against the old client, which is what the core counted."""
    from fieldseal_django.signals import record_plaintext_read

    with read_mode("permissive"):
        old = get_client()
        reset_client()
        new = get_client()
        assert new is not old
        record_plaintext_read(old, Patient, "note")
        assert plaintext_read_counts() == {}


def test_a_raising_receiver_is_logged_and_the_read_goes_on(caplog):
    """A metrics hook that fails must not turn a legacy row into an error,
    nor a backfill's in-place read into `INTERNAL`: the signal is sent with
    `send_robust`, the exception is logged (once, #295), and the count was
    taken first."""
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")

    class Boom(Exception):
        pass

    def receiver(**kwargs):
        raise Boom("metrics backend down")

    plaintext_read.connect(receiver, weak=False)
    try:
        with read_mode("permissive") as client, caplog.at_level(
                "ERROR", logger="fieldseal_django"):
            assert Patient.objects.get(pk=pk).note == "legacy"
            assert client.plaintext_reads == 1
            assert plaintext_read_counts() == {NOTE: 1}
    finally:
        plaintext_read.disconnect(receiver)
    [record] = [r for r in caplog.records if r.levelname == "ERROR"]
    assert record.name == "fieldseal_django"
    assert "tests.Patient.note" in record.getMessage()
    assert isinstance(record.exc_info[1], Boom)
    assert "legacy" not in record.getMessage()


class Boom(Exception):
    pass


def boom(**kwargs):
    raise Boom("metrics backend down")


def boom_too(**kwargs):
    raise Boom("the other backend down")


@contextlib.contextmanager
def connected(*receivers):
    for r in receivers:
        plaintext_read.connect(r, weak=False)
    try:
        yield
    finally:
        for r in receivers:
            plaintext_read.disconnect(r)


def fs_records(caplog):
    """Every ERROR record, on every logger. Django's own `send_robust` logs
    each receiver failure on `django.dispatch` unless the signal switches it
    off, so a filter on `fieldseal_django` would hide that."""
    return [r for r in caplog.records if r.levelname == "ERROR"]


def test_django_still_has_the_hook_the_signal_silences():
    """`_PlaintextReadSignal` overrides a private Django method. If Django
    renames it, the override silently stops working; fail here instead."""
    import django.dispatch

    assert callable(getattr(django.dispatch.Signal,
                            "_log_robust_failure", None))


class Instance:
    def __init__(self, label):
        self.label = label

    def on_read(self, **kwargs):
        raise Boom(self.label)


class CallableInstance:
    def __call__(self, **kwargs):
        raise Boom("callable instance")


@pytest.mark.parametrize("make", [
    lambda: functools.partial(boom),
    CallableInstance,
], ids=["partial", "callable-instance"])
def test_a_receiver_with_no_qualname_cannot_break_a_read(caplog, make):
    receiver = make()
    pks = [patient(note="seen") for _ in range(3)]
    for pk in pks:
        plant(pk, "note", b"legacy")
    with connected(receiver), read_mode("permissive") as client, \
            caplog.at_level("ERROR"):
        got = [Patient.objects.get(pk=pk).note for pk in pks]
        assert got == ["legacy"] * 3
        assert client.plaintext_reads == 3
        assert list(plaintext_read_receiver_failures().values()) == [3]
    assert len(fs_records(caplog)) == 1


def test_two_instances_of_one_class_are_each_logged_once(caplog):
    a, b = Instance("a"), Instance("b")
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    n = 4
    with connected(a.on_read, b.on_read), read_mode("permissive"), \
            caplog.at_level("ERROR"):
        for _ in range(n):
            Patient.objects.get(pk=pk)
        failures = plaintext_read_receiver_failures()
    name = f"{Instance.__module__}.{Instance.on_read.__qualname__}"
    assert failures == {name: 2 * n}
    assert len(fs_records(caplog)) == 2
    assert {r.exc_info[1].args[0] for r in fs_records(caplog)} == {"a", "b"}


def test_a_failing_receiver_is_logged_once_and_counted_every_time(caplog):
    """#295: one traceback per read was unbounded (50 reads, 50 records).
    The first failure is logged with its traceback; the rest are counted."""
    n = 5
    pks = [patient(note="seen") for _ in range(n)]
    for pk in pks:
        plant(pk, "note", b"legacy secret")
    name = f"{boom.__module__}.{boom.__qualname__}"
    with connected(boom), read_mode("permissive") as client, caplog.at_level(
            "ERROR", logger="fieldseal_django"):
        got = [Patient.objects.get(pk=pk).note for pk in pks]
        assert got == ["legacy secret"] * n
        assert client.plaintext_reads == n
        assert plaintext_read_counts() == {NOTE: n}
        assert plaintext_read_receiver_failures() == {name: n}
    [record] = fs_records(caplog)
    assert isinstance(record.exc_info[1], Boom)
    assert name in record.getMessage()
    assert "counted, not logged" in record.getMessage()
    assert "plaintext_read_receiver_failures" in record.getMessage()
    assert "legacy secret" not in record.getMessage()
    assert "legacy secret" not in repr(record.__dict__)


def test_two_failing_receivers_are_logged_once_each(caplog):
    pks = [patient(note="seen") for _ in range(3)]
    for pk in pks:
        plant(pk, "note", b"legacy")
    with connected(boom, boom_too), read_mode("permissive"), caplog.at_level(
            "ERROR", logger="fieldseal_django"):
        for pk in pks:
            Patient.objects.get(pk=pk)
        failures = plaintext_read_receiver_failures()
    assert sorted(failures.values()) == [3, 3]
    assert len(fs_records(caplog)) == 2


def test_a_rebuilt_client_logs_a_failing_receiver_again(caplog):
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    with connected(boom), read_mode("permissive"), caplog.at_level(
            "ERROR", logger="fieldseal_django"):
        Patient.objects.get(pk=pk)
        Patient.objects.get(pk=pk)
        assert len(fs_records(caplog)) == 1
        reset_client()
        assert plaintext_read_receiver_failures() == {}
        Patient.objects.get(pk=pk)
        assert len(fs_records(caplog)) == 2
        assert list(plaintext_read_receiver_failures().values()) == [1]


def test_a_supplied_client_keeps_its_receiver_failures_across_a_reset(caplog):
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    with connected(boom), read_mode("permissive") as client, caplog.at_level(
            "ERROR", logger="fieldseal_django"):
        cfg = dict(settings.FIELDSEAL)
        cfg["READ_MODE"] = "permissive"
        cfg["CLIENT"] = client
        with override_settings(FIELDSEAL=cfg):
            Patient.objects.get(pk=pk)
            reset_client()
            assert get_client() is client
            Patient.objects.get(pk=pk)
            assert list(plaintext_read_receiver_failures().values()) == [2]
    assert len(fs_records(caplog)) == 1


def test_receiver_failures_are_empty_without_a_failure_and_a_copy():
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    with read_mode("permissive"):
        assert plaintext_read_receiver_failures() == {}
        Patient.objects.get(pk=pk)
        assert plaintext_read_receiver_failures() == {}
        with connected(boom):
            Patient.objects.get(pk=pk)
            before = plaintext_read_receiver_failures()
            Patient.objects.get(pk=pk)
            assert list(before.values()) == [1]
            assert list(plaintext_read_receiver_failures().values()) == [2]
    assert plaintext_read_receiver_failures() == {}


def test_two_weakly_connected_bound_methods_are_logged_once_each(caplog):
    """`weak=True` is what `@receiver` uses: Django resolves a fresh bound
    method on every send, so the identity must not be the method object's."""
    a, b = Instance("a"), Instance("b")
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    plaintext_read.connect(a.on_read)
    plaintext_read.connect(b.on_read)
    n = 6
    try:
        with read_mode("permissive"), caplog.at_level("ERROR"):
            for _ in range(n):
                Patient.objects.get(pk=pk)
            failures = plaintext_read_receiver_failures()
    finally:
        plaintext_read.disconnect(a.on_read)
        plaintext_read.disconnect(b.on_read)
    assert list(failures.values()) == [2 * n]
    assert len(fs_records(caplog)) == 2


def test_a_receiver_that_lands_on_a_freed_ones_id_is_still_logged():
    """CPython reuses ids. Five generations of a receiver, each connected,
    failed once, disconnected and freed, are five first failures, and leave
    nothing behind."""
    import logging

    from fieldseal_django import signals

    class Count(logging.Handler):
        n = 0

        def emit(self, record):
            # Not kept: a record's `exc_info` would keep the receiver alive.
            self.n += 1

    handler = Count(level=logging.ERROR)
    log = logging.getLogger("fieldseal_django")
    log.addHandler(handler)
    log.propagate = False
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    try:
        with read_mode("permissive"):
            for i in range(5):
                obj = Instance(str(i))
                plaintext_read.connect(obj.on_read)
                Patient.objects.get(pk=pk)
                plaintext_read.disconnect(obj.on_read)
                del obj
                gc.collect()
            assert handler.n == 5
            assert list(plaintext_read_receiver_failures().values()) == [5]
            seen = signals._logged[get_client()]
            assert (seen.refs, seen.funcs, seen.fallback) == ({}, {}, set())
    finally:
        log.removeHandler(handler)
        log.propagate = True


def test_a_partial_is_named_after_its_function_and_never_leaks_its_arguments(
        caplog):
    secret = "sk_live_SECRET"
    receiver = functools.partial(boom, api_key=secret)
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    with connected(receiver), read_mode("permissive"), caplog.at_level("ERROR"):
        Patient.objects.get(pk=pk)
        failures = plaintext_read_receiver_failures()
    assert failures == {f"{boom.__module__}.{boom.__qualname__}": 1}
    assert secret not in repr(failures)
    for r in caplog.records:
        assert secret not in r.getMessage()
        assert secret not in repr(r.__dict__)


def test_a_receiver_whose_repr_raises_cannot_break_a_read(caplog):
    class BadRepr:
        def __call__(self, **kwargs):
            raise Boom("x")

        def __repr__(self):
            raise RuntimeError("repr must not be called")

    pk = patient(note="seen")
    plant(pk, "note", b"legacy")
    with connected(BadRepr()), read_mode("permissive"), \
            caplog.at_level("ERROR"):
        assert Patient.objects.get(pk=pk).note == "legacy"
        Patient.objects.get(pk=pk)
        failures = plaintext_read_receiver_failures()
    assert failures == {f"{BadRepr.__module__}.{BadRepr.__qualname__}": 2}
    assert len(fs_records(caplog)) == 1
