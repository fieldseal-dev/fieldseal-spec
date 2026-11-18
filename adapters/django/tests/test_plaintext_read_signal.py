"""The `plaintext_read` signal and its per-field counter (`docs/12` §4, §8;
#246).

Spec §10.3: `permissive` and `readonly` return non-envelope input as it is
and SHOULD count those reads. The core counts them for the whole client;
`tools/backfill/PROCEDURE.md` §8 gates the switch to `strict` on the count
per model and field. These tests hold the adapter's signal and counter to
the core's count, read for read: once per value passed through, including a
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

import pytest
from django.conf import settings
from django.db import connection
from django.test.utils import override_settings
from fieldseal.errors import NotCiphertext, UnknownFormatVersion

from fieldseal_django.apps import get_client, reset_client
from fieldseal_django.errors import FieldsealNotSupported
from fieldseal_django.signals import plaintext_read, plaintext_read_counts

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


def test_a_raising_receiver_propagates_and_the_read_is_still_counted():
    """The count is taken before the signal is sent, so a receiver that
    fails cannot hide the read from the metric. Its exception reaches the
    caller, as Django's `send` delivers it."""
    pk = patient(note="seen")
    plant(pk, "note", b"legacy")

    class Boom(Exception):
        pass

    def receiver(**kwargs):
        raise Boom

    plaintext_read.connect(receiver, weak=False)
    try:
        with read_mode("permissive") as client:
            with pytest.raises(Boom):
                Patient.objects.get(pk=pk)
            assert client.plaintext_reads == 1
            assert plaintext_read_counts() == {NOTE: 1}
    finally:
        plaintext_read.disconnect(receiver)
