"""A `binary` column whose legacy values are not bytes (#251).

SQLite rebuilds a table for `AlterField` with `INSERT ... SELECT`, and a value
keeps its storage class whatever the new column is declared as. A column
changed from a plain field to `Encrypted(field, storage="binary")` is
declared `BLOB` and still holds TEXT, INTEGER or REAL values. The adapter
handed those to the core as they were: a permissive read raised `TypeError`
or `ValueError`, or, for an int, read 42 as 42 zero bytes.

Each test here makes the state the way an application does -- one value
written through the ORM into a plain column, then a real `AlterField` -- and
asserts what spec §10.3 asks of each mode: `NOT_CIPHERTEXT` in strict, and in
permissive exactly the value the inner field read before the `AlterField`.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import decimal
import itertools

import pytest
from django.conf import settings
from django.db import connection, models
from django.test.utils import isolate_apps, override_settings
from fieldseal.errors import NotCiphertext, UnknownFormatVersion

from fieldseal_django import Encrypted, FieldsealMeta
from fieldseal_django.apps import get_client, reset_client
from fieldseal_django.errors import FieldsealNotSupported

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.filterwarnings("ignore::fieldseal.errors.FieldsealWarning"),
]

sqlite_only = pytest.mark.skipif(connection.vendor != "sqlite",
                                 reason="SQLite storage classes")

_serial = itertools.count(1)

UTC = dt.timezone.utc

#: (id, inner field, value written, SQLite storage class after AlterField)
CASES = [
    ("char", lambda: models.CharField(max_length=100),
     "ada@example.com", "text"),
    ("text", models.TextField, "two\nlines", "text"),
    ("int", models.IntegerField, 42, "integer"),
    ("negative-int", models.IntegerField, -3, "integer"),
    ("big-int", models.BigIntegerField, 5551234567, "integer"),
    ("float", models.FloatField, 1.5, "real"),
    ("decimal", lambda: models.DecimalField(max_digits=10, decimal_places=2),
     decimal.Decimal("1.50"), "real"),
    # NUMERIC affinity stores a whole-valued decimal as an INTEGER.
    ("decimal-whole",
     lambda: models.DecimalField(max_digits=10, decimal_places=2),
     decimal.Decimal("2.00"), "integer"),
    ("bool", models.BooleanField, True, "integer"),
    ("date", models.DateField, dt.date(2026, 10, 5), "text"),
    ("datetime", models.DateTimeField,
     dt.datetime(2026, 10, 5, 12, 34, 56, 123456, tzinfo=UTC), "text"),
    ("datetime-whole-second", models.DateTimeField,
     dt.datetime(2026, 10, 5, 12, 34, 56, tzinfo=UTC), "text"),
]


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


def _models(make_inner, *, encrypted_inner=None):
    """A plain model and its encrypted successor over one table."""
    n = next(_serial)
    table = f"legacy251_{n}"
    Plain = type(f"Plain{n}", (models.Model,), {
        "__module__": "tests",
        "v": make_inner(),
        "Meta": type("Meta", (), {"db_table": table}),
    })
    Sealed = type(f"Sealed{n}", (models.Model,), {
        "__module__": "tests",
        "v": Encrypted((encrypted_inner or make_inner)(), storage="binary",
                       null=True,
                       column_uuid=f"018f3c2e-0000-7000-8000-251{n:09d}"),
        "fieldseal": FieldsealMeta(
            table_uuid=f"018f3c2e-0000-7000-8000-252{n:09d}"),
        "Meta": type("Meta", (), {"db_table": table, "managed": False}),
    })
    return Plain, Sealed


@contextlib.contextmanager
def altered(make_inner, value, *, encrypted_inner=None):
    """Write `value` into a plain column, then `AlterField` it to
    `Encrypted(..., storage="binary")`. Yields the encrypted model, the pk,
    and the value the plain field read back before the change."""
    Plain, Sealed = _models(make_inner, encrypted_inner=encrypted_inner)
    with connection.schema_editor() as editor:
        editor.create_model(Plain)
    try:
        pk = Plain.objects.create(v=value).pk
        before = Plain.objects.get(pk=pk).v
        with connection.schema_editor() as editor:
            editor.alter_field(Plain, Plain._meta.get_field("v"),
                               Sealed._meta.get_field("v"), strict=True)
        yield Sealed, pk, before
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(Plain)


def storage_class(model, pk):
    with connection.cursor() as cur:
        cur.execute(f"SELECT typeof(v) FROM {model._meta.db_table} "
                    "WHERE id = %s", [pk])
        return cur.fetchone()[0]


@sqlite_only
@isolate_apps("tests")
@pytest.mark.parametrize(("make_inner", "value", "klass"),
                         [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_strict_refuses_a_legacy_value_as_not_ciphertext(make_inner, value,
                                                         klass):
    with altered(make_inner, value) as (Sealed, pk, _):
        assert storage_class(Sealed, pk) == klass
        with read_mode("strict"), pytest.raises(NotCiphertext):
            Sealed.objects.get(pk=pk)


@sqlite_only
@isolate_apps("tests")
@pytest.mark.parametrize(("make_inner", "value", "klass"),
                         [c[1:] for c in CASES], ids=[c[0] for c in CASES])
@pytest.mark.parametrize("mode", ["permissive", "readonly"])
def test_a_pass_through_mode_reads_what_the_plain_field_read(
        mode, make_inner, value, klass):
    with altered(make_inner, value) as (Sealed, pk, before):
        assert storage_class(Sealed, pk) == klass
        with read_mode(mode) as client:
            assert Sealed.objects.get(pk=pk).v == before
            assert client.plaintext_reads == 1


@sqlite_only
@isolate_apps("tests")
@pytest.mark.parametrize(("make_inner", "value"),
                         [c[1:3] for c in CASES], ids=[c[0] for c in CASES])
def test_the_value_read_saves_as_an_envelope_strict_can_read(make_inner,
                                                             value):
    """The in-place backfill's step: read permissively, write back."""
    with altered(make_inner, value) as (Sealed, pk, before):
        with read_mode("permissive"):
            obj = Sealed.objects.get(pk=pk)
            obj.save()
        assert storage_class(Sealed, pk) == "blob"
        with read_mode("strict"):
            assert Sealed.objects.get(pk=pk).v == before


@sqlite_only
@isolate_apps("tests")
def test_text_the_inner_field_cannot_read_is_refused_not_coerced():
    """SQLite's date parser returns None for text that is not a date; that
    is a refusal with the adapter's error, never a NULL or a guessed date."""
    with altered(models.TextField, "not a date",
                 encrypted_inner=models.DateField) as (Sealed, pk, _):
        with read_mode("permissive"), pytest.raises(
                FieldsealNotSupported, match="DateField could not read it"):
            Sealed.objects.get(pk=pk)
        with read_mode("strict"), pytest.raises(NotCiphertext):
            Sealed.objects.get(pk=pk)


@sqlite_only
@isolate_apps("tests")
def test_text_in_a_bytes_column_is_not_base64_decoded():
    """`BinaryField.to_python` would base64-decode a str -- #245's wrong
    value, through a different door. The codec refuses a non-bytes value
    for a `bytes` column instead."""
    with altered(models.TextField, "Zm9v",
                 encrypted_inner=models.BinaryField) as (Sealed, pk, _):
        assert storage_class(Sealed, pk) == "text"
        with read_mode("permissive"), pytest.raises(
                FieldsealNotSupported, match="takes bytes, not str"):
            Sealed.objects.get(pk=pk)


@sqlite_only
@isolate_apps("tests")
def test_a_legacy_value_still_meets_the_reserved_version_rule():
    """The rendered bytes go through the core's recognition like any other
    operand, so spec §3.4's stated cost applies to a legacy value as it does
    to a legacy `bytea`: 111 bytes or more starting with 0x02 is refused in
    every mode, never passed through."""
    with altered(models.TextField, "\x02" + "a" * 120) as (Sealed, pk, _):
        assert storage_class(Sealed, pk) == "text"
        with read_mode("permissive"), pytest.raises(UnknownFormatVersion):
            Sealed.objects.get(pk=pk)


@isolate_apps("tests")
def test_a_bytea_column_only_ever_yields_bytes():
    """The branch #251 added never runs on Postgres: `AlterField` casts the
    text to `bytea`, and the driver returns it as bytes. On SQLite the same
    migration leaves a str, which is what the branch is for."""
    with altered(lambda: models.CharField(max_length=100),
                 "ada@example.com") as (Sealed, pk, before):
        with connection.cursor() as cur:
            cur.execute(f"SELECT v FROM {Sealed._meta.db_table}")
            stored = cur.fetchone()[0]
        if connection.vendor == "sqlite":
            assert type(stored) is str
        else:
            assert isinstance(stored, bytes | memoryview)
        with read_mode("permissive"):
            assert Sealed.objects.get(pk=pk).v == before
