"""A `base64` column whose values are legacy plaintext (#245).

A column changed from a plain field to `Encrypted(field, storage="base64")`
is declared `TEXT` and holds whatever the legacy values were. The read ran
the stored text through a non-validating `base64.b64decode` and handed the
decode to the core: `Zm9v` read back as `foo`, other values raised
`FieldsealNotSupported`, and others a raw `binascii.Error` that is not a
`FieldsealError` at all.

The confirmed read (2026-11-04) decodes strictly, decrypts only a decode the
core recognizes as an envelope, and otherwise hands the stored text's UTF-8
to the core. Spec §10.3 then answers with the stored text's own read:
`NOT_CIPHERTEXT` in strict, the text as stored in permissive and readonly,
and one plaintext read counted.

Each test makes the state the way an application does -- a value written
through the ORM into a plain column, then a real `AlterField` -- except where
a storage class no `AlterField` can produce is the point (a BLOB in a TEXT
column).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import itertools

import pytest
from django.conf import settings
from django.db import connection, models
from django.test.utils import isolate_apps, override_settings
from fieldseal.errors import NotCiphertext

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

#: The literals from #245. The first three are valid base64 (and decode to
#: things that are not envelopes); the last two are not base64 at all, so
#: they exercise the strict-decode failure branch. `Zm9v` is the one that
#: silently became `foo`.
LITERALS = ["Zm9v", "abcdabcd", "Anna", "ada@example.com", "Ada Lovelace"]

#: `fmt_ver` 0x02 at the minimum plausible envelope length (spec §3.4): not
#: ciphertext to `is_ciphertext`, but a decode no read may pass back.
RESERVED = base64.b64encode(b"\x02" + b"\x00" * 110).decode("ascii")


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
    table = f"legacy245_{n}"
    Plain = type(f"Plain245{n}", (models.Model,), {
        "__module__": "tests",
        "v": make_inner(),
        "Meta": type("Meta", (), {"db_table": table}),
    })
    Sealed = type(f"Sealed245{n}", (models.Model,), {
        "__module__": "tests",
        "v": Encrypted((encrypted_inner or make_inner)(), storage="base64",
                       null=True,
                       column_uuid=f"018f3c2e-0000-7000-8000-245{n:09d}"),
        "fieldseal": FieldsealMeta(
            table_uuid=f"018f3c2e-0000-7000-8000-246{n:09d}"),
        "Meta": type("Meta", (), {"db_table": table, "managed": False}),
    })
    return Plain, Sealed


@contextlib.contextmanager
def altered(make_inner, value, *, encrypted_inner=None):
    """Write `value` into a plain column, then `AlterField` it to
    `Encrypted(..., storage="base64")`. Yields the encrypted model and pk."""
    Plain, Sealed = _models(make_inner, encrypted_inner=encrypted_inner)
    with connection.schema_editor() as editor:
        editor.create_model(Plain)
    try:
        pk = Plain.objects.create(v=value).pk
        with connection.schema_editor() as editor:
            editor.alter_field(Plain, Plain._meta.get_field("v"),
                               Sealed._meta.get_field("v"), strict=True)
        yield Sealed, pk
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(Plain)


def stored(model, pk):
    with connection.cursor() as cur:
        cur.execute(f"SELECT v FROM {model._meta.db_table} "
                    "WHERE id = %s", [pk])
        return cur.fetchone()[0]


def plant(model, pk, value):
    with connection.cursor() as cur:
        cur.execute(f"UPDATE {model._meta.db_table} SET v = %s "
                    "WHERE id = %s", [value, pk])


@isolate_apps("tests")
@pytest.mark.parametrize("literal", LITERALS)
@pytest.mark.parametrize("mode", ["permissive", "readonly"])
def test_a_pass_through_mode_reads_legacy_text_as_stored(mode, literal):
    with altered(lambda: models.CharField(max_length=100), literal) as (
            Sealed, pk):
        assert stored(Sealed, pk) == literal
        with read_mode(mode) as client:
            assert Sealed.objects.get(pk=pk).v == literal
            assert client.plaintext_reads == 1


@isolate_apps("tests")
@pytest.mark.parametrize("literal", LITERALS)
def test_strict_refuses_legacy_text_with_not_ciphertext(literal):
    with altered(lambda: models.CharField(max_length=100), literal) as (
            Sealed, pk):
        with read_mode("strict"), pytest.raises(NotCiphertext) as excinfo:
            Sealed.objects.get(pk=pk)
        # The old read leaked `binascii.Error` (a `ValueError`) for two of
        # these. It must be the core's typed refusal, never that.
        assert not isinstance(excinfo.value, binascii.Error)


@isolate_apps("tests")
@pytest.mark.parametrize("mode", ["strict", "permissive"])
def test_an_envelope_reads_in_every_mode(mode):
    with altered(lambda: models.CharField(max_length=100), "ada@example.com"
                 ) as (Sealed, pk):
        Sealed.objects.filter(pk=pk).update(v="Ada Lovelace")
        raw = stored(Sealed, pk)
        assert isinstance(raw, str)
        assert get_client().is_ciphertext(
            base64.b64decode(raw, validate=True))
        with read_mode(mode) as client:
            assert Sealed.objects.get(pk=pk).v == "Ada Lovelace"
            assert client.plaintext_reads == 0


@isolate_apps("tests")
def test_a_permissive_read_saved_back_is_an_envelope():
    """The in-place backfill's step: read permissively, write back."""
    with altered(lambda: models.CharField(max_length=100), "ada@example.com"
                 ) as (Sealed, pk):
        with read_mode("permissive"):
            obj = Sealed.objects.get(pk=pk)
            obj.save()
        raw = stored(Sealed, pk)
        assert isinstance(raw, str)
        assert get_client().is_ciphertext(
            base64.b64decode(raw, validate=True))
        with read_mode("strict"):
            assert Sealed.objects.get(pk=pk).v == "ada@example.com"


@isolate_apps("tests")
def test_a_stored_text_whose_decode_is_a_reserved_version_blob_passes():
    """Recognition applies to what is handed to the core (spec §3.4), not to
    an unrecognized decode: the stored text is the operand, so a decode that
    would raise `UNKNOWN_FORMAT_VERSION` is passed over (#245)."""
    with altered(lambda: models.CharField(max_length=200), RESERVED) as (
            Sealed, pk):
        assert stored(Sealed, pk) == RESERVED
        with read_mode("permissive") as client:
            assert Sealed.objects.get(pk=pk).v == RESERVED
            assert client.plaintext_reads == 1
        with read_mode("strict"), pytest.raises(NotCiphertext):
            Sealed.objects.get(pk=pk)


@isolate_apps("tests")
def test_a_bytes_inner_field_reads_the_texts_utf8():
    """`bytes` follows the confirmed rule like every other inner type: the
    stored text's UTF-8 is what permissive passes through, not the decode
    `BinaryField.to_python` would have produced (that was #245's bug)."""
    with altered(models.TextField, "Anna",
                 encrypted_inner=models.BinaryField) as (Sealed, pk):
        with read_mode("permissive") as client:
            assert Sealed.objects.get(pk=pk).v == b"Anna"
            assert client.plaintext_reads == 1


@isolate_apps("tests")
def test_a_non_canonical_int_text_is_refused_and_still_counted():
    """A non-string column reads text only when it is §3.6's canonical
    rendering. A refusal still counts: spec §10.3's metric is the cut-over
    gate, and the core's pass-through counted before the codec refused."""
    with altered(models.IntegerField, 42) as (Sealed, pk):
        with read_mode("permissive"):
            assert Sealed.objects.get(pk=pk).v == 42
        plant(Sealed, pk, "forty-two")
        with read_mode("permissive") as client:
            with pytest.raises(FieldsealNotSupported,
                               match="canonical `int` rendering"):
                Sealed.objects.get(pk=pk)
            assert client.plaintext_reads == 1
        with read_mode("strict"), pytest.raises(NotCiphertext):
            Sealed.objects.get(pk=pk)


@sqlite_only
@isolate_apps("tests")
def test_a_non_text_value_is_refused():
    """SQLite leaves a BLOB in a TEXT column. It is not an envelope whatever
    it holds: strict refuses it unread, permissive counts it and refuses."""
    with altered(models.TextField, "Anna") as (Sealed, pk):
        plant(Sealed, pk, b"\x01\x02")
        with read_mode("strict"), pytest.raises(NotCiphertext):
            Sealed.objects.get(pk=pk)
        with read_mode("permissive") as client:
            with pytest.raises(FieldsealNotSupported, match="#245"):
                Sealed.objects.get(pk=pk)
            assert client.plaintext_reads == 1
