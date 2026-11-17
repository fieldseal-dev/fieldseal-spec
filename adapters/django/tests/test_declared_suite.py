"""A blind index is derived under the suite its declaration names (#213).

Spec §7.2: the index context's `suite_id` is the suite the *index* is declared
under, never the client's write suite. For the adapter that means
`BlindIndex(suite_id=...)` is required, has no default, is never taken from
`FIELDSEAL["WRITE_SUITE"]`, and reaches the core's `IndexDeclaration`
untouched. Validating the value stays the core's (AD-1); these tests pin the
adapter's half: it is required, it is passed through, a refusal names the
model field, a supplied client is compared on it (E006), and a migration
carries it.
"""

from __future__ import annotations

import dataclasses
from dataclasses import replace

import pytest
from django.db import connection, models
from django.db.migrations.writer import MigrationWriter
from django.test import override_settings
from django.test.utils import isolate_apps
from fieldseal import FieldContext, index_registry_key

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta
from fieldseal_django.apps import build_index_registry, get_client, reset_client

from .models import (
    COL_EMAIL,
    COL_SUITE_TWO_HANDLE,
    TABLE_PATIENT,
    TABLE_SUITE_TWO,
    Patient,
    SuiteTwoDoc,
)
from .test_checks import _client, ids, run_checks

pytestmark = pytest.mark.django_db

H = bytes.fromhex


def _uuid_bytes(s: str) -> bytes:
    return H(s.replace("-", ""))


# -- 1. required, no default, never the write suite ---------------------------


def test_an_unstated_suite_is_None_and_never_a_suite():
    """The dataclass default is `None`, "not stated", so that a migration
    written before the suite existed still imports (PR #282 review). It is
    not a suite, and nothing completes it: see the E003 tests below."""
    f = next(f for f in dataclasses.fields(BlindIndex) if f.name == "suite_id")
    assert f.default is None
    assert f.kw_only
    assert BlindIndex(projected_population=100_000).suite_id is None


def test_the_suite_is_never_filled_from_the_write_suite():
    """Write suite 0xFF01; the column's index is declared under 0xFF02. The
    registry the adapter builds, and the validated one the client reports,
    both say 0xFF02."""
    assert get_client().write_suite == 0xFF01
    decl = next(d for d in build_index_registry()
                if d.column_uuid == _uuid_bytes(COL_SUITE_TWO_HANDLE))
    assert decl.suite_id == 0xFF02
    key = index_registry_key(_uuid_bytes(TABLE_SUITE_TWO),
                             _uuid_bytes(COL_SUITE_TWO_HANDLE), "exact")
    assert get_client().indexes[key].suite_id == 0xFF02
    # ...and the other columns are 0xFF01 because they say so, not because of
    # the write suite.
    assert {d.suite_id for d in build_index_registry()} == {0xFF01, 0xFF02}


@pytest.mark.parametrize("kwargs", [{}, {"suite_id": None}],
                         ids=["omitted", "explicit-None"])
def test_an_unstated_suite_is_E003_and_names_the_model_field(kwargs):
    with isolate_apps("tests") as apps:
        class NoSuite(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(projected_population=100_000, **kwargs))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        issues = [i for i in run_checks(apps) if i.id == "fieldseal.E003"]
        assert issues, ids(run_checks(apps))
        msg = issues[0].msg
        assert "NoSuite.email" in msg
        assert "suite_id" in msg
        assert "State the suite explicitly" in msg


def test_an_unregistered_suite_is_E003_and_names_the_model_field():
    with isolate_apps("tests") as apps:
        class BadSuite(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(suite_id=0x1234, projected_population=100_000))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        issues = [i for i in run_checks(apps) if i.id == "fieldseal.E003"]
        assert issues, ids(run_checks(apps))
        msg = issues[0].msg
        assert "BadSuite.email" in msg
        assert "0x1234" in msg and "not registered" in msg
        assert "§7.2 declared suite" in issues[0].hint


def test_an_unstated_suite_is_refused_at_first_use_without_the_checks():
    """A project that skips `manage.py check` still fails closed: building
    the client refuses the declaration, naming the model field."""
    from fieldseal_django.apps import index_declarations
    from fieldseal_django.errors import FieldsealConfigurationError

    with isolate_apps("tests") as apps:
        class Unstated(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(projected_population=100_000))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        with pytest.raises(FieldsealConfigurationError,
                           match="Unstated.email declares a BlindIndex with "
                                 "no suite_id"):
            index_declarations(apps)


def test_a_refusal_that_is_not_about_the_suite_does_not_blame_the_suite():
    """The band gate's refusal names the model field and says nothing about
    stating a suite: the declaration already states one (PR #282 review)."""
    with isolate_apps("tests") as apps:
        class WideBand(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(suite_id=0xFF01, truncate_bits=30,
                                 projected_population=100_000))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        issues = [i for i in run_checks(apps) if i.id == "fieldseal.E003"]
        assert issues, ids(run_checks(apps))
        msg = issues[0].msg
        assert "WideBand.email (BlindIndex 'exact')" in msg
        assert "suite" not in msg.lower()


def test_the_registry_builder_does_not_validate():
    """Translation only: an unregistered suite passes through
    `build_index_registry` untouched and is the core's to refuse."""
    with isolate_apps("tests") as apps:
        class BadSuite(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(suite_id=0x1234, projected_population=100_000))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        (decl,) = build_index_registry(apps)
        assert decl.suite_id == 0x1234


def test_a_bool_is_not_a_suite():
    """`True == 1`; the core refuses a flag as a suite id, and the adapter
    passes the value through rather than coercing it."""
    with isolate_apps("tests") as apps:
        class FlagSuite(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(suite_id=True, projected_population=100_000))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert "fieldseal.E003" in ids(run_checks(apps))


# -- 2. E006 compares the declared suite -------------------------------------


def test_a_supplied_client_with_a_different_declared_suite_is_E006():
    """Same parameters, different declared suite: a different index value for
    every row, so a mismatch."""
    decls = build_index_registry()
    swapped = [replace(d, suite_id=0xFF01 if d.suite_id == 0xFF02 else 0xFF02)
               if d.column_uuid == _uuid_bytes(COL_SUITE_TWO_HANDLE) else d
               for d in decls]
    assert swapped != decls
    reset_client()
    with override_settings(FIELDSEAL={"CLIENT": _client(swapped)}):
        issues = [i for i in run_checks() if i.id == "fieldseal.E006"]
    reset_client()
    assert issues
    assert "different resolved parameters" in issues[0].msg
    assert index_registry_key(_uuid_bytes(TABLE_SUITE_TWO),
                              _uuid_bytes(COL_SUITE_TWO_HANDLE),
                              "exact") in issues[0].msg


def test_a_supplied_client_declaring_the_same_suites_passes():
    reset_client()
    with override_settings(FIELDSEAL={"CLIENT": _client(build_index_registry())}):
        assert "fieldseal.E006" not in ids(run_checks())
    reset_client()


# -- 3. a migration carries the declared suite -------------------------------


@pytest.mark.parametrize(("model", "suite"),
                         [(Patient, 0xFF01), (SuiteTwoDoc, 0xFF02)])
def test_a_migration_round_trips_the_declared_suite(model, suite):
    field = next(f for f in model._meta.get_fields()
                 if isinstance(f, Encrypted) and f.index is not None)
    # Through Django's own serializer, as `makemigrations` writes it...
    text, imports = MigrationWriter.serialize(field)
    assert f"suite_id={suite}" in text
    ns: dict = {}
    exec("\n".join(imports) + "\nrebuilt = " + text, ns)  # noqa: S102
    assert ns["rebuilt"].index.suite_id == suite
    assert ns["rebuilt"].index == field.index
    # ...and through `deconstruct()` directly.
    _, _, args, kwargs = field.deconstruct()
    assert kwargs["index"].suite_id == suite
    assert Encrypted(*args, **kwargs).index.suite_id == suite


def test_a_migration_written_before_the_suite_existed_still_loads():
    """A historical migration serializes `BlindIndex(...)` without a suite.
    It must import, or `migrate`, `makemigrations` and `showmigrations` all
    crash while loading the graph, before E003 can explain anything
    (PR #282 review). It loads as "not stated", and is written back as it
    was: nothing invents a suite for it."""
    ns: dict = {}
    exec(  # noqa: S102
        "import fieldseal_django.declarations\n"
        "idx = fieldseal_django.declarations.BlindIndex("
        "projected_population=100000)", ns)
    assert ns["idx"].suite_id is None
    _, _, kwargs = ns["idx"].deconstruct()
    assert "suite_id" not in kwargs


def test_the_suite_is_emitted_even_when_every_other_member_is_default():
    _, _, kwargs = BlindIndex(suite_id=0xFF01,
                              projected_population=100_000).deconstruct()
    assert kwargs["suite_id"] == 0xFF01


# -- 5. end to end through the ORM, under a suite that is not the write suite --


def _stored_index(pk: int) -> bytes:
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT {connection.ops.quote_name('handle_bidx')} "
            f"FROM {connection.ops.quote_name(SuiteTwoDoc._meta.db_table)} "
            "WHERE id = %s", [pk])
        return bytes(cur.fetchone()[0])


def _derive_under(suite_id: int, value: str) -> bytes:
    """What the core derives for `SuiteTwoDoc.handle` under `suite_id`: the
    model's own declaration, otherwise identical, with only the suite varied."""
    decl = next(d for d in build_index_registry()
                if d.column_uuid == _uuid_bytes(COL_SUITE_TWO_HANDLE))
    ctx = FieldContext(table_uuid=decl.table_uuid, column_uuid=decl.column_uuid,
                       purpose="index:exact", tenant_id=None, row_id=None)
    return _client([replace(decl, suite_id=suite_id)]).blind_index(value, ctx)


def test_an_index_declared_under_a_non_write_suite_saves_and_is_found():
    assert get_client().write_suite == 0xFF01
    row = SuiteTwoDoc.objects.create(handle="ada@example.com")
    other = SuiteTwoDoc.objects.create(handle="grace@example.com")

    # Equality finds the row (and, case-folded, the same row).
    assert [r.pk for r in SuiteTwoDoc.objects.filter(
        handle="ada@example.com")] == [row.pk]
    assert [r.pk for r in SuiteTwoDoc.objects.filter(
        handle="ADA@example.com")] == [row.pk]
    assert [r.pk for r in SuiteTwoDoc.objects.filter(
        handle__in=["grace@example.com"])] == [other.pk]
    assert SuiteTwoDoc.objects.get(pk=row.pk).handle == "ada@example.com"

    # The stored bytes are the index derived under the DECLARED suite, and
    # differ from the same value under an otherwise identical 0xFF01 index.
    stored = _stored_index(row.pk)
    assert stored == _derive_under(0xFF02, "ada@example.com")
    assert stored != _derive_under(0xFF01, "ada@example.com")
