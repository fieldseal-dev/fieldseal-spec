"""An `AlterField` that does not change an `Encrypted` column issues no SQL (#283).

Django's schema editor asks `_field_should_be_altered(old, new)` whether an
`AlterField` needs SQL, by comparing the two fields' deconstructed forms with
`non_db_attrs` dropped from the keyword arguments. `Encrypted.deconstruct()`
used to pass the inner field positionally, and two `Field` instances never
compare equal (`Field.__eq__` compares creation order), so two identical
declarations always counted as altered: SQLite rebuilt the whole table, and
PostgreSQL found nothing to emit. #213 made every project with an indexed
encrypted column generate one such `AlterField` on upgrade.

These tests assert that only what changes the column counts, on every
backend; that a migration written with the inner field first still loads and
reads as unchanged to `makemigrations`; and that a rebuild that does happen
keeps each legacy value's SQLite storage class.
"""

from __future__ import annotations

import pytest
from django.db import connection, models
from django.db.migrations.autodetector import MigrationAutodetector
from django.db.migrations.state import ProjectState
from django.db.migrations.writer import MigrationWriter
from django.test.utils import CaptureQueriesContext

from fieldseal_django import BlindIndex, Encrypted

# The migration-package fixture and helpers of the #252 tests.
from .test_convert_to_encrypted import case, mig  # noqa: F401

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.filterwarnings("ignore::fieldseal.errors.FieldsealWarning"),
]

U = "018f3c2e-0000-7000-8000-000000283001"
U2 = "018f3c2e-0000-7000-8000-000000283002"


def _rebuilt(field: models.Field) -> models.Field:
    """`field` as a migration file brings it back: serialized and executed."""
    text, imports = MigrationWriter.serialize(field)
    ns: dict = {}
    exec("\n".join(imports) + "\nfield = " + text, ns)  # noqa: S102
    return ns["field"]


def _altered(old: models.Field, new: models.Field) -> bool:
    for f in (old, new):
        f.set_attributes_from_name("v")
    with connection.schema_editor() as editor:
        return bool(editor._field_should_be_altered(old, new))


def _email(**kw):
    return Encrypted(models.EmailField(), column_uuid=U, **kw)


INDEX = BlindIndex(projected_population=100_000, suite_id=1)

#: Pairs that leave the column as it is: no SQL on any backend.
UNCHANGED = {
    "identical": (_email, _email),
    "identical-with-index": (lambda: _email(index=INDEX),
                             lambda: _email(index=INDEX)),
    "suite-stated": (
        lambda: _email(index=BlindIndex(projected_population=100_000)),
        lambda: _email(index=INDEX)),
    "inner-max-length": (
        lambda: Encrypted(models.CharField(max_length=100), column_uuid=U),
        lambda: Encrypted(models.CharField(max_length=200), column_uuid=U)),
    "inner-type": (
        lambda: Encrypted(models.CharField(max_length=10), column_uuid=U),
        lambda: Encrypted(models.IntegerField(), column_uuid=U)),
    "column-uuid": (_email, lambda: Encrypted(models.EmailField(),
                                              column_uuid=U2)),
    "tenant-bound": (_email, lambda: _email(tenant_bound=False)),
    "unindexable-noun": (_email, lambda: _email(unindexable_noun="email")),
    "verbose-name": (_email, lambda: _email(verbose_name="e-mail")),
}

#: Pairs that change the column: still altered.
CHANGED = {
    "null": (_email, lambda: _email(null=True)),
    "storage": (_email, lambda: _email(storage="base64")),
    "unique": (_email, lambda: _email(unique=True)),
    "db-column": (_email, lambda: _email(db_column="mail")),
    "from-plain": (models.EmailField, _email),
}


@pytest.mark.parametrize("make", list(UNCHANGED.values()),
                         ids=list(UNCHANGED))
def test_a_change_that_leaves_the_column_is_not_altered(make):
    old, new = make
    assert not _altered(old(), new())


@pytest.mark.parametrize("make", list(UNCHANGED.values()),
                         ids=list(UNCHANGED))
def test_through_a_migration_file_too(make):
    """The schema editor compares fields rendered from migration files."""
    old, new = make
    assert not _altered(_rebuilt(old()), _rebuilt(new()))


@pytest.mark.parametrize("make", list(CHANGED.values()), ids=list(CHANGED))
def test_a_change_to_the_column_is_still_altered(make):
    old, new = make
    assert _altered(old(), new())


def test_the_inner_field_is_a_keyword_argument():
    """`non_db_attrs` drops keyword arguments only."""
    _, _, args, kwargs = _email(index=INDEX).deconstruct()
    assert args == []
    assert isinstance(kwargs["inner"], models.EmailField)
    assert kwargs["column_uuid"] == U


def test_a_migration_with_the_inner_field_first_reads_as_unchanged():
    """Every migration written before #283 passes the inner field
    positionally. It must load, and the autodetector, which compares deep
    deconstructions, must see it as the model's field: no new migration."""
    text = ("fieldseal_django.fields.Encrypted(models.EmailField("
            f"max_length=254), column_uuid={U!r}, index=fieldseal_django."
            "declarations.BlindIndex(projected_population=100000, "
            "suite_id=1))")
    ns: dict = {}
    exec("import fieldseal_django.declarations\n"  # noqa: S102
         "import fieldseal_django.fields\n"
         "from django.db import models\n"
         f"field = {text}", ns)
    historical = ns["field"]
    detector = MigrationAutodetector(ProjectState(), ProjectState())
    assert (detector.deep_deconstruct(historical)
            == detector.deep_deconstruct(_email(index=INDEX)))
    assert not _altered(historical, _email(index=INDEX))


# -- real migrations ---------------------------------------------------------


def _field(inner: str, **kw: str) -> str:
    extra = "".join(f", {k}={v}" for k, v in kw.items())
    return (f"fieldseal_django.fields.Encrypted({inner}, "
            f"column_uuid={U!r}{extra})")


def _alter(field: str) -> str:
    return (f'[migrations.AlterField(model_name="thing", name="v", '
            f'field={field})]')


def _ddl(queries: list[dict]) -> list[str]:
    """The statements that touch a table, not the migration recorder's."""
    return [q["sql"] for q in queries
            if q["sql"].lstrip().upper().startswith(
                ("CREATE", "ALTER", "DROP", "INSERT"))
            and "django_migrations" not in q["sql"]]


def test_migrate_issues_no_sql_for_an_unchanged_column(case):  # noqa: F811
    """The issue's shape: an `AlterField` that only states the suite. On
    SQLite it used to remake the table (`CREATE TABLE "new__..."`, `INSERT
    ... SELECT`, `DROP`, `RENAME`)."""
    before = _field("models.CharField(max_length=100)",
                    index="fieldseal_django.declarations.BlindIndex("
                          "projected_population=100000)")
    after = _field("models.CharField(max_length=200)",
                   index="fieldseal_django.declarations.BlindIndex("
                         "projected_population=100000, suite_id=1)")
    c = case(before, _alter(after))
    c.migrate("0001")
    with CaptureQueriesContext(connection) as ctx:
        c.migrate("0002")
    assert "0002_change" in c.applied()
    assert _ddl(ctx.captured_queries) == []


@pytest.mark.skipif(connection.vendor != "sqlite",
                    reason="SQLite storage classes")
def test_a_rebuild_keeps_each_legacy_values_storage_class(case):  # noqa: F811
    """A change that does alter the column still rebuilds the table on
    SQLite. `INSERT ... SELECT` must copy each legacy value in its own
    storage class, which the adapter's legacy read depends on (#251)."""
    c = case(_field("models.CharField(max_length=100)"),
             _alter(_field("models.CharField(max_length=100)",
                           null="True")))
    c.migrate("0001")
    legacy = ["ada@example.com", 42, 1.5, b"\x00\xffbytes"]
    c.insert(*legacy)
    with CaptureQueriesContext(connection) as ctx:
        c.migrate("0002")
    assert any("new__" in sql for sql in _ddl(ctx.captured_queries))
    with connection.cursor() as cur:
        cur.execute(f"SELECT typeof(v), v FROM {c.table} ORDER BY id")
        rows = cur.fetchall()
    assert [t for t, _ in rows] == ["text", "integer", "real", "blob"]
    assert [bytes(v) if isinstance(v, memoryview) else v
            for _, v in rows] == legacy
