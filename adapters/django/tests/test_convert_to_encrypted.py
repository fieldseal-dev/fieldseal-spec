"""Converting a column into an `Encrypted` `binary` one by migration (#252).

On PostgreSQL a plain `AlterField` from `CharField` to `Encrypted(CharField)`
changes the column to `bytea` with `USING "v"::bytea`, which reads the text
as `bytea` input: `a\\101b` is stored as `aAb`, `\\x41` as `A`, and `C:\\path`
fails the migration. These tests run real `migrate` commands over migration
packages written per case, so the plan goes through `pre_migrate` exactly as
a deployment's does, and assert:

- `ConvertToEncrypted` stores the value's UTF-8 bytes (spec §3.6's `string`
  rendering) on PostgreSQL, whatever the text holds, and undoes it;
- `migrate` refuses a plain `AlterField` that would cast into or out of an
  `Encrypted` `binary` column on PostgreSQL, before any DDL runs;
- the refusal is narrow: a column already `bytea`, and SQLite, are let through.
"""

from __future__ import annotations

import contextlib
import inspect
import itertools
import sys
import textwrap

import pytest
from django.conf import settings
from django.core.management import call_command
from django.db import connection, models
from django.db.migrations.writer import MigrationWriter
from django.db.models.signals import pre_migrate
from django.test.utils import isolate_apps, override_settings

from fieldseal_django import Encrypted, FieldsealMeta, FieldsealNotSupported
from fieldseal_django.apps import get_client, reset_client
from fieldseal_django.operations import (
    ConvertToEncrypted,
    refuse_unsafe_alter_fields,
)

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.filterwarnings("ignore::fieldseal.errors.FieldsealWarning"),
]

postgres_only = pytest.mark.skipif(connection.vendor != "postgresql",
                                   reason="PostgreSQL's ::bytea cast")
sqlite_only = pytest.mark.skipif(connection.vendor != "sqlite",
                                 reason="SQLite's table rebuild")

_serial = itertools.count(1)

#: Legacy text that `::bytea` rewrites or refuses, and two controls. The
#: first four are the issue's table; the `\x` rows its review's.
TEXTS = [
    ("plain", "ada@example.com"),
    ("octal-escape", "a\\101b"),
    ("windows-path", "C:\\path"),
    ("backslash-t", "tab\\tend"),
    ("hex-prefix", "\\x41"),
    ("hex-prefix-word", "\\x666f6f"),
    ("hex-prefix-empty", "\\x"),
    ("hex-prefix-bad", "\\xZZ"),
    ("double-backslash", "\\\\"),
    ("non-ascii", "Zoë ✓ 東京"),
    ("empty", ""),
]

UUID = "018f3c2e-0000-7000-8000-000000252001"


def _encrypted(inner: str, **kw: str) -> str:
    extra = "".join(f", {k}={v}" for k, v in kw.items())
    return (f"fieldseal_django.fields.Encrypted({inner}, "
            f"column_uuid={UUID!r}, null=True{extra})")


HEAD = textwrap.dedent("""\
    from django.db import migrations, models
    import fieldseal_django.fields
    import fieldseal_django.operations
    """)


def create(table: str, v: str, *, replaces: str = "") -> str:
    """A `0001`-style migration creating the table, with an unencrypted
    integer column `w` beside `v` for changes that do not touch it."""
    return textwrap.dedent("""
        class Migration(migrations.Migration):
            initial = True
            dependencies = []
            REPLACES
            operations = [migrations.CreateModel(
                name="Thing",
                fields=[
                    ("id", models.BigAutoField(primary_key=True,
                                               serialize=False)),
                    ("v", V),
                    ("w", models.IntegerField(null=True)),
                ],
                options={"db_table": TABLE},
            )]
        """).replace("REPLACES", f"replaces = {replaces}" if replaces else "") \
        .replace("V", v).replace("TABLE", repr(table))


def mig(deps: list[str], ops: str) -> str:
    """A migration in app252 depending on `deps` and running `ops`."""
    # Dedent the template before interpolating: `ops` may span lines.
    return textwrap.dedent("""
        class Migration(migrations.Migration):
            dependencies = DEPS
            operations = OPS
        """).replace("DEPS", repr([("app252", d) for d in deps])) \
        .replace("OPS", ops)


class Case:
    """A migration package for app252: `0001` creates the table with `old`,
    `0002` runs `change`: Python source of a list of operations, or a
    function from the table name to it. `graph`, a function from the table
    name to {module name: source}, writes any other graph instead."""

    def __init__(self, root, old: str, change, graph=None) -> None:
        n = next(_serial)
        self.table = f"app252_t{n}"
        if graph is None:
            if callable(change):
                change = change(self.table)
            files = {"0001_initial": create(self.table, old),
                     "0002_change": mig(["0001_initial"], change)}
        else:
            files = graph(self.table)
        self.package = f"m252_{n}"
        pkg = root / self.package
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        for name, source in files.items():
            (pkg / f"{name}.py").write_text(HEAD + source)

    def migrate(self, target: str) -> None:
        call_command("migrate", "app252", target, verbosity=0)

    def insert(self, *values: object) -> None:
        with connection.cursor() as cur:
            for v in values:
                cur.execute(f"INSERT INTO {self.table} (v) VALUES (%s)", [v])

    def values(self) -> list[object]:
        with connection.cursor() as cur:
            cur.execute(f"SELECT v FROM {self.table} ORDER BY id")
            rows = [r[0] for r in cur.fetchall()]
        return [bytes(v) if isinstance(v, memoryview) else v for v in rows]

    def column_type(self) -> str:
        with connection.cursor() as cur:
            cur.execute("SELECT data_type FROM information_schema.columns "
                        "WHERE table_name = %s AND column_name = 'v'",
                        [self.table])
            return str(cur.fetchone()[0])

    def applied(self) -> set[str]:
        with connection.cursor() as cur:
            cur.execute("SELECT name FROM django_migrations "
                        "WHERE app = 'app252'")
            return {r[0] for r in cur.fetchall()}


@contextlib.contextmanager
def guard_off():
    pre_migrate.disconnect(dispatch_uid="fieldseal_django.operations.252")
    try:
        yield
    finally:
        pre_migrate.connect(refuse_unsafe_alter_fields,
                            dispatch_uid="fieldseal_django.operations.252")


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(tmp_path))
    made: list[Case] = []
    stack = contextlib.ExitStack()

    def make(old: str = "", change="", graph=None) -> Case:
        c = Case(tmp_path, old, change, graph)
        made.append(c)
        stack.enter_context(
            override_settings(MIGRATION_MODULES={"app252": c.package}))
        return c

    try:
        yield make
    finally:
        try:
            for c in made:
                # Unapplying may cross a plain AlterField a test applied with
                # the guard off; the guard has been asserted by then.
                with guard_off():
                    c.migrate("zero")
        finally:
            # A squashed migration's own row outlives `migrate zero`.
            with connection.cursor() as cur:
                cur.execute("DELETE FROM django_migrations "
                            "WHERE app = 'app252'")
            stack.close()
            for name in list(sys.modules):
                if name.startswith("m252_"):
                    del sys.modules[name]


def _convert(field: str) -> str:
    return (f'[fieldseal_django.operations.ConvertToEncrypted('
            f'model_name="thing", name="v", field={field})]')


def _alter(field: str) -> str:
    return (f'[migrations.AlterField(model_name="thing", name="v", '
            f'field={field})]')


CHAR = "models.CharField(max_length=100, null=True, db_index=True)"


# -- ConvertToEncrypted -------------------------------------------------------


@postgres_only
@pytest.mark.parametrize("text", [t for _, t in TEXTS],
                         ids=[i for i, _ in TEXTS])
def test_convert_stores_the_values_utf8_bytes_and_undoes_it(case, text):
    c = case(CHAR, _convert(_encrypted("models.CharField(max_length=100)")))
    c.migrate("0001")
    c.insert(text, None)

    c.migrate("0002")
    assert c.column_type() == "bytea"
    assert c.values() == [text.encode("utf-8"), None]

    c.migrate("0001")
    assert c.column_type() == "character varying"
    assert c.values() == [text, None]


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


@postgres_only
@isolate_apps("tests")
@pytest.mark.parametrize("text", [t for _, t in TEXTS],
                         ids=[i for i, _ in TEXTS])
def test_after_convert_a_permissive_read_returns_the_legacy_text(case, text):
    """What the in-place backfill reads (`PROCEDURE.md` §6.3 rule 1) is the
    value as it was, not what `::bytea` would have made of it."""
    c = case(CHAR, _convert(_encrypted("models.CharField(max_length=100)")))
    c.migrate("0001")
    c.insert(text)
    c.migrate("0002")
    n = next(_serial)
    Sealed = type(f"Sealed252_{n}", (models.Model,), {
        "__module__": "tests",
        "v": Encrypted(models.CharField(max_length=100), column_uuid=UUID,
                       null=True),
        "fieldseal": FieldsealMeta(
            table_uuid="018f3c2e-0000-7000-8000-000000252002"),
        "Meta": type("Meta", (), {"db_table": c.table, "managed": False}),
    })
    with read_mode("permissive"):
        assert Sealed.objects.get().v == text


@postgres_only
def test_convert_reads_a_text_column_too(case):
    c = case("models.TextField(null=True)",
             _convert(_encrypted("models.TextField()")))
    c.migrate("0001")
    c.insert("a\\101b\n\\x41")
    c.migrate("0002")
    assert c.values() == [b"a\\101b\n\\x41"]


@sqlite_only
@pytest.mark.parametrize("text", [t for _, t in TEXTS],
                         ids=[i for i, _ in TEXTS])
def test_convert_on_sqlite_is_a_plain_alter_field(case, text):
    c = case(CHAR, _convert(_encrypted("models.CharField(max_length=100)")))
    c.migrate("0001")
    c.insert(text)
    c.migrate("0002")
    # The rebuild keeps the value in its storage class (#251), so the
    # adapter's legacy read sees exactly the text.
    assert c.values() == [text]
    c.migrate("0001")
    assert c.values() == [text]


@postgres_only
@pytest.mark.parametrize(("old", "inner", "value"), [
    ("models.IntegerField(null=True)", "models.IntegerField()", 825373492),
    ("models.DateField(null=True)", "models.DateField()", "2026-10-05"),
    ("models.DecimalField(max_digits=10, decimal_places=2, null=True)",
     "models.DecimalField(max_digits=10, decimal_places=2)", "1.50"),
], ids=["int", "date", "decimal"])
def test_convert_refuses_a_non_string_column_on_postgres(case, old, inner,
                                                        value):
    c = case(old, _convert(_encrypted(inner)))
    c.migrate("0001")
    c.insert(value)
    before = c.values()
    with pytest.raises(FieldsealNotSupported, match="two-column shape"):
        c.migrate("0002")
    assert c.values() == before
    assert "0002_change" not in c.applied()


def test_convert_refuses_two_encrypted_declarations(case):
    c = case(_encrypted("models.CharField(max_length=100)"),
             _convert(_encrypted("models.CharField(max_length=100)",
                                 storage='"base64"')))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="one side must be"):
        c.migrate("0002")


def test_convert_serializes_under_its_own_import():
    op = ConvertToEncrypted(model_name="thing", name="v", field=None)
    text, imports = MigrationWriter.serialize(op)
    assert text.startswith("fieldseal_django.operations.ConvertToEncrypted(")
    assert "import fieldseal_django.operations" in imports


@postgres_only
def test_the_private_schema_editor_method_it_replaces_is_still_there():
    """`ConvertToEncrypted` sets the conversion through `_using_sql`; a Django
    that renames it or changes its arguments must fail here first."""
    from django.db.backends.postgresql.schema import DatabaseSchemaEditor

    params = list(inspect.signature(DatabaseSchemaEditor._using_sql)
                  .parameters)
    assert params == ["self", "new_field", "old_field"]


# -- the migrate-time refusal -------------------------------------------------


@postgres_only
def test_migrate_refuses_a_plain_alter_field_into_bytea_before_any_ddl(case):
    c = case(CHAR, _alter(_encrypted("models.CharField(max_length=100)")))
    c.migrate("0001")
    c.insert("a\\101b")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    msg = str(e.value)
    assert "ConvertToEncrypted" in msg
    assert "app252.0002_change" in msg
    assert c.column_type() == "character varying"
    assert c.values() == ["a\\101b"]
    assert "0002_change" not in c.applied()


@postgres_only
def test_migrate_refusal_for_a_non_string_column_names_two_columns(case):
    c = case("models.IntegerField(null=True)",
             _alter(_encrypted("models.IntegerField()")))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported) as e:
        c.migrate("0002")
    assert "two-column shape" in str(e.value)
    assert "ConvertToEncrypted" not in str(e.value)


@postgres_only
def test_migrate_refuses_base64_to_binary(case):
    c = case(_encrypted("models.CharField(max_length=100)",
                        storage='"base64"'),
             _alter(_encrypted("models.CharField(max_length=100)")))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="two-column shape"):
        c.migrate("0002")


@postgres_only
def test_migrate_refuses_the_plain_alter_field_out_of_bytea(case):
    c = case(_encrypted("models.CharField(max_length=100)"), _alter(CHAR))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="ConvertToEncrypted"):
        c.migrate("0002")


@postgres_only
def test_migrate_refuses_unapplying_a_plain_alter_field(case):
    c = case(CHAR, _alter(_encrypted("models.CharField(max_length=100)")))
    with guard_off():
        c.migrate("0002")
    with pytest.raises(FieldsealNotSupported, match="ConvertToEncrypted"):
        c.migrate("0001")
    assert c.column_type() == "bytea"


@postgres_only
def test_migrate_looks_inside_separate_database_and_state(case):
    field = _encrypted("models.CharField(max_length=100)")
    c = case(CHAR, textwrap.dedent(f"""[migrations.SeparateDatabaseAndState(
        database_operations={_alter(field)},
        state_operations={_alter(field)},
    )]"""))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported, match="ConvertToEncrypted"):
        c.migrate("0002")


@postgres_only
def test_migrate_lets_a_bytea_column_through(case):
    c = case("models.BinaryField(null=True)",
             _alter(_encrypted("models.BinaryField()")))
    c.migrate("0001")
    c.insert(b"\\x41")
    c.migrate("0002")
    assert c.values() == [b"\\x41"]


@postgres_only
def test_migrate_lets_a_raw_sql_conversion_through(case):
    """`SeparateDatabaseAndState` with the operator's own SQL is a statement
    that they converted the column; the refusal is about Django's cast."""
    field = _encrypted("models.CharField(max_length=100)")
    def change(table: str) -> str:
        sql = (f"ALTER TABLE {table} ALTER COLUMN v TYPE bytea "
               "USING convert_to(v, 'UTF8')")
        back = (f"ALTER TABLE {table} ALTER COLUMN v TYPE varchar(100) "
                "USING convert_from(v, 'UTF8')")
        return textwrap.dedent(f"""[migrations.SeparateDatabaseAndState(
            database_operations=[migrations.RunSQL({sql!r}, {back!r})],
            state_operations={_alter(field)},
        )]""")

    c = case("models.CharField(max_length=100, null=True)", change)
    c.migrate("0001")
    c.insert("a\\101b")
    c.migrate("0002")
    assert c.values() == [b"a\\101b"]


@sqlite_only
def test_sqlite_is_not_refused(case):
    c = case(CHAR, _alter(_encrypted("models.CharField(max_length=100)")))
    c.migrate("0001")
    c.insert("a\\101b")
    c.migrate("0002")
    assert c.values() == ["a\\101b"]


@postgres_only
def test_migrate_fake_is_refused_too(case):
    """`pre_migrate` does not say the run is fake, so the receiver cannot
    tell; `docs/12` §7 states this cost and the `SeparateDatabaseAndState`
    route around it."""
    c = case(CHAR, _alter(_encrypted("models.CharField(max_length=100)")))
    c.migrate("0001")
    with pytest.raises(FieldsealNotSupported):
        call_command("migrate", "app252", "0002", fake=True, verbosity=0)
    assert "0002_change" not in c.applied()


# -- the review of the first cut (PR review, 2026-11-18) ----------------------


@postgres_only
def test_migrate_refuses_a_bytea_column_into_base64(case):
    """Neither side is `binary`, but `bytea::text` writes hex: `AB` would be
    stored as `\\x4142` and read back as those six characters' bytes."""
    c = case("models.BinaryField(null=True)",
             _alter(_encrypted("models.BinaryField()", storage='"base64"')))
    c.migrate("0001")
    c.insert(b"AB")
    with pytest.raises(FieldsealNotSupported, match="two-column shape"):
        c.migrate("0002")
    assert c.values() == [b"AB"]


@postgres_only
def test_migrate_refuses_a_fresh_plan_through_the_state_it_builds(case):
    """From an empty database the plan creates the table and alters it, so
    the receiver must advance its state through `0001` and through each
    operation of `0002` to see the column as `varchar` when the cast runs.
    This is also the stated cost: a historical plain `AlterField` is refused
    on a fresh database, test databases included."""
    enc = _encrypted("models.CharField(max_length=100)")
    c = case(CHAR, "[" + _alter("models.CharField(max_length=50, null=True)")
             [1:-1] + ", " + _alter(enc)[1:-1] + "]")
    with pytest.raises(FieldsealNotSupported, match="ConvertToEncrypted"):
        c.migrate("0002")
    assert c.applied() == set()


@postgres_only
def test_rolling_back_to_a_migration_a_squash_replaced(case):
    """`migrate` plans a rollback to a replaced migration over a graph
    without replacements, so the plan names migrations the receiver's own
    graph does not hold. It must load the graph the plan came from: looking
    the plan up in the squashed graph finds nothing to check (or, through
    `project_state`, raises `NodeNotFoundError`). `0003_out` casts the
    converted column back out of `bytea`, so unapplying it casts varchar
    into `bytea` with ::bytea."""
    enc = _encrypted("models.CharField(max_length=100)")
    c = case(graph=lambda t: {
        "0001_initial": create(t, CHAR),
        "0002_convert": mig(["0001_initial"], _convert(enc)),
        "0003_out": mig(["0002_convert"], _alter(CHAR)),
        "0001_squashed_0003": create(
            t, CHAR, replaces="[('app252', '0001_initial'), "
            "('app252', '0002_convert'), ('app252', '0003_out')]"),
    })
    # Applying the squash records the three it replaces (no AlterField
    # runs). Django 5.2 cannot plan forwards to a replaced migration, so the
    # replaced ones are not applied one by one here.
    c.migrate("0001_squashed_0003")
    assert {"0001_initial", "0002_convert", "0003_out"} <= c.applied()
    c.insert("a\\101b")
    with pytest.raises(FieldsealNotSupported, match="0003_out"):
        c.migrate("0002_convert")
    assert c.values() == ["a\\101b"]


@postgres_only
def test_rolling_back_a_merged_branch_is_refused(case):
    """Django runs the branches as `0002_b` then `0002_a` (the full plan's
    order), and unapplies `0002_a` against the state that includes
    `0002_b`'s conversion: its `AlterField` then casts varchar(200) into the
    encrypted column's `bytea`. A walk over `0002_a`'s own ancestors would
    see two `CharField`s and let it run."""
    enc = _encrypted("models.CharField(max_length=100)")
    c = case(graph=lambda t: {
        "0001_initial": create(t, CHAR),
        "0002_a": mig(["0001_initial"],
                      _alter("models.CharField(max_length=200, null=True)")),
        "0002_b": mig(["0001_initial"], _convert(enc)),
        "0003_merge": mig(["0002_a", "0002_b"], "[]"),
    })
    # Forwards, `0002_a` casts the converted column back out of `bytea`.
    with pytest.raises(FieldsealNotSupported, match="0002_a"):
        c.migrate("0003_merge")
    # Applied anyway, as by a release without the receiver.
    with guard_off():
        c.migrate("0003_merge")
    assert c.column_type() == "character varying"
    c.insert("a\\101b")
    with pytest.raises(FieldsealNotSupported, match="0002_a"):
        c.migrate("0001_initial")
    assert c.values() == ["a\\101b"]
    # `migrate zero` would unapply the branches in the other order, against
    # a column Django's states do not describe; leave through `0001`.
    with guard_off():
        c.migrate("0001_initial")


class _ModelHintRouter:
    """Routes app252 away from every database through the `model` hint,
    the way Django documents routers deciding by model."""

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        model = hints.get("model")
        if model is not None and model._meta.app_label == "app252":
            return False
        return None


@postgres_only
def test_a_model_routed_away_is_not_refused(case):
    c = case(CHAR, _alter(_encrypted("models.CharField(max_length=100)")))
    with override_settings(DATABASE_ROUTERS=[_ModelHintRouter()]):
        c.migrate("0002")
        assert c.applied() == {"0001_initial", "0002_change"}
        # The router kept the table off this database, so leaving must too.
        c.migrate("zero")


def test_squashing_keeps_the_conversion():
    """A conversion followed by another change to the encrypted declaration
    must not reduce to one plain `AlterField` from the plain field."""
    from django.db import models as m
    from django.db.migrations.operations import AlterField
    from django.db.migrations.optimizer import MigrationOptimizer

    first = Encrypted(m.CharField(max_length=100), column_uuid=UUID)
    second = Encrypted(m.CharField(max_length=200), column_uuid=UUID)
    ops = [ConvertToEncrypted(model_name="thing", name="v", field=first),
           AlterField(model_name="thing", name="v", field=second)]
    out = MigrationOptimizer().optimize(ops, "app252")
    assert [type(o) for o in out] == [ConvertToEncrypted, AlterField]
