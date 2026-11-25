"""Migration graphs written per test case for the model-less `tests.app252`.

Shared by the #252 and #283 tests: `Case` writes a migration package and runs
real `migrate` commands over it, so a plan goes through `pre_migrate` exactly
as a deployment's does. The `case` fixture that makes them is in
`conftest.py`.
"""

from __future__ import annotations

import contextlib
import itertools
import textwrap

from django.core.management import call_command
from django.db import connection
from django.db.models.signals import pre_migrate

from fieldseal_django.operations import refuse_unsafe_alter_fields

#: Numbers each case's table and package, and any model a test defines.
serial = itertools.count(1)


HEAD = textwrap.dedent("""\
    from django.db import migrations, models
    import fieldseal_django.fields
    import fieldseal_django.operations
    """)


def create(table: str, v: str, *, replaces: str = "",
           extra: str = "") -> str:
    """A `0001`-style migration creating the table, with an unencrypted
    integer column `w` beside `v` for changes that do not touch it. `extra`
    is more fields, as source of `("name", field),` tuples (the #303 tests
    add a second `Encrypted` field and `EncryptedIndex` columns)."""
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
                    EXTRA
                ],
                options={"db_table": TABLE},
            )]
        """).replace("REPLACES", f"replaces = {replaces}" if replaces else "") \
        .replace("V", v).replace("TABLE", repr(table)) \
        .replace("EXTRA", extra)


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
        n = next(serial)
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


def alter(field: str) -> str:
    """An `AlterField` of `Thing.v` to `field`, as migration source."""
    return (f'[migrations.AlterField(model_name="thing", name="v", '
            f'field={field})]')
