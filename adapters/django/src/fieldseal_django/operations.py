"""Changing a column into an `Encrypted(..., storage="binary")` one (#252).

**What goes wrong without this module.** A migration's plain `AlterField` from
`CharField(...)` to `Encrypted(CharField(...))` changes the column type to
`bytea` on PostgreSQL, and Django's schema editor converts the rows with
`USING "col"::bytea` (`_using_sql` in `django/db/backends/postgresql/
schema.py`) whenever the two fields' data types differ. That cast reads the
text as `bytea` *input*, not as characters:

- a backslash escape is decoded (`a\\101b` is stored as `aAb`), and a leading
  `\\x` is read as hex (`\\x41` is stored as `A`), with no error. The adapter's
  permissive read then returns the rewritten value as if it were the legacy
  one, and the in-place backfill encrypts it and indexes it;
- any other backslash (`C:\\path`) fails the migration;
- on PostgreSQL 18 an integer becomes its big-endian bytes, and an integer
  whose bytes are ASCII digits reads back as a different integer with no
  error (825373492 is stored as `1234`); every other non-string type has no
  cast and fails.

Measured on PostgreSQL 17.11 and 18.6 (#252). Nothing the field can do stops
it: `_using_sql` consults only the two fields' data types, so the field has no
way to supply its own `USING` expression.

**What this module adds.**

- `ConvertToEncrypted`, an `AlterField` whose state change is identical and
  whose SQL is right: on PostgreSQL it converts a string column with
  `convert_to(col, 'UTF8')`, which is exactly spec §3.6's `string` rendering,
  and refuses every other inner type; on SQLite it is a plain `AlterField`,
  whose table rebuild keeps each value's storage class and whose legacy values
  the field already reads (#251).
- `refuse_unsafe_alter_fields`, a `pre_migrate` receiver. Before `migrate`
  runs any DDL it walks the plan with the states Django's executor will use,
  and on PostgreSQL it refuses a plain `AlterField` that would cast a column
  between `bytea` and another type with an `Encrypted` field on either side;
  on every backend it refuses a `ConvertToEncrypted` that would refuse when
  it runs. Spec §10.2:
  where a path would silently return wrong results, the adapter MUST throw.
  `makemigrations` writes the plain `AlterField`, so without the receiver
  the default path is the corrupting one.

Neither runs any cryptography: the conversion is the database's own text
encoding, and the backfill (`tools/backfill/PROCEDURE.md`) does the
encrypting afterwards.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterator
from typing import Any

from django.db import connections
from django.db.migrations.operations import (
    AlterField,
    RenameField,
    SeparateDatabaseAndState,
)
from django.db.models import NOT_PROVIDED

from .codec import logical_type
from .errors import FieldsealNotSupported

_ISSUE = "https://github.com/fieldseal-dev/fieldseal-spec/issues/252"

#: The PostgreSQL column types `convert_to` reads as characters: what
#: Django's `CharField` family (`varchar(n)`, or `varchar` with no length)
#: and `TextField` (`text`) create.
_PG_TEXT_TYPE = re.compile(r"^(varchar(\(\d+\))?|text)$")


def _encrypted_binary(field: Any) -> bool:
    from .fields import Encrypted

    return isinstance(field, Encrypted) and field.storage == "binary"


def _is_encrypted(field: Any) -> bool:
    from .fields import Encrypted

    return isinstance(field, Encrypted)


def casts_into_or_out_of_bytea(old: Any, new: Any, connection: Any) -> bool:
    """Whether a plain `AlterField` from `old` to `new` would run Django's
    cast between `bytea` and another type, with an `Encrypted` field on
    either side.

    Symmetric on purpose: the same pair is the backwards direction of the
    reverse migration. And not limited to a `binary` field: `bytea::text`
    writes `\\x…` hex text, so a `BinaryField` changed into
    `Encrypted(BinaryField(), storage="base64")` stores `\\x4142` for `AB`,
    which is no more the value than `aAb` is.
    """
    if not (_is_encrypted(old) or _is_encrypted(new)):
        return False
    old_type, new_type = old.db_type(connection), new.db_type(connection)
    bytea = connection.data_types["BinaryField"]
    return bool(old_type != new_type and bytea in (old_type, new_type))


class ConvertToEncrypted(AlterField):  # type: ignore[misc]
    """An `AlterField` into, or back out of, `Encrypted(..., storage="binary")`
    that converts the rows as text rather than as `bytea` input (#252).

    Use it in place of the `AlterField` `makemigrations` writes, with the same
    arguments::

        from fieldseal_django.operations import ConvertToEncrypted

        operations = [
            ConvertToEncrypted(
                model_name="patient",
                name="email",
                field=fieldseal_django.fields.Encrypted(
                    models.EmailField(max_length=254), column_uuid="…"),
            ),
        ]

    **What it does, by backend.**

    - **PostgreSQL**, a `CharField` or `TextField` (or subclass) inner field
      over a `varchar` or `text` column: the column becomes `bytea` with
      `USING convert_to(col, 'UTF8')`, which yields the value's UTF-8 bytes,
      spec §3.6's `string` rendering, whatever the text holds. Backwards,
      `convert_from(col, 'UTF8')` restores the text, and fails loudly on a
      value that is not UTF-8 -- which an envelope is likely to be, so
      backwards is for a column nothing has written to through the field
      yet: one `save()` after the conversion stores an envelope, and the
      rollback then fails and leaves the column `bytea`. Any other
      inner type is refused: PostgreSQL's text form of a date, a timestamp or
      a numeric is not §3.6's rendering, and no cast from an integer is. Use
      the two-column shape for those (`docs/12` §7).
    - **SQLite**: a plain `AlterField`. The table rebuild copies each value in
      its old storage class, and the field reads those (#251).
    - **Any other backend**: refused, because nothing about it is measured.

    A column that is `bytea` on both sides (a `BinaryField` changed into
    `Encrypted(BinaryField())`) needs no conversion and gets a plain
    `AlterField` everywhere.

    **Private API.** The conversion replaces the schema editor's
    `_using_sql` for the one field being altered, because that method is
    where Django decides the `USING` clause and it takes nothing from the
    field. Everything else `alter_field` does -- dropping a `CharField`'s
    `_like` index before the type change, the nullability, the defaults --
    stays Django's. `tests/test_convert_to_encrypted.py` pins the method's
    shape, so a Django release that renames it fails there rather than here.
    An installed Django is not this repository's CI, so the operation also
    checks at run time: it refuses when the method is gone, and when
    `alter_field` returns without having consulted the replacement for the
    field -- a Django that still has the method but no longer calls it, whose
    `::bytea` cast would then have run. That refusal is raised inside the
    migration's transaction, so on PostgreSQL the `ALTER` rolls back with it
    (unless the migration sets `atomic = False`).
    """

    def describe(self) -> str:
        return (f"Convert field {self.name} on {self.model_name} to or from "
                "Encrypted (binary), as text")

    def reduce(self, operation: Any, app_label: str) -> Any:
        """Never merge with a later `AlterField` of the same field.

        `AlterField.reduce` would replace this operation with the later one,
        so squashing a conversion followed by any change to the encrypted
        declaration would leave a plain `AlterField` from the plain field:
        the cast this operation exists to avoid (refused on PostgreSQL at
        `migrate`, but the squash would be unusable there). Returning False
        tells the optimizer it cannot reduce across the pair.

        A later `RenameField` of the same field is moved ahead of the
        conversion, as `AlterField.reduce` does, but the conversion keeps its
        class: Django 5.2 rebuilds it as a hard-coded `AlterField(...)`, which
        would leave the same plain `AlterField` (6.1 keeps the subclass).
        """
        if (isinstance(operation, AlterField)
                and self.is_same_field_operation(operation)):
            return False
        if (isinstance(operation, RenameField)
                and self.is_same_field_operation(operation)
                and self.field.db_column is None):
            return [operation, ConvertToEncrypted(
                model_name=self.model_name, name=operation.new_name,
                field=self.field, preserve_default=self.preserve_default)]
        return super().reduce(operation, app_label)

    def database_forwards(self, app_label: str, schema_editor: Any,
                          from_state: Any, to_state: Any) -> None:
        to_model = to_state.apps.get_model(app_label, self.model_name)
        if not self.allow_migrate_model(schema_editor.connection.alias,
                                        to_model):
            return
        from_model = from_state.apps.get_model(app_label, self.model_name)
        from_field = from_model._meta.get_field(self.name)
        to_field = to_model._meta.get_field(self.name)
        using = self._using_expression(app_label, from_field, to_field,
                                       schema_editor.connection)
        if not self.preserve_default:
            to_field.default = self.field.default
        try:
            with _using_sql(schema_editor, to_field, using):
                schema_editor.alter_field(from_model, from_field, to_field)
        finally:
            if not self.preserve_default:
                to_field.default = NOT_PROVIDED

    def database_backwards(self, app_label: str, schema_editor: Any,
                           from_state: Any, to_state: Any) -> None:
        self.database_forwards(app_label, schema_editor, from_state, to_state)

    def _refuse_declaration(self, app_label: str, old: Any, new: Any) -> None:
        """Raise if `old` to `new` is not a conversion this operation is for,
        on any backend: these mean the migration itself is wrong, which is
        true under `--fake` as well."""
        where = f"{app_label}.{self.model_name}.{self.name}"
        if _is_encrypted(old) == _is_encrypted(new):
            raise FieldsealNotSupported(
                f"ConvertToEncrypted on {where}: one side must be a plain "
                "field and the other Encrypted(..., storage=\"binary\"). For "
                "a change between two Encrypted declarations use AlterField; "
                "for a change between storage formats there is no in-place "
                "route, so use the two-column shape (docs/12 §7).")
        sealed = new if _is_encrypted(new) else old
        if sealed.storage != "binary":
            raise FieldsealNotSupported(
                f"ConvertToEncrypted on {where}: it converts into and out of "
                "storage=\"binary\" only. From a text column a plain "
                "AlterField into a base64 column leaves the legacy text as "
                "it is; from a bytea column there is no in-place route, so "
                "use the two-column shape (docs/12 §7).")

    def _using_expression(self, app_label: str, old: Any, new: Any,
                          connection: Any) -> str | None:
        """The `USING` expression for `old` to `new`, or None for Django's
        own; raises for a pair this operation has no correct conversion for.
        """
        where = f"{app_label}.{self.model_name}.{self.name}"
        self._refuse_declaration(app_label, old, new)
        sealed, plain = (new, old) if _is_encrypted(new) else (old, new)
        if old.db_type(connection) == new.db_type(connection):
            return None
        if connection.vendor == "sqlite":
            return None
        if connection.vendor != "postgresql":
            raise FieldsealNotSupported(
                f"ConvertToEncrypted on {where}: the {connection.vendor} "
                "backend is not measured, so this operation does not claim a "
                "conversion for it. Use the two-column shape (docs/12 §7).")
        inner_type = logical_type(sealed.inner)
        plain_type = plain.db_type(connection)
        if inner_type != "string" or not _PG_TEXT_TYPE.match(plain_type or ""):
            raise FieldsealNotSupported(
                f"ConvertToEncrypted on {where}: on PostgreSQL it converts "
                "a varchar or text column holding a string (a CharField or "
                "TextField inner field) only, and this one is "
                f"{plain_type} holding §3.6 {inner_type}. PostgreSQL's text "
                "form of a date, a timestamp or a number is not spec §3.6's "
                "rendering, so there is no in-place route for it: use the "
                f"two-column shape (docs/12 §7; {_ISSUE}).")
        if new is sealed:
            return "convert_to(%(column)s, 'UTF8')"
        return "convert_from(%(column)s, 'UTF8')"


@contextlib.contextmanager
def _using_sql(schema_editor: Any, field: Any,
               expression: str | None) -> Iterator[None]:
    """Make `schema_editor` convert `field`'s column with `expression`."""
    if expression is None:
        yield
        return
    original = getattr(schema_editor, "_using_sql", None)
    if original is None:
        raise FieldsealNotSupported(
            "ConvertToEncrypted: this Django's PostgreSQL schema editor has "
            "no _using_sql, which is where the operation sets the "
            "conversion. Refusing rather than letting Django's ::bytea cast "
            f"run ({_ISSUE}).")

    consulted = False

    def using_sql(new_field: Any, old_field: Any) -> str:
        nonlocal consulted
        if new_field is field:
            consulted = True
            return f" USING {expression}"
        return str(original(new_field, old_field))

    schema_editor._using_sql = using_sql
    try:
        yield
    finally:
        del schema_editor._using_sql
    if not consulted:
        # Reached only when `alter_field` returned normally. The type change
        # ran without the conversion, so with Django's own cast: #252. The
        # migration's transaction rolls the ALTER back with this raise.
        raise FieldsealNotSupported(
            "ConvertToEncrypted: this Django's PostgreSQL schema editor did "
            "not consult _using_sql while altering the column, so the "
            "conversion was not applied and Django's own cast ran instead. "
            "Refusing; in an atomic migration the change is rolled back "
            f"({_ISSUE}).")


# -- the migrate-time refusal ------------------------------------------------

#: The plan last checked. `pre_migrate` is sent once per installed app with a
#: models module, each time with the same plan list, and one walk is enough.
_last_plan: list[Any] | None = None


def refuse_unsafe_alter_fields(sender: Any, *, using: str = "default",
                               plan: list[Any] | None = None,
                               **kwargs: Any) -> None:
    """`pre_migrate` receiver: refuse the plan before any DDL runs if a plain
    `AlterField` in it would cast an `Encrypted` column into or out of
    `bytea` on PostgreSQL, or a `ConvertToEncrypted` in it would refuse when
    it ran, on any backend (#252)."""
    global _last_plan
    if not plan or plan is _last_plan:
        return
    _last_plan = plan
    connection = connections[using]
    # The one place the backend decides what is checked: on PostgreSQL every
    # `AlterField`, `ConvertToEncrypted` included; elsewhere a plain
    # `AlterField` casts nothing, so only conversions are worth the walk.
    checked = (AlterField if connection.vendor == "postgresql"
               else ConvertToEncrypted)
    if not any(_has_operation(m.operations, checked) for m, _ in plan):
        return
    for problem in _unsafe_alter_fields(plan, connection, checked):
        raise FieldsealNotSupported(problem)


def _has_operation(operations: list[Any], checked: type) -> bool:
    for op in operations:
        if isinstance(op, SeparateDatabaseAndState):
            if _has_operation(op.database_operations, checked):
                return True
        elif isinstance(op, checked):
            return True
    return False


def _unsafe_alter_fields(plan: list[Any], connection: Any,
                         checked: type) -> Iterator[str]:
    """Walk `plan` with the states Django's executor will give each
    migration, and describe each unsafe `AlterField` in it."""
    from django.db.migrations.executor import MigrationExecutor
    from django.db.migrations.state import ProjectState

    executor = MigrationExecutor(connection)
    loader = executor.loader
    if any((m.app_label, m.name) not in loader.graph.nodes for m, _ in plan):
        # `migration_plan` rebuilds its graph without replacements when the
        # target is a migration a squash replaced, so the plan names the
        # replaced migrations; build ours the same way.
        loader.replace_migrations = False
        loader.build_graph()
    full_plan = executor.migration_plan(loader.graph.leaf_nodes(),
                                        clean_start=True)
    applied = {loader.graph.nodes[key] for key in loader.applied_migrations
               if key in loader.graph.nodes}
    to_run = {m for m, _ in plan}
    state = ProjectState(real_apps=loader.unmigrated_apps)
    if plan[0][1]:
        # As `_migrate_all_backwards`: each migration is unapplied against
        # the state before it in `full_plan` order, built from every applied
        # migration ahead of it, including those on other branches.
        for migration, _ in full_plan:
            if not to_run:
                break
            if migration in to_run:
                before = state
                state = migration.mutate_state(state, preserve=True)
                to_run.remove(migration)
                yield from _scan(migration, migration.operations, before,
                                 connection, checked)
            elif migration in applied:
                migration.mutate_state(state, preserve=False)
        return
    # As `_create_project_state(with_applied_migrations=True)` and then
    # `_migrate_all_forwards`: every applied migration, then the plan's in
    # `full_plan` order, each advancing the state the next one starts from.
    for migration, _ in full_plan:
        if migration in applied:
            migration.mutate_state(state, preserve=False)
    for migration, _ in full_plan:
        if not to_run:
            break
        if migration in to_run:
            to_run.remove(migration)
            yield from _scan(migration, migration.operations, state,
                             connection, checked)


def _scan(migration: Any, operations: list[Any], state: Any,
          connection: Any, checked: type) -> Iterator[str]:
    """Check each operation against `state`, advancing it as Django does."""
    app_label = migration.app_label
    for op in operations:
        if isinstance(op, SeparateDatabaseAndState):
            # The database operations run against a copy of the state, and
            # only the state operations move the real one.
            yield from _scan(migration, op.database_operations,
                             state.clone(), connection, checked)
            for state_op in op.state_operations:
                state_op.state_forwards(app_label, state)
            continue
        problem = None
        if isinstance(op, ConvertToEncrypted):
            problem = _check_conversion(migration, op, state, connection)
        elif isinstance(op, checked):
            problem = _check(migration, op, state, connection)
        if problem:
            yield problem
        op.state_forwards(app_label, state)


def _allowed(op: AlterField, app_label: str, state: Any,
             connection: Any) -> bool:
    """As `AlterField.database_forwards`: a model Django would not migrate on
    this database (unmanaged, proxy, swapped, another vendor, or routed away,
    with the `model` hint routers receive) gets no DDL. Rendering is the
    expensive part, so callers ask only for an operation they would refuse.
    """
    model = state.clone().apps.get_model(app_label, op.model_name)
    return bool(op.allow_migrate_model(connection.alias, model))


def _check_conversion(migration: Any, op: ConvertToEncrypted, state: Any,
                      connection: Any) -> str | None:
    """The refusal `op` would raise when it ran, raised before the plan
    starts instead, so no earlier migration in it has committed.

    Checked forwards only: the refusals do not depend on the direction,
    and backwards swaps the two fields. On a backend that is not measured
    only the declaration's refusals are raised here; the backend's own one
    stays where it was, when the operation runs, so `migrate --fake` can
    still record a column an operator converted by hand there."""
    app_label = migration.app_label
    model_state = state.models.get((app_label, op.model_name_lower))
    if model_state is None:
        return None
    old = model_state.fields.get(op.name)
    if old is None:
        return None
    try:
        if connection.vendor in ("postgresql", "sqlite"):
            op._using_expression(app_label, old, op.field, connection)
        else:
            op._refuse_declaration(app_label, old, op.field)
    except FieldsealNotSupported as e:
        if not _allowed(op, app_label, state, connection):
            return None
        return (f"{app_label}.{migration.name}: {e} Nothing has run: "
                "migrate refused the plan before any DDL.")
    return None


def _check(migration: Any, op: AlterField, state: Any,
           connection: Any) -> str | None:
    app_label = migration.app_label
    model_state = state.models.get((app_label, op.model_name_lower))
    if model_state is None:
        return None
    old = model_state.fields.get(op.name)
    new = op.field
    if old is None or not casts_into_or_out_of_bytea(old, new, connection):
        return None
    if not _allowed(op, app_label, state, connection):
        return None
    where = (f"{app_label}.{migration.name}: AlterField {op.name} on "
             f"{op.model_name}")
    sealed = new if _is_encrypted(new) else old
    plain = old if sealed is new else new
    if (not _is_encrypted(plain) and _encrypted_binary(sealed)
            and logical_type(sealed.inner) == "string"
            and _PG_TEXT_TYPE.match(plain.db_type(connection) or "")):
        # The same pair is checked when the migration is unapplied, so the
        # remedy names both directions rather than guess which one runs.
        fix = ("Replace it with fieldseal_django.operations."
               "ConvertToEncrypted, with the same arguments: into bytea it "
               "converts the text with convert_to(col, 'UTF8'), the value's "
               "spec §3.6 bytes, and out of bytea with convert_from(col, "
               "'UTF8'), which fails loudly on a value that is not UTF-8, as "
               "an envelope written through the field is likely to be.")
    else:
        fix = ("There is no in-place route for this column on PostgreSQL: "
               "use the two-column shape (docs/12 §7).")
    return (
        f"{where} changes the column from {old.db_type(connection)} to "
        f"{new.db_type(connection)}, and on PostgreSQL Django converts it "
        "with a cast between bytea and text. Into bytea, the cast reads text "
        "as bytea input: a backslash escape or a leading \\x is decoded with no "
        "error (a\\101b is stored as aAb, \\x41 as A), other backslashes fail "
        "the migration, and on PostgreSQL 18 an integer becomes its "
        "big-endian bytes, which can read back as a different integer. Out "
        "of bytea, it writes the bytes as \\x... hex text. "
        f"{fix} Nothing has run: migrate refused the plan before any DDL "
        f"({_ISSUE}).")
