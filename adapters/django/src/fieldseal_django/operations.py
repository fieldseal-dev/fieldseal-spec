"""Changing a column into an `Encrypted(..., storage="binary")` one (#252), and
refusing a change of an `Encrypted` column's identity (#288) or of a blind
index's declaration (#303).

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
  forwards or backwards, and refuses (spec §10.2: where a path would silently
  return wrong results, the adapter MUST throw):

  - on every backend, an `AlterField` between two `Encrypted` declarations
    that changes the `column_uuid`, the inner field's spec §3.6 logical type,
    `tenant_bound` or `storage` (#288), and a `ConvertToEncrypted` that would
    refuse when it runs;
  - on PostgreSQL, a plain `AlterField` that would cast a column between
    `bytea` and another type with an `Encrypted` field on either side (#252).
    `makemigrations` writes the plain `AlterField`, so without the receiver
    the default path is the corrupting one;
  - on every backend, an `AlterField` that changes a blind index's
    declaration (#303): between two `Encrypted` declarations that both carry
    a `BlindIndex`, its `index_id`, `idf`, `normalize` or `truncate_bits`,
    its `time_cost` or `memory_kib` under Argon2id, or its `suite_id` when
    both sides state one; between two `EncryptedIndex` fields, `source`.

**What #288 adds.** Four attributes are the stored value's identity, and an
`AlterField` that changes one leaves every envelope written under an identity
the field no longer has. Since #283 a change to the first three runs no SQL
at all (`column_uuid`, `tenant_bound` and the inner field are in
`non_db_attrs`); a `storage` change does run SQL (a table rebuild on SQLite,
the bytea/text cast of #252 on PostgreSQL), which converts no value into the
new form: a changed `column_uuid` is a key the
field no longer derives (spec §6.1), a changed logical type is a different
rendering (§3.6), a changed `tenant_bound` a different tenant in the key and
context (§6; docs/12 §4), a changed `storage` a different §3.3 form. The
receiver refuses them under `migrate --fake` as well, since `pre_migrate` does
not say the run is fake, and when a migration is unapplied, which is the same
change reversed. What passes: a change that keeps the logical type
(`max_length`, `EmailField` to `CharField`) and a change to
`unindexable_noun` or any other attribute the stored bytes and the decrypt
context do not depend on (a change to `index` is #303's, below); and a
`SeparateDatabaseAndState` whose `state_operations` carry the `AlterField`,
the operator's statement that the values were re-encrypted some other way
(only its database operations are checked). `tenant_bound` is compared as
declared, so a change between unstated and a value is refused: the model's
`FieldsealMeta` decides an unstated one, and a migration state does not carry
it.

**What #303 adds.** The index half. A change to a blind index's declaration
runs no SQL either (`index` and `source` are in `non_db_attrs`), and the
stored index values stay those of the old declaration. Spec §7.8 says the
IDF, the normalize function, the truncation length and the key-derivation
context, `index_id` and the declared `suite_id` (§7.2) included, MUST NOT
change once written; an equality lookup then derives the new value, matches
none of the stored ones and returns no rows, the silent empty result spec
§10.2 says the adapter must refuse. Refused, by the same walk and with the
same escape hatch: both sides `Encrypted` with a `BlindIndex` and any of
`index_id`, `idf`, `normalize`, `truncate_bits` differing; `time_cost` and
`memory_kib`, as declared, when both sides use `argon2id` (a change between
unstated and a value is refused, which may over-refuse); `suite_id`, only when
both sides state one; and two `EncryptedIndex` fields whose `source` differs.
Not refused: adding a `BlindIndex` where there was none, removing one, a
change to `projected_population`, `cardinality_override`, `skewed`,
`on_unindexable` or `unindexable_override`, and a `suite_id` going from
unstated to a value or back. The last is what #213 made every project with an
index generate, an `AlterField` that records the suite the index was always
derived under, and unapplying it must work too. No supported rebuild of an
index exists yet (#315), so the escape hatch is a statement that it was
rebuilt by other means.

The walk starts only for a plan with a `ConvertToEncrypted` in it, or an
`AlterField` on PostgreSQL, or elsewhere an `AlterField` to an `Encrypted` or
`EncryptedIndex` field, since both checks need one on the new side.

**Scope.** The refusal guards `migrate` only. A deployment that ships a new
declaration without running `migrate`, or a declaration change with no
migration generated for it, is not stopped: the refusal prevents the loss only
when a failed `migrate` stops the deploy. A fresh database, test databases
included, runs the whole history, so a historical `AlterField` that changed
one of the four is refused there although the table is empty (docs/12 §6).

Neither runs any cryptography: the conversion is the database's own text
encoding, and the backfill (`tools/backfill/PROCEDURE.md`) does the
encrypting afterwards.
"""

from __future__ import annotations

import contextlib
import re
import uuid as _uuid
from collections.abc import Callable, Iterator
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
_ISSUE_288 = "https://github.com/fieldseal-dev/fieldseal-spec/issues/288"
_ISSUE_303 = "https://github.com/fieldseal-dev/fieldseal-spec/issues/303"
_ISSUE_315 = "https://github.com/fieldseal-dev/fieldseal-spec/issues/315"

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


def _is_encrypted_index(field: Any) -> bool:
    from .fields import EncryptedIndex

    return isinstance(field, EncryptedIndex)


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
    """`pre_migrate` receiver: refuse the plan before any DDL runs if

    - on any backend, an `AlterField` in it changes an `Encrypted` column's
      `column_uuid`, its inner field's spec §3.6 logical type, its
      `tenant_bound` or its `storage`, between two `Encrypted` declarations,
      in either direction (#288);
    - on any backend, an `AlterField` in it changes a blind index's
      declaration: `index_id`, `idf`, `normalize`, `truncate_bits`,
      `time_cost` or `memory_kib` (Argon2id only) or `suite_id` (when both
      sides state one) between two `Encrypted` declarations that both carry
      a `BlindIndex`, or `source` between two `EncryptedIndex` fields (#303);
    - on PostgreSQL, a plain `AlterField` in it would cast an `Encrypted`
      column into or out of `bytea` (#252);
    - on any backend, a `ConvertToEncrypted` in it would refuse when it ran
      (#252).
    """
    global _last_plan
    if not plan or plan is _last_plan:
        return
    _last_plan = plan
    connection = connections[using]
    worth = _worth_a_walk(connection)
    if not any(_has_operation(m.operations, worth) for m, _ in plan):
        return
    for problem in _unsafe_alter_fields(plan, connection):
        raise FieldsealNotSupported(problem)


def _worth_a_walk(connection: Any) -> Callable[[Any], bool]:
    """Which operations make the plan worth walking, on this backend.

    The one place the backend decides what is walked. A `ConvertToEncrypted`
    always is, since `_check_conversion` raises its own refusals before the
    plan starts (#252). On PostgreSQL every `AlterField` can be a bytea cast,
    so every one is. Elsewhere only the identity and index checks apply to a
    plain `AlterField` (#288, #303), and they need an `Encrypted` or
    `EncryptedIndex` declaration on the new side, so an `AlterField` to a
    plain field does not start a walk. The walk
    itself is cheap (it renders a state only in `_allowed`, for an operation
    it is about to refuse); this keeps it off plans that cannot need it.
    """
    postgresql = connection.vendor == "postgresql"

    def worth(op: Any) -> bool:
        return isinstance(op, ConvertToEncrypted) or (
            isinstance(op, AlterField)
            and (postgresql or _is_encrypted(op.field)
                 or _is_encrypted_index(op.field)))

    return worth


def _has_operation(operations: list[Any],
                   worth: Callable[[Any], bool]) -> bool:
    for op in operations:
        if isinstance(op, SeparateDatabaseAndState):
            if _has_operation(op.database_operations, worth):
                return True
        elif worth(op):
            return True
    return False


def _unsafe_alter_fields(plan: list[Any],
                         connection: Any) -> Iterator[str]:
    """Walk `plan` with the states Django's executor will give each
    migration, and describe each unsafe `AlterField` in it."""
    from django.db.migrations.executor import MigrationExecutor
    from django.db.migrations.state import ProjectState

    backwards = bool(plan[0][1])
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
    if backwards:
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
                                 connection, backwards)
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
                             connection, backwards)


def _scan(migration: Any, operations: list[Any], state: Any,
          connection: Any, backwards: bool) -> Iterator[str]:
    """Check each operation against `state`, advancing it as Django does."""
    app_label = migration.app_label
    for op in operations:
        if isinstance(op, SeparateDatabaseAndState):
            # The database operations run against a copy of the state, and
            # only the state operations move the real one.
            yield from _scan(migration, op.database_operations,
                             state.clone(), connection, backwards)
            for state_op in op.state_operations:
                state_op.state_forwards(app_label, state)
            continue
        problem = None
        if isinstance(op, ConvertToEncrypted):
            problem = _check_conversion(migration, op, state, connection)
        elif isinstance(op, AlterField):
            problem = _check(migration, op, state, connection, backwards)
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


def _check(migration: Any, op: AlterField, state: Any, connection: Any,
           backwards: bool) -> str | None:
    """The refusals for a plain `AlterField`: the identity change (#288) and
    the index declaration change (#303), on every backend, and the bytea
    cast, on PostgreSQL only (#252). When more than one applies the message
    carries each."""
    app_label = migration.app_label
    model_state = state.models.get((app_label, op.model_name_lower))
    if model_state is None:
        return None
    old = model_state.fields.get(op.name)
    new = op.field
    if old is None:
        return None
    changes = _identity_changes(old, new)
    index_changes = _index_changes(old, new)
    casts = (connection.vendor == "postgresql"
             and casts_into_or_out_of_bytea(old, new, connection))
    if not changes and not index_changes and not casts:
        return None
    if not _allowed(op, app_label, state, connection):
        return None
    problems = []
    if changes:
        problems.append(_identity_message(migration, op, changes, backwards))
    if index_changes:
        problems.append(_index_message(migration, op, index_changes,
                                       backwards))
    if casts:
        problems.append(_cast_message(migration, op, old, connection,
                                      backwards))
    return " ".join(problems)


def _uuid_text(field: Any) -> str:
    return str(_uuid.UUID(bytes=field.column_uuid))


def _identity_changes(old: Any, new: Any) -> list[tuple[str, str, str, str]]:
    """What an `AlterField` from `old` to `new` changes of the identity the
    stored values were written under, as (attribute, old, new, why).

    Only between two `Encrypted` declarations: from or to a plain field is
    the conversion (#252), whose rows hold no envelope or are being made into
    one by the backfill. Each attribute here is one the stored bytes or the
    decrypt context depend on (#288):

    - `column_uuid` is the key-derivation and AAD identity (spec §6.1); it
      is compared as the 16 bytes parsed, not as the string written.
    - the inner field's spec §3.6 logical type is the rendering the
      envelopes hold. A change inside one type (`max_length`, `EmailField` to
      `CharField`) keeps the rendering and is not a change here.
    - `storage`, the spec §3.3 form the envelope is stored in. It always
      holds a resolved value (`Encrypted.__init__` defaults it to `"binary"`).
    - `tenant_bound`, as declared: the tenant is part of the key and AAD
      context (spec §6; docs/12 §4). `None` means the model's
      `FieldsealMeta` decides, which a migration state does not carry, so a
      change between `None` and a value is refused too: it may be a change,
      and the refusal has an escape hatch where a silent pass has none.
    """
    if not (_is_encrypted(old) and _is_encrypted(new)):
        return []
    changes = []
    if old.column_uuid != new.column_uuid:
        changes.append((
            "column_uuid", _uuid_text(old), _uuid_text(new),
            "spec §6.1 binds each value's key derivation and context to "
            "column_uuid, so every stored value, written under the old one, "
            "no longer decrypts (fieldseal_gen_uuids calls a changed "
            "column_uuid a data-loss event)"))
    old_type, new_type = logical_type(old.inner), logical_type(new.inner)
    if old_type != new_type:
        changes.append((
            "inner logical type",
            f"{old_type} ({type(old.inner).__name__})",
            f"{new_type} ({type(new.inner).__name__})",
            "spec §3.6 fixes each type's rendering, and the stored envelopes "
            "hold the old type's, so a read fails or misreads them"))
    if old.tenant_bound != new.tenant_bound:
        changes.append((
            "tenant_bound",
            _tenant_text(old.tenant_bound), _tenant_text(new.tenant_bound),
            "the tenant is part of the key and context a value is encrypted "
            "under (spec §6; docs/12 §4), so values written under one "
            "setting do not decrypt under the other"))
    if old.storage != new.storage:
        changes.append((
            "storage", old.storage, new.storage,
            "spec §3.3 gives the envelope a binary or a base64 text form, "
            "and nothing converts the stored values into the new one: on "
            "SQLite the table rebuild copies each value in its old storage "
            "class, "
            "so every read fails with NOT_CIPHERTEXT in strict, and in "
            "permissive a column changed from base64 to binary returns the "
            "envelope's base64 text as the plaintext value"))
    return changes


def _tenant_text(declared: bool | None) -> str:
    return ("not declared (the model's FieldsealMeta decides)"
            if declared is None else str(declared))


def _identity_message(migration: Any, op: AlterField,
                      changes: list[tuple[str, str, str, str]],
                      backwards: bool) -> str:
    where = (f"{migration.app_label}.{migration.name}: "
             f"{'unapplying ' if backwards else ''}AlterField {op.name} on "
             f"{op.model_name}")
    # Backwards, the migration's declaration is the state the column leaves
    # and the state before it the one it arrives at.
    parts = []
    for attribute, before, after, why in changes:
        if backwards:
            before, after = after, before
        parts.append(f"{attribute} from {before} to {after}: {why}")
    return (
        f"{where} changes an Encrypted column's identity: "
        f"{'; and '.join(parts)}. Nothing converts the stored values into "
        "the new identity, and migrate --fake would record the change "
        "without running anything, so the values already written would be "
        "silently lost to reads, where spec §10.2 says the adapter MUST "
        "throw. If the values were "
        "re-encrypted by other means, record the change in a "
        "SeparateDatabaseAndState whose state_operations carry this "
        "AlterField, which is your statement that they were; otherwise use "
        "the two-column shape (docs/12 §7). Nothing has run: migrate refused "
        f"the plan before any DDL ({_ISSUE_288}).")


def _index_changes(old: Any, new: Any) -> list[tuple[str, str, str]]:
    """What an `AlterField` from `old` to `new` changes of a blind index's
    declaration, as (attribute, old, new): the parts of it spec §7.8 says
    MUST NOT change once an index is written (#303).

    Between two `Encrypted` declarations that both carry a `BlindIndex`: a
    declaration added or removed is not a change here (adding one leaves the
    column to be filled by a backfill; the rebuild of a changed one is #315).
    Between two `EncryptedIndex` fields: `source`.

    - `index_id`, `idf`, `normalize` and `truncate_bits` are named by §7.8
      or are part of the key-derivation context (§7.2).
    - `time_cost` and `memory_kib` are the Argon2id cost (§7.3) and are
      compared only when both sides use `argon2id`; under another IDF they
      are ignored by the derivation, and if `idf` itself differs that is
      reported alone. They are compared as declared, so a change between
      unstated and a value is refused although the effective cost may be the
      same: the default is the adapter's to change, and a refusal has the
      escape hatch where a silent pass has none.
    - `suite_id` only when both sides state one. `None` means "not stated"
      (#213): every project with an index generated an `AlterField` that
      records the suite the index was always derived under, and unapplying
      it goes from a value to `None`, so neither direction is a change.
    """
    from .fields import EncryptedIndex

    if isinstance(old, EncryptedIndex) and isinstance(new, EncryptedIndex):
        if old.source != new.source:
            return [("source", old.source, new.source)]
        return []
    if not (_is_encrypted(old) and _is_encrypted(new)):
        return []
    before, after = old.index, new.index
    if before is None or after is None:
        return []
    changes = []
    for attribute in ("index_id", "idf", "normalize", "truncate_bits"):
        a, b = getattr(before, attribute), getattr(after, attribute)
        if a != b:
            changes.append((attribute, str(a), str(b)))
    if before.idf == after.idf == "argon2id":
        for attribute in ("time_cost", "memory_kib"):
            a, b = getattr(before, attribute), getattr(after, attribute)
            if a != b:
                changes.append((attribute, _declared_text(a),
                                _declared_text(b)))
    if (before.suite_id is not None and after.suite_id is not None
            and before.suite_id != after.suite_id):
        changes.append(("suite_id", f"{before.suite_id:#06x}",
                        f"{after.suite_id:#06x}"))
    return changes


def _declared_text(value: int | None) -> str:
    return "not declared" if value is None else str(value)


def _index_message(migration: Any, op: AlterField,
                   changes: list[tuple[str, str, str]],
                   backwards: bool) -> str:
    where = (f"{migration.app_label}.{migration.name}: "
             f"{'unapplying ' if backwards else ''}AlterField {op.name} on "
             f"{op.model_name}")
    parts = []
    for attribute, before, after in changes:
        if backwards:
            before, after = after, before
        parts.append(f"{attribute} from {before} to {after}")
    return (
        f"{where} changes a blind index's declaration: {'; and '.join(parts)}"
        ". By spec §7.8 the IDF, the normalize function, the truncation "
        "length and the key-derivation context (the index_id and the "
        "declared suite_id, §7.2) MUST NOT change once an index is written. "
        "This AlterField runs no SQL, so the stored index values stay those "
        "of the old declaration; an equality lookup derives its value under "
        "the new one, matches none of them and returns no rows, the silent "
        "empty result spec §10.2 says the adapter MUST refuse, and migrate "
        "--fake would record the change without running anything. If the "
        "index column was rebuilt under the new declaration by other means, "
        "record the change in a SeparateDatabaseAndState whose "
        "state_operations carry this AlterField, which is your statement "
        f"that it was. No supported rebuild exists yet ({_ISSUE_315}). "
        "Nothing has run: migrate refused the plan before any DDL "
        f"({_ISSUE_303}).")


def _cast_message(migration: Any, op: AlterField, before: Any,
                  connection: Any, backwards: bool) -> str:
    """The #252 message. `before` is the field in the state ahead of the
    migration; unapplying, the column goes from `op.field` back to it."""
    app_label = migration.app_label
    old, new = (op.field, before) if backwards else (before, op.field)
    where = (f"{app_label}.{migration.name}: "
             f"{'unapplying ' if backwards else ''}AlterField {op.name} on "
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
