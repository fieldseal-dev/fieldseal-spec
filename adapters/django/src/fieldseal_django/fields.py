"""`Encrypted` and its index sibling (docs/12 §1, §2).

Composition over Django's field types -- the Rails `encrypts` shape `docs/04`
§8 recommends -- rather than a parallel hierarchy of `EncryptedCharField`,
`EncryptedEmailField`, and so on. The inner field keeps its own
`to_python`, validators and form widget; this field owns only the trip to and
from storage.

**Hook placement is load-bearing and was verified, not guessed** (`docs/04`
§1): the write transform lives in `get_db_prep_value`, which is the one hook
both the save path and the lookup path traverse. `get_prep_value` is too
early -- it runs for lookups whose right-hand side must stay plaintext --
and `pre_save` is too late for anything but the index sibling, which needs
the instance and so can only run there.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.db import models
from fieldseal.errors import InvalidArgument

from . import codec
from .context import build_context
from .declarations import BlindIndex, parse_uuid
from .errors import FieldsealConfigurationError, FieldsealNotSupported

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fieldseal import FieldContext

#: Lookups that must never reach the database against a randomized ciphertext
#: column. Spec §7.10 lists the honest fallback for each; §10.2 requires the
#: adapter to raise rather than let one through, because every one of them
#: would compile to valid SQL and return a confidently wrong answer.
REFUSED_LOOKUPS = {
    "contains": "substring search over ciphertext matches nothing",
    "icontains": "substring search over ciphertext matches nothing",
    "startswith": "prefix search needs a §7.9 prefix index, not declared here",
    "istartswith": "prefix search needs a §7.9 prefix index, not declared here",
    "endswith": "suffix search has no blind-index construction",
    "iendswith": "suffix search has no blind-index construction",
    "iexact": "case folding belongs to the normalizer, not the query",
    "gt": "ordering over ciphertext is meaningless; see spec §7.10",
    "gte": "ordering over ciphertext is meaningless; see spec §7.10",
    "lt": "ordering over ciphertext is meaningless; see spec §7.10",
    "lte": "ordering over ciphertext is meaningless; see spec §7.10",
    "range": "ordering over ciphertext is meaningless; see spec §7.10",
    "regex": "pattern matching over ciphertext matches nothing",
    "iregex": "pattern matching over ciphertext matches nothing",
    "search": "full-text search over ciphertext matches nothing",
    "year": "date parts are not recoverable from ciphertext",
    "month": "date parts are not recoverable from ciphertext",
    "day": "date parts are not recoverable from ciphertext",
}


class Encrypted(models.Field):
    """Wraps an inner field; stores its value as a fieldseal envelope.

        email = Encrypted(models.EmailField(), column_uuid="018f3c2e-...")
    """

    description = "fieldseal-encrypted value"

    def __init__(
        self,
        inner: models.Field[Any, Any],
        *,
        column_uuid: str | bytes,
        index: BlindIndex | None = None,
        tenant_bound: bool | None = None,
        storage: str = "binary",
        **kwargs: Any,
    ) -> None:
        if not isinstance(inner, models.Field):
            raise FieldsealConfigurationError(
                "Encrypted() takes a Django field instance as its first "
                f"argument, e.g. Encrypted(models.EmailField(), ...); got "
                f"{type(inner).__name__}"
            )
        if storage not in ("binary", "base64"):
            raise FieldsealConfigurationError(
                f"storage must be 'binary' or 'base64', got {storage!r}"
            )
        self.inner = inner
        self.column_uuid = parse_uuid(column_uuid, "column_uuid")
        self.column_uuid_raw = column_uuid
        self.index = index
        self.tenant_bound = tenant_bound
        self.storage = storage
        #: Set by `contribute_to_class` on the sibling; see `index_column`.
        self.fieldseal_index_field: EncryptedIndex | None = None

        # The inner field's own kwargs stay with the inner field. What this
        # field takes are the storage-level ones: a ciphertext column is
        # nullable or not, and that is about all it can honour.
        kwargs.setdefault("editable", inner.editable)
        kwargs.setdefault("blank", inner.blank)
        kwargs.setdefault("null", inner.null)
        kwargs.setdefault("verbose_name", inner.verbose_name)
        super().__init__(**kwargs)

    # -- Django plumbing ---------------------------------------------------

    def deconstruct(self) -> tuple[str, str, list[Any], dict[str, Any]]:
        """Capture the surrogate UUIDs into migrations (`docs/12` §1.1).

        The UUIDs must survive into the migration file, because that is what
        makes a rename safe: the column can be renamed, the model can be
        renamed, and the identifier the key derivation binds to does not move.
        """
        name, path, args, kwargs = super().deconstruct()
        args = [self.inner, *args]
        kwargs["column_uuid"] = self.column_uuid_raw
        if self.index is not None:
            kwargs["index"] = self.index
        if self.tenant_bound is not None:
            kwargs["tenant_bound"] = self.tenant_bound
        if self.storage != "binary":
            kwargs["storage"] = self.storage
        return name, path, args, kwargs

    def contribute_to_class(
        self, cls: type[models.Model], name: str, **kwargs: Any
    ) -> None:
        super().contribute_to_class(cls, name, **kwargs)
        # The inner field never joins the model -- it has no column and must
        # not appear in queries -- but it needs enough identity to render
        # errors and coerce values.
        self.inner.set_attributes_from_name(name)
        self.inner.model = cls

    def get_internal_type(self) -> str:
        return "TextField" if self.storage == "base64" else "BinaryField"

    def db_type(self, connection: Any) -> str | None:
        if self.storage == "base64":
            return connection.data_types.get("TextField")
        return connection.data_types.get("BinaryField")

    # -- context -----------------------------------------------------------

    def _is_tenant_bound(self) -> bool:
        if self.tenant_bound is not None:
            return self.tenant_bound
        meta = getattr(self.model, "fieldseal", None)
        return bool(getattr(meta, "tenant_bound", False))

    def fieldseal_context(self, purpose: str = "encrypt") -> FieldContext:
        meta = getattr(self.model, "fieldseal", None)
        if meta is None:
            raise FieldsealConfigurationError(
                f"{self.model.__name__} carries an Encrypted field but no "
                "`fieldseal = FieldsealMeta(table_uuid=...)` declaration "
                "(docs/12 §1; system check fieldseal.E004)"
            )
        return build_context(
            table_uuid=meta.table_uuid_bytes,
            column_uuid=self.column_uuid,
            tenant_bound=self._is_tenant_bound(),
            model=self.model.__name__,
            field=self.name,
            purpose=purpose,
        )

    # -- value path (docs/12 §2) -------------------------------------------

    def get_db_prep_value(
        self, value: Any, connection: Any, prepared: bool = False
    ) -> Any:
        """Encrypt on the way to the database.

        `get_db_prep_save` routes here for ordinary values and short-circuits
        on expressions, which is exactly the behaviour §6's expression row
        depends on: an `F()` right-hand side never reaches this method, so the
        refusal has to live in `get_db_prep_save` instead.
        """
        if value is None:
            return None
        if isinstance(value, _AlreadyCiphertext):
            return value.blob if self.storage == "binary" else value.text
        blob = _client().encrypt(codec.to_bytes(self.inner, value),
                                 self.fieldseal_context())
        if self.storage == "base64":
            return base64.b64encode(blob).decode("ascii")
        return blob

    def get_db_prep_save(self, value: Any, connection: Any) -> Any:
        """Refuse the expressions the *database* would compute; allow the ones
        that merely carry literals.

        Django's base implementation returns anything with `as_sql` untouched
        and lets the compiler render it, which is how `update(field=F(...))`
        would reach the column as a raw SQL reference -- the database copying
        one ciphertext into another column, or worse, computing over it.

        But not every expression is that. `bulk_update()` builds a
        `Case/When` whose results are `Value(...)` literals, and `Value.as_sql`
        calls `output_field.get_db_prep_save` on the literal (Django
        `expressions.py`, `for_save=True`), which re-enters this method with
        the plain value and encrypts it. Refusing the whole class would take
        `bulk_update` -- a supported row of `docs/12` §6, and the write path
        `docs/15` requires backfill to use -- down with it.

        So the test is on the *written* expression, not on its conditions: a
        `When` may reference any column it likes, because that reference
        decides which row is updated rather than what is stored in it.
        """
        if hasattr(value, "as_sql"):
            self._assert_literal_expression(value)
            return value
        return super().get_db_prep_save(value, connection)

    def _assert_literal_expression(self, expr: Any) -> None:
        """Allow expressions that only *carry* literals; refuse the rest.

        `Cast` is on the list because Django puts it there itself:
        `bulk_update` wraps each `Value` in a `Cast` when the backend sets
        `requires_casted_case_in_updates`, which **PostgreSQL does and SQLite
        does not** (`django/db/backends/postgresql/features.py`). The same
        `bulk_update()` call therefore builds a different expression tree per
        backend, and a walker that only knew `Value` and `Case` passed on
        SQLite and refused on Postgres. That divergence is exactly what
        `docs/12` §8 requires a two-backend CI run to catch, and it is what
        caught this.

        A cast is safe here for a specific reason, not by analogy: it coerces
        the *representation* of a parameter the database already received as
        an opaque blob, and the inner `Value.as_sql` has already routed that
        parameter through `get_db_prep_value` and encrypted it. A general
        `Func` is not safe -- `Upper(Value("x"))` would compile `UPPER(%s)`
        over the ciphertext -- so the allow-list stays closed, and a `Cast`
        whose source is an `F()` still refuses, because the recursion finds a
        column reference rather than a literal.
        """
        from django.db.models.expressions import Case, Value
        from django.db.models.functions import Cast

        if isinstance(expr, Value):
            return
        if isinstance(expr, Case):
            for case in expr.cases:
                self._assert_literal_expression(case.result)
            if expr.default is not None:
                self._assert_literal_expression(expr.default)
            return
        if isinstance(expr, Cast):
            for source in expr.get_source_expressions():
                self._assert_literal_expression(source)
            return
        raise FieldsealNotSupported(
            f"{self.model.__name__}.{self.name} is encrypted, so "
            f"{type(expr).__name__} cannot be its right-hand side: the "
            "database would have to compute over ciphertext, and the result "
            "would be written to the column without ever passing through "
            "encryption. `update(field=F(...))`, arithmetic, and database "
            "functions are refused rather than silently storing a wrong or "
            "plaintext value (spec §10.2; docs/12 §6). Read the rows, compute "
            "in Python, and write back with `bulk_update()`, which is "
            "supported because it carries literals."
        )

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> Any:
        if value is None:
            return None
        blob = _to_bytes_from_db(value, self.storage)
        return codec.from_bytes(self.inner, _client().decrypt(
            blob, self.fieldseal_context()))

    def value_to_string(self, obj: models.Model) -> str:
        """`dumpdata` emits base64 ciphertext (`docs/04` §1 gotcha).

        Without this, serialization reaches for the field's Python value and
        writes **plaintext** into a fixture -- a silent leak into a file that
        gets committed, copied to laptops and attached to tickets.
        """
        value = self.value_from_object(obj)
        if value is None:
            return ""
        blob = _client().encrypt(codec.to_bytes(self.inner, value),
                                 self.fieldseal_context())
        return base64.b64encode(blob).decode("ascii")

    # -- forms and validation ----------------------------------------------

    def to_python(self, value: Any) -> Any:
        return self.inner.to_python(value)

    def formfield(self, **kwargs: Any) -> Any:
        return self.inner.formfield(**kwargs)

    def get_lookup(self, lookup_name: str) -> Any:
        if lookup_name in ("exact", "in"):
            # L2 is not implemented yet, and shipping half of it would be
            # worse than shipping none: without spec §7.5 re-verification a
            # truncated index returns collisions, so the queryset would hand
            # back rows whose plaintext does not match -- a wrong answer
            # rather than an error. Until that lands, both paths refuse.
            raise FieldsealNotSupported(
                f"`{self.model.__name__}.{self.name}__{lookup_name}` is not "
                "available yet. The column holds a randomized envelope, so a "
                "direct comparison matches nothing -- it would return an "
                "empty queryset rather than an error, which spec §10.2 "
                "forbids. Equality goes through the blind-index sibling "
                "column, and that path is not enabled until it re-verifies "
                "candidates as spec §7.5 requires (a truncated index collides "
                "by design). Read rows by primary key, or decrypt and compare "
                "in Python, until L2 ships."
            )
        reason = REFUSED_LOOKUPS.get(lookup_name)
        if reason is not None:
            raise FieldsealNotSupported(
                f"`{self.model.__name__}.{self.name}__{lookup_name}` is not "
                f"available on an encrypted column: {reason}. The column "
                "holds a randomized envelope, so this lookup would compile "
                "to valid SQL and return a confidently wrong answer -- spec "
                "§10.2 requires the adapter to raise instead. See spec §7.10 "
                "for the honest fallback for each lookup."
            )
        return super().get_lookup(lookup_name)


class EncryptedIndex(models.BinaryField):
    """The blind-index sibling column (`docs/12` §1.2).

    A real, explicit field rather than a hidden auto-injected one, for the two
    reasons `docs/12` gives: `SQLInsertCompiler.as_sql` iterates fields in
    declaration order and this field's `pre_save` must run after the
    encrypted field's, which is only visible if the column is in the source;
    and `makemigrations` then emits ordinary DDL with no magic.
    """

    description = "fieldseal blind index"

    def __init__(self, source: str, **kwargs: Any) -> None:
        self.source = source
        kwargs.setdefault("editable", False)
        kwargs.setdefault("null", True)
        super().__init__(**kwargs)

    def deconstruct(self) -> tuple[str, str, list[Any], dict[str, Any]]:
        name, path, args, kwargs = super().deconstruct()
        return name, path, [self.source, *args], kwargs

    @property
    def source_field(self) -> Encrypted:
        field = self.model._meta.get_field(self.source)
        if not isinstance(field, Encrypted):
            raise FieldsealConfigurationError(
                f"{self.model.__name__}.{self.name} indexes "
                f"{self.source!r}, which is not an Encrypted field"
            )
        return field

    def get_lookup(self, lookup_name: str) -> Any:
        if lookup_name in ("exact", "in"):
            raise FieldsealNotSupported(
                f"`{self.model.__name__}.{self.name}__{lookup_name}` is not "
                "available yet. This column stores a *truncated* blind index, "
                "so spec §7.4 makes collisions certain by design and spec "
                "§7.5 makes re-verification mandatory: matching on it alone "
                "returns rows whose plaintext differs from the value asked "
                "for. The lookup is refused rather than served without that "
                "step. The column is written correctly in the meantime, so no "
                "backfill is needed when L2 lands."
            )
        return super().get_lookup(lookup_name)

    def pre_save(self, model_instance: models.Model, add: bool) -> Any:
        """Derive the index from the *sibling plaintext* on the instance.

        `pre_save` is the only field hook that receives the instance
        (`docs/04` §1, verified), which is why the index lives here and the
        ciphertext does not.
        """
        source = self.source_field
        value = getattr(model_instance, self.source, None)
        if value is None:
            return None
        decl = source.index
        if decl is None:
            raise FieldsealConfigurationError(
                f"{self.model.__name__}.{self.name} indexes "
                f"{self.source!r}, which declares no BlindIndex"
            )
        ctx = source.fieldseal_context().for_index(decl.index_id)
        try:
            return _client().blind_index(codec.to_bytes(source.inner, value), ctx)
        except InvalidArgument as e:
            # docs/12 §10.1: `refuse` must arrive as a field error the person
            # who typed the value can act on, not as a 500 and not as a
            # silently missing index.
            raise ValidationError({self.source: str(e)}) from e


def index_column(source: str, **kwargs: Any) -> EncryptedIndex:
    """`email_bidx = index_column("email")` -- the declaration in `docs/12` §1."""
    return EncryptedIndex(source, **kwargs)


# Attached for the `Encrypted.index_column(...)` spelling docs/12 §1 uses.
Encrypted.index_column = staticmethod(index_column)


class _AlreadyCiphertext:
    """Marker for values that must not be re-encrypted (backfill paths)."""

    __slots__ = ("blob", "text")

    def __init__(self, blob: bytes) -> None:
        self.blob = blob
        self.text = base64.b64encode(blob).decode("ascii")


def _to_bytes_from_db(value: Any, storage: str) -> bytes:
    if storage == "base64":
        return base64.b64decode(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    return value


def _client() -> Any:
    from .apps import get_client

    return get_client()
