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

from . import codec, unindexable
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
        unindexable_noun: str = "value",
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
        #: What this column holds, for the `docs/12` §10.2 refusal message.
        #: "We can't save this **name** yet" reads very differently from "this
        #: value" to the person whose name it is, and §10.2's requirement 2 is
        #: precisely about how that sentence lands.
        self.unindexable_noun = unindexable_noun

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
        if self.unindexable_noun != "value":
            kwargs["unindexable_noun"] = self.unindexable_noun
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

    def validate(self, value: Any, model_instance: Any) -> None:
        """Refuse an unindexable value here, where a form can still render it.

        **This is where `docs/12` §10.1 wants the failure**, and the reason is
        not tidiness. The index can only be derived in `pre_save`, which is
        the one hook that receives the instance -- and `pre_save` runs *inside*
        the INSERT, so a `ValidationError` raised there propagates out of
        `Model.save()`, whose `transaction.atomic(savepoint=False)` marks the
        connection for rollback. The caller then gets their field error and a
        transaction they cannot use, which is not a form error in any sense
        that helps.

        `validate()` runs from `full_clean()`, which every `ModelForm` calls
        before `save()`. So the form path fails before the database is
        touched, and `pre_save` stays as the backstop for code that calls
        `create()` directly -- where the transaction consequence is real and
        is documented in the package README rather than pretended away.
        """
        super().validate(value, model_instance)
        if self.index is None or value is None:
            return
        from fieldseal import normalize
        from fieldseal.errors import InvalidArgument

        if self.index.on_unindexable == "bucket":
            return
        try:
            normalize(self.index.normalize, self.index_operand(value))
        except InvalidArgument as e:
            raise ValidationError(
                unindexable.validation_error(
                    self.index.normalize, value, self.unindexable_noun)
            ) from e

    def index_operand(self, value: Any) -> Any:
        """What to hand `blind_index` for this column.

        **Text goes to the core as text.** `docs/09` §7.1 (G16 part A) makes
        an index API accept the language's string type precisely because the
        encoding step can destroy information before the core is entered --
        and while CPython's `str.encode` raises on a lone surrogate rather
        than substituting, that is a property of CPython rather than of this
        adapter, and it would surface as a `UnicodeEncodeError` nobody
        catches instead of the §9 `INVALID_ARGUMENT` the refusal path expects.
        Passing the `str` keeps the refusal where the information still is.

        Everything else goes through the codec, which is what the write path
        encrypts, so an index and its ciphertext are derived from the same
        rendering of the same value.
        """
        if isinstance(value, str):
            return value
        return codec.to_bytes(self.inner, value)

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
            # `case.condition` is deliberately NOT inspected. A `When`
            # condition decides *which rows* are updated; only `result` and
            # `default` decide *what is stored*. A condition may therefore
            # reference any column, encrypted or not, without the database
            # ever computing over ciphertext on the write side --
            # `test_a_when_condition_may_reference_any_column` pins it, so the
            # asymmetry is asserted rather than merely intended.
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
        """Coerce through the inner field -- but refuse a fixture round-trip.

        `loaddata` is **not supported** and must not appear to be. Django's
        deserializer routes every fixture value through this hook, and
        `value_to_string` writes base64 ciphertext, so a fixture reloaded
        through the ordinary path arrives here as the base64 of an envelope,
        passes as ordinary text, is stored, and is encrypted **again** by
        `get_db_prep_value`. The row then reads back as the base64 of the
        original envelope instead of the plaintext, with no error at any
        point -- the silent wrong answer spec §10.2 forbids, arriving through
        the one path that looked safe because `dumpdata` was fixed.

        Measured 2026-08-25: `email` and `note` both came back double
        encrypted while an `IntegerField` column survived, so the corruption
        is per-inner-type and a smoke test on the wrong column reports
        success.

        The detection below uses the core's `is_ciphertext`, which spec §3.4
        defines as total over arbitrary input, rather than a pattern this
        adapter invented: a value only trips it if it base64-decodes to
        something carrying `fmt_ver` 0x01, a registered suite id and a
        plausible length. **It is still a recognition heuristic**, and it is
        used here in the fail-closed direction only -- the worst case is
        refusing to accept a plaintext that a user typed and that happens to
        be valid base64 for a valid envelope, which is a refusal rather than
        a corruption. Supporting `loaddata` properly is harder than it looks,
        because this same hook sees user-typed plaintext and fixture
        ciphertext with nothing but the value to tell them apart; the
        supported route for moving encrypted data is `tools/backfill`
        (docs/15).
        """
        if isinstance(value, str) and self._looks_like_a_fixture_envelope(value):
            raise FieldsealNotSupported(
                f"{self.model.__name__}.{self.name}: this value is an "
                "encrypted envelope, not a plaintext one. `loaddata` and "
                "fixture loading are not supported for encrypted columns in "
                "v0: the fixture holds ciphertext, this hook cannot tell it "
                "apart from a plaintext a user typed, and storing it would "
                "encrypt it a second time and return base64 instead of the "
                "value on the next read -- silently. `dumpdata` still emits "
                "ciphertext so fixtures never leak plaintext; to move "
                "encrypted data between databases use the backfill tooling "
                "(docs/15) or copy the ciphertext column directly."
            )
        return self.inner.to_python(value)

    def _looks_like_a_fixture_envelope(self, value: str) -> bool:
        import binascii

        try:
            blob = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return False
        return bool(_client().is_ciphertext(blob))

    def formfield(self, **kwargs: Any) -> Any:
        return self.inner.formfield(**kwargs)

    @property
    def fieldseal_index_field(self) -> EncryptedIndex:
        """The sibling column this field's equality lookups compile against.

        System check E001 already guarantees it exists whenever a BlindIndex
        is declared, so a failure here is a configuration the checks would
        have refused at startup.
        """
        for f in self.model._meta.fields:
            if isinstance(f, EncryptedIndex) and f.source == self.name:
                return f
        raise FieldsealConfigurationError(
            f"{self.model.__name__}.{self.name} declares a BlindIndex but no "
            f"sibling index column (system check fieldseal.E001)"
        )

    def get_lookup(self, lookup_name: str) -> Any:
        if lookup_name in ("exact", "in"):
            if self.index is None:
                raise FieldsealNotSupported(
                    f"`{self.model.__name__}.{self.name}__{lookup_name}` is "
                    "not available: this column declares no BlindIndex, so "
                    "there is no index to match against, and the ciphertext "
                    "is randomized -- a direct comparison matches nothing and "
                    "would return an empty queryset rather than an error, "
                    "which spec §10.2 forbids. Declare a BlindIndex and "
                    "backfill, or filter in Python after fetching."
                )
            return _INDEXED_LOOKUPS[lookup_name]
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
            # `bucket` never reaches the except: the core returns the column's
            # reserved marker rather than raising (docs/09 §7.2), so the row
            # saves and stays findable with no adapter special-casing.
            return _client().blind_index(source.index_operand(value), ctx)
        except InvalidArgument as e:
            # docs/12 §10.1: `refuse` must arrive as a field error the person
            # who typed the value can act on, not as a 500 and not as a
            # silently missing index. §10.2 shapes the wording.
            raise ValidationError(
                {self.source: unindexable.validation_error(
                    decl.normalize, value, source.unindexable_noun)}
            ) from e


class _IndexedLookup(models.Lookup):
    """Compile an equality on the encrypted column onto its index sibling.

    `docs/12` §3.2's route, and the reason it is a `Lookup` rather than a
    queryset-level rewrite: compiling to a `Col` for the sibling composes with
    `Q`, joins and subqueries for free, where a textual rewrite would have to
    reimplement each of them.

    **This class is only half of L2.** What it produces is a *candidate* set:
    spec §7.4 mandates collisions in a truncated index, so the rows it matches
    are a superset of the answer. `FieldsealQuerySet` performs the §7.5
    re-verification that narrows them, and the two are not separable -- which
    is why system check **E008** requires the manager.
    """

    def _index_values(self, values: list[Any]) -> list[bytes]:
        from .apps import get_client

        field = self.lhs.output_field
        decl = field.index
        ctx = field.fieldseal_context().for_index(decl.index_id)
        client = get_client()
        out = []
        for v in values:
            try:
                out.append(client.blind_index(codec.to_bytes(field.inner, v), ctx))
            except InvalidArgument as e:
                # docs/12 §10.1: a lookup for a value this column refuses
                # "raises the same ValidationError -- never returns an empty
                # queryset". The same wording as the write path, because the
                # reader is the same person: a search box is a form field too,
                # and an empty result page would tell them their name does not
                # exist here rather than that we cannot spell it yet.
                raise ValidationError(
                    {field.name: unindexable.validation_error(
                        decl.normalize, v, field.unindexable_noun)}
                ) from e
        return out

    def _sibling_sql(self, compiler: Any) -> tuple[str, list[Any]]:
        self._refuse_cross_model(compiler)
        sibling = self.lhs.output_field.fieldseal_index_field
        col = sibling.get_col(self.lhs.alias, output_field=sibling)
        sql, params = compiler.compile(col)
        return str(sql), list(params)

    def _refuse_cross_model(self, compiler: Any) -> None:
        """Refuse compiling for any model but the column's own.

        A lookup compiles wherever a join can reach the column --
        `Visit.objects.filter(patient__email=...)` -- including from models
        whose manager is a plain one this package never sees. Spec §7.5
        re-verification runs only on the queryset that owns the encrypted
        column, so a cross-model compilation would serve the §7.4 bucket,
        unverified, as results: the spec §10.2 wrong answer. This is the
        backstop for every queryset; `FieldsealQuerySet` additionally refuses
        the same traversal at filter() time with the friendlier message.
        Multi-table-inheritance children are the owning model for this
        purpose: their (verifying) queryset materializes rows that carry the
        column.
        """
        field = self.lhs.output_field
        owner = field.model._meta.concrete_model
        querying = compiler.query.model._meta.concrete_model
        if owner is querying or owner in querying._meta.get_parent_list():
            return
        raise FieldsealNotSupported(
            f"`{querying.__name__}` filters on the encrypted column "
            f"{owner.__name__}.{field.name} through a relation. The join "
            "would match its blind-index sibling, but spec §7.5 "
            "re-verification runs on the queryset that owns the encrypted "
            "column and cannot run from here, so the join would serve "
            "unverified index candidates as results -- which spec §10.2 "
            f"forbids. Filter {owner.__name__} directly instead and join on "
            "the result: embed bucket semantics with "
            f"filter(...__in={owner.__name__}_qs.candidates()), or "
            "materialize verified primary keys and use "
            "filter(...__pk__in=[...])."
        )


class EncryptedExact(_IndexedLookup):
    lookup_name = "exact"

    def as_sql(self, compiler: Any, connection: Any) -> tuple[str, list[Any]]:
        lhs_sql, lhs_params = self._sibling_sql(compiler)
        if self.rhs is None:
            return f"{lhs_sql} IS NULL", list(lhs_params)
        (value,) = self._index_values([self.rhs])
        return f"{lhs_sql} = %s", [*lhs_params, value]


class EncryptedIn(_IndexedLookup):
    lookup_name = "in"

    def as_sql(self, compiler: Any, connection: Any) -> tuple[str, list[Any]]:
        values = self._index_values([v for v in self.rhs if v is not None])
        if not values:
            # Spec §7.10 membership over an empty set matches nothing, and
            # must keep matching nothing rather than degrading to `IN ()`,
            # which is a syntax error on most backends.
            return "1 = 0", []
        lhs_sql, lhs_params = self._sibling_sql(compiler)
        placeholders = ", ".join(["%s"] * len(values))
        return f"{lhs_sql} IN ({placeholders})", [*lhs_params, *values]


_INDEXED_LOOKUPS = {"exact": EncryptedExact, "in": EncryptedIn}


def index_column(source: str, **kwargs: Any) -> EncryptedIndex:
    """`email_bidx = index_column("email")` -- the declaration in `docs/12` §1."""
    return EncryptedIndex(source, **kwargs)


# Attached for the `Encrypted.index_column(...)` spelling docs/12 §1 uses.
Encrypted.index_column = staticmethod(index_column)


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
