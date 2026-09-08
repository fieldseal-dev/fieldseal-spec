"""The L2 query path: index rewriting plus mandatory §7.5 re-verification.

**The design decision this file implements** is `docs/12` §3.2's deferred one,
settled as option C: `_fetch_all` re-verifies by default and `.candidates()`
opts out. The alternative -- an explicit `.verified()` that callers must
remember -- was rejected because its failure mode is silent: a forgotten call
returns collision rows, which is precisely the wrong answer spec §10.2 exists
to forbid. The safe path has to be the default path.

**The cost of that decision is that this module owns private Django API.**
`_fetch_all` is not a documented extension point. `tests/test_query_private_api.py` pins
every assumption this module makes about it, so that a Django upgrade breaks
the build rather than silently returning unverified rows.

**What re-verification compares** is spec §7.5's comparison rule (G19,
[#78], resolved 2026-08-26): `normalize(stored)` against
`normalize(queried)` under the index's own normalizer, not raw plaintext. On a
column declaring `nfc-casefold-v1` a row stored `Ada@Example.com` matches a
query for `ada@example.com` -- because the index already merged them, and a
verification step that un-merged them would leave the caseless lookup the
normalizer exists to enable unreachable from the ORM (`docs/12` §3.3 refuses
`iexact` on exactly that reasoning). The normalizer comes from the core; an
adapter that reimplemented `nfc-casefold-v1` would be reimplementing
portability surface where a disagreement is a silent lookup miss.

**The hard part is not the rewrite, it is what shrinks.** Verification drops
rows after the database has already applied `LIMIT`, `COUNT` and `OFFSET`, so
every queryset method that answers from SQL rather than from materialized rows
is wrong by default. Each one is handled explicitly below; none is left to
inherit a wrong answer. The dividing line throughout: a predicate is
*approximate* only when it touches the blind index. `IS NULL` -- spelled
`__isnull` or `filter(field=None)` -- is answered exactly by the envelope
column itself (NULL plaintext is stored as NULL, never as an encrypted
placeholder), so it is served with no obligation, in any combination.

**A second family is not verification's to lift either, and this one is a
filter (G24, [#100], decided 2026-09-06):** an encrypted term in a
*subtractive* position -- `exclude()`, a negated `Q`, XOR -- is refused on
every queryset, `.candidates()` included. The hatch hands the caller §7.5,
and §7.5 is a filter obligation: a superset can be narrowed to the answer,
an exclusion cannot be widened back to it, because the rows the database
dropped are not in what the caller was handed. Spec §10.2 carries the rule;
this adapter lifted it until G24 closed, and the Prisma adapter did not,
which is the divergence the issue was filed for.

**A third refusal family, G20 ([#80]), is orthogonal to verification:** SQL
that *reads envelope bytes* -- `ORDER BY`, `GROUP BY`, `DISTINCT`, aggregate
and function expressions over them -- is meaningless on every queryset,
obligations or none, and `.candidates()` does not lift it. See the section
comment above `order_by` for what was measured before those refusals were
written. The one aggregate that reads no envelope bytes is carved out (G23,
[#89]): a plain, non-distinct `Count(field)` counts null-ness alone, and the
§10.2 NULL-preservation invariant (the same one that makes `__isnull` exact,
above) makes it equal the plaintext count exactly, so it is served.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from django.db import models

from .errors import FieldsealNotSupported

#: The positions a wider index bucket *narrows* rather than widens, named for
#: the refusal message. `.candidates()` does not lift either (G24, [#100]):
#: XOR is here because it is negation once expanded, and a widened operand
#: flips rows out of the answer exactly as an `exclude()` does.
_NEGATED = "a negated combination"
_XOR = ("an XOR combination -- negation once expanded, since `a XOR b` is "
        "`(a AND NOT b) OR (NOT a AND b)`")


#: Appended to a refusal whose usual justification is bucket mechanics, when
#: the column has no bucket for the claim to be about. The refusal itself is
#: unchanged -- what changes is that it stops asserting a §7.4 bucket that
#: does not exist, and stops prescribing a remedy that is itself refused.
#: G23's precedent, one clause up: a refusal MUST NOT carry a false
#: justification (spec §10.2).
_NO_BUCKET_TAIL = (" Fetch the rows and filter in Python after decryption, "
                   "which is the honest fallback in either direction.")


class _Bucketed:
    """What the walk reports for an indexed term seen while §7.5 was off.

    There is no obligation to record -- `.candidates()` handed §7.5 to the
    caller -- but the queryset's rows are a §7.4 bucket rather than the
    answer, and a position that *embeds* it has to be able to tell. Carried
    as a marker in the walk's own result list so that neither walker grows a
    parameter for it.
    """

    __slots__ = ()


_BUCKETED = _Bucketed()


def _embedded_index_query(value: Any, bucket_only: bool = False,
                          expressions_only: bool = False) -> Any:
    """The first embedded `Query` a blind index selected the rows of, or None.

    `filter(x__in=qs)` hands Django the queryset, so `resolve_expression`
    sees it; `Exists(qs)` and `Subquery(qs)` take `qs.query` in their
    constructor and never call the queryset again, so the mark has to live
    on the `Query` (see `_mark_query`) and the operand has to be walked as
    an expression tree to find it.

    `expressions_only` skips a bare queryset operand, which is the other
    route's to police: `filter(x__in=qs.candidates())` is the shape three
    refusal messages recommend and must stay served, while an `Exists` or
    `Subquery` *wrapping* the same queryset has no layer beneath it and is
    refused wherever it appears.

    An iterable operand is deliberately not iterated. `__in` values are
    consumed twice -- here and again by the SQL compiler -- and a generator
    handed to both would arrive at the second exhausted, which is the hazard
    `_predicate` materializes for.
    """
    stack = [value]
    while stack:
        node = stack.pop()
        if expressions_only and isinstance(node, models.QuerySet):
            continue
        query = getattr(node, "query", node)
        if getattr(query, "fieldseal_indexed", False) and not (
                bucket_only and getattr(query, "fieldseal_verify", True)):
            return query
        getter = getattr(node, "get_source_expressions", None)
        if getter is not None:
            stack.extend(getter())
    return None


class _Obligation:
    """One encrypted-column predicate that SQL matched approximately.

    Targets are normalized at `filter()` time rather than per row: the query
    value is normalized once, every candidate row once, and `exact` and `in`
    then share one membership test. The `Encrypted` field is resolved once
    here too, not per row in `matches`.
    """

    __slots__ = ("field", "lookup", "normalized", "raw", "normalizer")

    def __init__(self, field: Any, lookup: str, normalized: frozenset[bytes],
                 raw: frozenset[bytes], normalizer: str) -> None:
        self.field = field
        self.lookup = lookup
        self.normalized = normalized
        #: Targets whose *normalization was refused* -- a `bucket` column's
        #: unindexable values (docs/09 §7.2). They share one index marker, so
        #: SQL cannot separate them and only a raw comparison can.
        self.raw = raw
        self.normalizer = normalizer

    def matches(self, value: Any) -> bool:
        from .codec import to_bytes

        if value is None:
            # NULL never equals an indexed target. A NULL row can only reach
            # a verifying result set through a precise `IS NULL` predicate,
            # which records no obligation in the first place.
            return False
        as_bytes = to_bytes(self.field.inner, value)
        normalized = _normalize_or_none(self.normalizer, as_bytes)
        if normalized is None:
            return as_bytes in self.raw
        return normalized in self.normalized


def _normalize_or_none(normalizer: str, value: bytes) -> bytes | None:
    """`None` when the normalizer refuses -- a bucketed unindexable value."""
    from fieldseal import normalize
    from fieldseal.errors import InvalidArgument

    try:
        return normalize(normalizer, value)
    except InvalidArgument:
        return None


def resolve_path(model: Any, key: str) -> tuple[Any, str, bool]:
    """Resolve `key` to `(terminal field, lookup name, crossed a relation)`.

    `email__in` is `(email, "in", False)`; `patient__email` walks the
    relation (forward or reverse) and is `(email, "exact", True)`. A part
    that is not a field on the model reached so far ends the walk and names
    the lookup; an unresolvable first part (an annotation, `pk`) returns no
    field and the path is not ours to judge. Module-level because the system
    checks (E009, W005) walk `Meta.ordering` and admin declarations with the
    same rules -- a second walker that drifted would let a declaration
    through that the queryset refuses at runtime.
    """
    parts = key.split("__")
    field: Any = None
    traversed = False
    i = 0
    while i < len(parts):
        try:
            f = model._meta.get_field(parts[i])
        except Exception:  # noqa: BLE001 - FieldDoesNotExist and friends
            break
        field = f
        i += 1
        if f.is_relation and f.related_model is not None and i < len(parts):
            model = f.related_model
            traversed = True
            continue
        break
    lookup = parts[i] if i < len(parts) else "exact"
    return field, lookup, traversed


def iter_reference_names(item: Any) -> Any:
    """The column paths an ordering or annotation item refers to.

    A name string yields itself with any `-`/`+` ordering prefix stripped
    (`"?"` -- random order -- refers to nothing); an expression yields the
    name of every `F(...)` leaf in its tree, which covers `F("email")`,
    `F("email").asc()`, `Lower("email")`, `Sum("age")` and their nestings.
    """
    from django.db.models import F

    if isinstance(item, str):
        if item != "?":
            yield item.lstrip("-+")
        return
    stack = [item]
    while stack:
        node = stack.pop()
        if isinstance(node, F):
            yield node.name
            continue
        getter = getattr(node, "get_source_expressions", None)
        if getter is not None:
            stack.extend(getter())


class FieldsealQuerySet(models.QuerySet):  # type: ignore[misc]
    """A queryset that re-verifies blind-index candidates (spec §7.5)."""

    #: Declared only so `--strict` can see it. Django owns the attribute and
    #: sets it in its own `__init__`; a bare annotation creates no class
    #: attribute and shadows nothing at runtime.
    _result_cache: list[Any] | None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._fieldseal_obligations: tuple[_Obligation, ...] = ()
        self._fieldseal_verify = True
        self._fieldseal_indexed = False

    # -- cloning -----------------------------------------------------------
    #
    # Every chaining method funnels through `_clone`, so carrying the two
    # attributes here is what makes `filter(...).order_by(...)` keep its
    # obligations. Missing this is the failure that would return candidates
    # from any chained queryset while the unchained one verified.

    def _clone(self) -> FieldsealQuerySet:
        clone: FieldsealQuerySet = super()._clone()
        clone._fieldseal_obligations = self._fieldseal_obligations
        clone._fieldseal_verify = self._fieldseal_verify
        clone._fieldseal_indexed = self._fieldseal_indexed
        clone._mark_query()
        return clone

    def _mark_query(self) -> None:
        """Mirror the two flags onto `self.query`, where an *embedded* copy
        of this queryset can still be asked about them.

        `filter(x__in=qs)` hands Django the queryset and Django calls its
        `resolve_expression`; `Exists(qs)` and `Subquery(qs)` take `qs.query`
        in their constructor and never touch the queryset again, so a mark
        that lived only on the queryset would be invisible to every
        expression route. `Query.clone()` copies `__dict__`, so both marks
        survive the clone `Subquery.__init__` takes.
        """
        self.query.fieldseal_indexed = self._fieldseal_indexed
        self.query.fieldseal_verify = self._fieldseal_verify

    # -- the opt-out (docs/12 §3.2, decision C) ----------------------------

    def candidates(self) -> FieldsealQuerySet:
        """Return the raw index candidates, **unverified**.

        The escape hatch for callers who need SQL semantics -- pagination,
        `count()` pushed down, a `LIMIT` the database can honour. What comes
        back is a superset of the answer: spec §7.4 *mandates* collisions in a
        truncated index, so some rows will not hold the value asked for. The
        caller takes on §7.5.

        Every *verification* refusal below is lifted, including the
        filter-time `Q` under OR: the SQL semantics they refuse are exactly
        what this method hands over. Three families are not lifted, because
        there is nothing meaningful to accept:

        - **negation over an encrypted column** -- `exclude()`, a negated
          `Q`, and XOR, which is negation once expanded (G24, [#100], and
          spec §10.2). Bucket semantics are a coherent thing to accept for a
          filter, where they hand back *more* rows than the answer; they are
          not for an exclusion, where they hand back fewer and the missing
          ones are not recoverable from what came back. This method lifted
          it until G24 closed, and the `exclude()` message recommended it;
        - a **relation traversal** onto another model's encrypted column
          (refused at compile time for every queryset -- the opt-in there is
          the owning model's own `.candidates()`, embedded:
          `filter(rel__in=Owner.objects.filter(col=v).candidates())`);
        - the **G20 family** -- ordering, grouping, DISTINCT or aggregation
          over ciphertext -- where the database would be computing on bytes
          that carry no order or identity at all.
        """
        clone: FieldsealQuerySet = self._chain()
        clone._fieldseal_verify = False
        clone._mark_query()
        return clone

    @property
    def _verifying(self) -> bool:
        return bool(self._fieldseal_verify and self._fieldseal_obligations)

    @property
    def _bucketed(self) -> bool:
        """These rows are a §7.4 *bucket*, not the answer.

        The property an embedding position needs: `_verifying` says §7.5
        will run here, `_bucketed` says it will not and the rows are
        approximate. A `.candidates()` queryset that never touched a blind
        index is neither -- it is exact, and embedding it anywhere is fine.
        """
        return self._fieldseal_indexed and not self._fieldseal_verify

    # -- recording obligations --------------------------------------------

    def _filter_or_exclude(self, negate: bool, args: Any, kwargs: Any) -> Any:
        walked = self._encrypted_predicates(args, kwargs, negate)
        clone = super()._filter_or_exclude(negate, args, kwargs)
        found = [ob for ob in walked if isinstance(ob, _Obligation)]
        if found:
            clone._fieldseal_obligations = (*self._fieldseal_obligations, *found)
        if walked:
            # Every entry, obligation or `_BUCKETED` marker, means the blind
            # index answered a term here; `_bucketed` reads it back off the
            # `verify` flag.
            clone._fieldseal_indexed = True
            clone._mark_query()
        return clone

    def _encrypted_predicates(self, args: Any, kwargs: Any,
                              negate: bool) -> list[_Obligation | _Bucketed]:
        """Record what `_fetch_all` must re-verify -- and refuse what neither
        this queryset nor its caller could put right.

        On a `.candidates()` queryset nothing is recorded and every
        *verification* refusal is lifted: an escape hatch that refuses the
        same things is not one. **One family is not lifted (G24, [#100]):**
        an encrypted term in a subtractive position, where a wider index
        bucket yields a *narrower* result. The hatch hands over §7.5, and
        §7.5 is a filter obligation -- a caller handed a superset can reach
        the answer by dropping rows, a caller handed an exclusion cannot
        reach it at all, because the rows are not there. So the walk runs in
        both modes; `verifying` decides how much of it applies.
        """
        verifying = self._fieldseal_verify
        # `filter(Exists(qs))` is a positional *expression*, not a `Q`, so the
        # `Q` walk below never sees it, and `Exists` keeps `qs.query` rather
        # than the queryset, so `resolve_expression` never sees it either.
        # Measured before this call existed: served, unverified, in both
        # directions.
        self._refuse_embedded_index(args, kwargs, "exclude" if negate
                                    else "filter")
        out: list[_Obligation | _Bucketed] = []
        for key in list(kwargs):
            ob = self._predicate(key, kwargs, negate, verifying)
            if ob is not None:
                out.append(ob)
        for arg in args:
            # `exclude(Q(...))` enters the walk already negated on both
            # counts: verification cannot decide the row, and the row may not
            # be there to decide. The two are separate below.
            out.extend(self._q_obligations(
                arg, "negated" if negate else None,
                _NEGATED if negate else None, verifying))
        return out

    def _predicate(self, key: str, kwargs: dict[str, Any],
                   negate: bool,
                   verifying: bool) -> _Obligation | _Bucketed | None:
        """One keyword predicate: an obligation, a pass-through, or a raise.

        `kwargs` is taken whole rather than the value alone so that an
        `__in` iterable can be materialized *in place*: this method consumes
        it to build the obligation, and Django consumes it again to compile
        the SQL -- a generator handed to both would arrive at the second
        consumer exhausted.
        """
        from .fields import Encrypted

        field, lookup, traversed = self._resolve(key)
        value = kwargs[key]
        if negate:
            # Before the left-hand side is even known to be ours: the
            # operand can *be* a bucket without this predicate naming an
            # encrypted column at all (`exclude(pk__in=Owner.objects
            # .filter(enc=v).candidates())`).
            self._refuse_bucket_operand(f"exclude({key}=...)", value)
        if not isinstance(field, Encrypted):
            return None
        if lookup == "isnull" or (lookup == "exact" and value is None):
            # Served exactly by the envelope column (`IS [NOT] NULL`; Django
            # itself rewrites `exact=None` to `isnull`). No blind index is
            # touched, so there is no candidate set to verify and negation
            # loses nothing -- allowed in every combination.
            return None
        if negate:
            # Ahead of the traversal branch, and that ordering is the rule
            # rather than an accident: G24 scopes the refusal by *position*,
            # and a negated term is in one whoever owns the column. Checked
            # second, this fell through the `traversed` early return for
            # every path whose owner is the querying model -- a self-FK, an
            # MTI parent, `Patient.objects.candidates()
            # .exclude(visit__patient__email=v)` -- because the compile-time
            # backstop those rely on (`_refuse_cross_model`) passes there by
            # design. Measured before the reorder: served, collision row
            # dropped, nothing raised.
            self._refuse_subtractive(
                f"`exclude({key}=...)` is not available on an encrypted "
                "column.",
                self._bucket_absence(field, lookup, key),
            )
        if traversed:
            if verifying:
                self._refuse_traversal(key, field)
            # Not verifying: the lookup itself refuses this traversal on
            # every queryset it can (`_refuse_cross_model`), so leave the
            # message to the layer that owns it.
            return None
        if not verifying:
            # `.candidates()` has taken §7.5 off this queryset: nothing to
            # record, and every refusal below it is the caller's to accept.
            # The marker still goes back, because an embedding position has
            # to know these rows came out of a bucket.
            return _BUCKETED
        if lookup == "in":
            value = kwargs[key] = list(value)
        return self._obligation(field, lookup, value, key)

    def _resolve(self, key: str) -> tuple[Any, str, bool]:
        return resolve_path(self.model, key)

    def _refuse_traversal(self, key: str, field: Any) -> None:
        owner = field.model.__name__
        raise FieldsealNotSupported(
            f"`{key}` reaches the encrypted column {owner}.{field.name} "
            "through a relation. The join would match its blind-index "
            "sibling, but spec §7.5 re-verification runs on the queryset "
            "that owns the encrypted column -- this one materializes "
            f"{self.model.__name__} rows and cannot decrypt the related "
            "column (nor decide a reverse traversal, where one row may "
            "relate to many). Serving the join unverified is the spec §10.2 "
            f"wrong answer. Filter {owner} directly instead and join on the "
            f"result: embed bucket semantics with "
            f"filter(...__in={owner}_qs.candidates()), or materialize "
            "verified primary keys and use filter(...__pk__in=[...])."
        )

    def _bucket_absence(self, field: Any, lookup: str,
                        key: str) -> str | None:
        """Why this predicate reaches no §7.4 bucket at all, or None.

        Both refusals below justify themselves with bucket mechanics -- an
        exclusion drops the whole bucket, an `OR` branch leaves a candidate
        undecidable -- and both run before `_obligation`, which is where the
        column is checked for actually having one. On a column with no
        `BlindIndex`, or under a lookup spec §7.1 keeps off the index, those
        justifications describe a bucket that is not there, and the remedy
        they prescribe (the positive `filter()`) is refused on its own
        account. The ordering is not the bug and reversing it would trade
        this for a worse one -- a caller told to run a schema migration for
        a shape that is refused with the index too -- so the *message* is
        what carries the fact.
        """
        if field.index is None:
            # `field.model`, not `self.model`: `resolve_path` follows
            # relations, and this check deliberately runs *ahead* of the
            # traversal branch (the G24 reorder), so a traversed key reaches
            # here routinely. Named off the querying model,
            # `Visit.objects.exclude(patient__note=...)` reported
            # "Visit.note", which is not a column that exists -- the same
            # false-justification class this method was written to remove.
            # `_refuse_traversal` names the owner the same way.
            return (
                f"{field.model.__name__}.{field.name} declares no BlindIndex, "
                "so there is no index column to compare against and the "
                "randomized ciphertext matches nothing -- in either "
                "direction. Declaring one would not make this shape "
                "available either"
            )
        if lookup not in ("exact", "in"):
            return (
                f"spec §7.1 restricts a blind index to equality and "
                f"membership, so `{key}` reaches no index column at all. A "
                "lookup the index can serve would not make this shape "
                "available either"
            )
        return None

    def _refuse_subtractive(self, lead: str,
                            absent: str | None = None) -> None:
        """The one filter-time refusal `.candidates()` does not lift.

        Decided by G24 ([#100]) and normative in spec §10.2: the hatch hands
        the caller spec §7.5, and §7.5 is a *filter* obligation. Under
        `filter(...).candidates()` the caller holds a superset of the answer
        and can reach it by dropping rows; under an exclusion they hold a
        subset and cannot reach it at all, because the rows the database
        removed are not in what they were handed. Recommending the hatch for
        this shape -- which the `exclude()` message did until G24 closed --
        sends a caller following the error text onto semantics that differ
        in kind from the filter case, with nothing saying so.

        `absent` carries `_bucket_absence`'s answer: when the column has no
        bucket for this predicate, the paragraph below would be describing
        one that does not exist, so the refusal states the real reason
        first and keeps the G24 rule as the second half -- which is what
        stops the caller migrating for nothing.
        """
        if absent is not None:
            raise FieldsealNotSupported(
                f"{lead.rstrip('.')}: {absent}: an encrypted column in a "
                "subtractive position is refused over a blind index too, "
                "because the SQL excludes the whole §7.4 bucket and the "
                "rows it should have kept never reach the adapter for spec "
                "§7.5 re-verification to put back (spec §10.2, G24 "
                f"[#100]).{_NO_BUCKET_TAIL}"
            )
        raise FieldsealNotSupported(
            f"{lead} The SQL excludes the whole index bucket, and spec §7.4 "
            "mandates that the bucket holds rows whose value differs -- so "
            "the query drops rows it should have kept, and they never reach "
            "the adapter for §7.5 re-verification to put back. A filter's "
            "false positives are recoverable; an exclusion's false negatives "
            "are not. Fetch the matches with a positive filter() and exclude "
            "their primary keys. .candidates() does not lift this: it hands "
            "over §7.5, and no operation on an exclusion's own result "
            "restores a row the database already removed (spec §10.2, G24 "
            "[#100])."
        )

    def _refuse_bucket_operand(self, at: str, value: Any) -> None:
        """Refuse a §7.4 bucket used as the *operand* of a subtractive term.

        G24 scopes the refusal by position, and a subquery occupies one
        without the outer predicate naming an encrypted column:
        `exclude(pk__in=Patient.objects.filter(email=v).candidates())`
        subtracts the whole bucket, so the colliding rows §7.4 mandates are
        removed from the answer and are not among the ones the caller was
        handed. Measured before this refusal existed, on all of
        `exclude(pk__in=...)`, `exclude(rel__in=...)`, `filter(~Q(...))` and
        `difference(...)`: served, collision row dropped, nothing raised.

        It cannot live in `resolve_expression`, which is where the same
        embedding is otherwise caught: that method is handed the operand and
        not the position, so it cannot tell this from
        `filter(...__in=qs.candidates())` -- the shape three refusal
        messages recommend.
        """
        if _embedded_index_query(value, bucket_only=True) is None:
            return
        self._refuse_subtractive(
            f"`{at}` subtracts a queryset whose rows a blind index selected "
            "(`.candidates()`)."
        )

    def _q_obligations(self, node: Any, reason: str | None,
                       subtractive: str | None,
                       verifying: bool) -> list[_Obligation | _Bucketed]:
        """Walk a `Q`: a plain AND of positive terms records obligations
        exactly like keyword arguments; anything else refuses.

        Under OR (or negation), a candidate row may have been returned
        because the *other* branch matched, so dropping it on a failed
        encrypted-column check would remove a legitimate result --
        verification would have to evaluate the whole predicate in Python to
        be correct, which is a different and much larger feature. Under a
        pure AND every returned row must satisfy the encrypted term too, so
        per-term verification is exact. `reason` carries why an enclosing
        context is already unverifiable; it poisons everything beneath it.

        `subtractive` is tracked *separately* rather than read off `reason`,
        and for a reason the shapes make concrete: under
        `filter(Q(a=1) | ~Q(enc=v))` the enclosing OR sets `reason` first and
        poisons the subtree, so the inner negation would never be seen if the
        two shared one slot -- and that is the shape `.candidates()` must
        still refuse (G24, [#100]). One is "verification cannot decide this
        row"; the other is "the row is not here to decide".
        """
        from django.db.models import Q

        from .fields import Encrypted

        if not isinstance(node, Q):
            return []
        if node.negated:
            subtractive = subtractive or _NEGATED
            reason = reason or "negated"
        elif node.connector == Q.XOR:
            subtractive = subtractive or _XOR
            reason = reason or "XOR-combined"
        elif node.connector != Q.AND:
            reason = reason or f"{node.connector}-combined"
        out: list[_Obligation | _Bucketed] = []
        for i, child in enumerate(node.children):
            if isinstance(child, Q):
                out.extend(
                    self._q_obligations(child, reason, subtractive, verifying))
                continue
            if not isinstance(child, (tuple, list)) or len(child) != 2:
                # An expression child (`Q(Exists(qs))`), which carries the
                # same subquery hazard as a positional one.
                self._refuse_embedded_index((child,), {}, "filter")
                continue
            key, value = str(child[0]), child[1]
            if subtractive is not None:
                self._refuse_bucket_operand(f"Q({key}=...)", value)
            field, lookup, traversed = self._resolve(key)
            if not isinstance(field, Encrypted):
                continue
            if lookup == "isnull" or (lookup == "exact" and value is None):
                continue  # precise on the envelope column; see _predicate
            if subtractive is not None:
                # Ahead of `traversed`, for the reason `_predicate` gives at
                # length: the position is the rule, not who owns the column.
                self._refuse_subtractive(
                    f"`Q({key}=...)` reaches an encrypted column through "
                    f"{subtractive}.",
                    self._bucket_absence(field, lookup, key),
                )
            if traversed:
                if verifying:
                    self._refuse_traversal(key, field)
                continue  # see `_predicate`: the lookup layer owns this one
            if not verifying:
                out.append(_BUCKETED)
                continue
            if reason is not None:
                absent = self._bucket_absence(field, lookup, key)
                if absent is not None:
                    # Same correction as the subtractive one: "a candidate
                    # row may be present" describes a candidate set this
                    # column does not have, and splitting the term into its
                    # own filter() -- the remedy below -- is refused too.
                    raise FieldsealNotSupported(
                        f"`Q({key}=...)` reaches an encrypted column through "
                        f"an {reason.split('-')[0]} combination: {absent}: an "
                        "encrypted column under a combination spec §7.5 "
                        "cannot decide row by row is refused over a blind "
                        f"index too.{_NO_BUCKET_TAIL}"
                    )
                raise FieldsealNotSupported(
                    f"`Q({key}=...)` reaches an encrypted column through an "
                    f"{reason.split('-')[0]} combination. A candidate row may "
                    "be present because another branch matched, so spec §7.5 "
                    "re-verification cannot decide it without evaluating the "
                    "whole predicate in Python. Split the encrypted term "
                    "into its own filter() call, or use .candidates() and "
                    "take on §7.5 yourself."
                )
            if lookup == "in":
                # Materialized for the same double-consumption reason as in
                # `_predicate`; replacing the child also leaves the caller's
                # Q reusable where a generator would have made it single-use.
                value = list(value)
                node.children[i] = (key, value)
            out.append(self._obligation(field, lookup, value, key))
        return out

    def _obligation(self, field: Any, lookup: str, value: Any,
                    key: str) -> _Obligation:
        from .codec import to_bytes

        decl = field.index
        if decl is None:
            raise FieldsealNotSupported(
                f"`{key}` is not available: {self.model.__name__}."
                f"{field.name} declares no BlindIndex, so there is no index "
                "column to match against and the ciphertext is randomized -- "
                "a direct comparison matches nothing. Declare a BlindIndex "
                "and backfill, or filter in Python after fetching."
            )
        if lookup not in ("exact", "in"):
            raise FieldsealNotSupported(
                f"`{key}` is not available on an encrypted column: spec §7.1 "
                "restricts a blind index to equality and membership."
            )
        if lookup == "in":
            # SQL `IN` never matches NULL, and the compiled lookup drops None
            # the same way -- so a None target is dropped here too, not
            # tracked: no NULL row can arrive to be matched against it.
            targets = [v for v in value if v is not None]
        else:
            targets = [value]
        if lookup == "in" and not targets:
            # `__in=[]` matches nothing in SQL and must keep doing so.
            return _Obligation(field, lookup, frozenset(), frozenset(),
                               decl.normalize)
        normalized: set[bytes] = set()
        raw: set[bytes] = set()
        for v in targets:
            as_bytes = to_bytes(field.inner, v)
            n = _normalize_or_none(decl.normalize, as_bytes)
            if n is None:
                raw.add(as_bytes)
            else:
                normalized.add(n)
        return _Obligation(field, lookup, frozenset(normalized),
                           frozenset(raw), decl.normalize)

    # -- verification ------------------------------------------------------

    def _fetch_all(self) -> None:
        """Django's `_fetch_all`, with the §7.5 filter between materialization
        and prefetch.

        This mirrors `QuerySet._fetch_all` rather than calling it, so that
        candidates are dropped **before** `_prefetch_related_objects` runs and
        related objects are not fetched for rows that are about to be
        discarded. `tests/test_query_private_api.py` asserts the mirrored
        body still matches Django's, so an upstream change fails the build.
        """
        if self._result_cache is None:
            rows: list[Any] = list(self._iterable_class(self))
            if self._verifying:
                rows = [row for row in rows if self._matches(row)]
            self._result_cache = rows
        if self._prefetch_related_lookups and not self._prefetch_done:
            self._prefetch_related_objects()

    def _matches(self, row: Any) -> bool:
        for ob in self._fieldseal_obligations:
            if not ob.matches(getattr(row, ob.field.attname, None)):
                return False
        return True

    # -- methods that would otherwise answer about candidates --------------

    def count(self) -> int:
        """Correct rather than cheap.

        `QuerySet.count()` issues `SELECT COUNT(*)`, which counts the index
        bucket. Materializing and verifying is the only correct answer, and
        the cost is bounded by the bucket: spec §7.4 sizes the truncation so
        that `2 ≤ P·2^−b < √P`, so an equality lookup fetches a small multiple
        of its true match count by design. A hot value in a skewed column is
        the bad case, which is what §7.6's cardinality gate is for.
        """
        if self._verifying:
            return len(self)
        count: int = super().count()
        return count

    def exists(self) -> bool:
        """Short-circuits: the first verified match ends the scan."""
        if not self._verifying:
            exists: bool = super().exists()
            return exists
        cached = self._result_cache
        if cached is not None:
            return bool(cached)
        for row in self._iterable_class(self):
            if self._matches(row):
                return True
        return False

    def get(self, *args: Any, **kwargs: Any) -> Any:
        """Django's `get()`, without the candidate-sampling LIMIT.

        `QuerySet.get()` applies `LIMIT MAX_GET_RESULTS` (21) before
        materializing -- a window over the *candidate* rows, so a §7.4 bucket
        larger than the window can hold the true match beyond it and `get()`
        would raise `DoesNotExist` about a row that exists. Verified `get()`
        materializes the whole bucket instead; the cost bound is §7.4's, the
        same one `count()` relies on. `tests/test_query_private_api.py` pins
        that the limit is still why this override exists.
        """
        clone = self.filter(*args, **kwargs) if args or kwargs else self._chain()
        if not clone._verifying:
            return super().get(*args, **kwargs)
        if clone.query.can_filter() and not clone.query.distinct_fields:
            clone = clone.order_by()
        num = len(clone)
        if num == 1:
            cached = clone._result_cache
            assert cached is not None  # len() just materialized it
            return cached[0]
        if not num:
            raise self.model.DoesNotExist(
                f"{self.model._meta.object_name} matching query does not "
                "exist."
            )
        raise self.model.MultipleObjectsReturned(
            f"get() returned more than one {self.model._meta.object_name} "
            f"-- it returned {num}!"
        )

    def first(self) -> Any:
        return self._first_verified(reverse=False)

    def last(self) -> Any:
        return self._first_verified(reverse=True)

    def _first_verified(self, *, reverse: bool) -> Any:
        """`first()`/`last()` without slicing.

        Django implements both as `queryset[:1]`, which applies `LIMIT 1`
        before verification -- so a single colliding candidate makes `first()`
        return `None` while a match sits in the next row. Ordering is applied
        the way Django applies it and the scan stops at the first verified
        row.
        """
        if not self._verifying:
            return super().last() if reverse else super().first()
        qs = self
        if not self.ordered and self.query.default_ordering:
            qs = self.order_by("-pk" if reverse else "pk")
        elif reverse:
            qs = self.reverse()
        cached = qs._result_cache
        if cached is not None:
            return cached[0] if cached else None
        for row in qs._iterable_class(qs):
            if qs._matches(row):
                return row
        return None

    def iterator(self, chunk_size: int | None = None) -> Any:
        """Streaming, minus the rows §7.5 drops.

        Django's `iterator()` deliberately bypasses `_fetch_all` (that is its
        point: no result cache), so without this override it would stream
        unverified candidates -- the one read path left doing so. The stream
        stays a stream; failing rows are dropped as they pass.
        """
        rows = super().iterator(chunk_size=chunk_size)
        if not self._verifying:
            return rows
        return (row for row in rows if self._matches(row))

    async def aiterator(self, chunk_size: int = 2000) -> AsyncIterator[Any]:
        """`aiterator()` is the one async method not delegating to its sync
        twin (`aget`, `afirst`, `acount`... all wrap the overrides above), so
        it gets the same treatment as `iterator()` directly."""
        async for row in super().aiterator(chunk_size=chunk_size):
            if not self._verifying or self._matches(row):
                yield row

    # -- refusals ----------------------------------------------------------

    def __getitem__(self, k: Any) -> Any:
        if (self._verifying and self._result_cache is None
                and isinstance(k, (int, slice))):
            raise FieldsealNotSupported(
                "Indexing or slicing a queryset filtered on an encrypted "
                "column is not available. Both compile to LIMIT/OFFSET, "
                "which the database applies before spec §7.5 "
                "re-verification drops collision rows -- so the page comes "
                "back short, the next page starts in the wrong place, and "
                "qs[0] can miss a match sitting behind a collision (the "
                "failure first() exists to avoid). Spec §7.5 states outright "
                "that pagination built directly on an indexed encrypted "
                "column is incorrect; the documented pattern is over-fetch → "
                "decrypt → filter → paginate: use .candidates() and paginate "
                "that yourself, or materialize with list(qs) and index in "
                "Python."
            )
        return super().__getitem__(k)

    def _refuse_sql_answered(self, method: str) -> None:
        raise FieldsealNotSupported(
            f"`{method}()` is not available on a queryset filtered by an "
            "encrypted column. It is answered by the database, which matched "
            "the index bucket -- and spec §7.4 mandates that the bucket holds "
            "rows whose value differs, so the statement would "
            + ("count rows that do not match."
               if method == "aggregate" else
               f"{method} rows that do not match.")
            + " Materialize the verified rows first and act on their primary "
            "keys, or use .candidates() if bucket semantics are what you want."
        )

    def aggregate(self, *args: Any, **kwargs: Any) -> Any:
        if self._verifying:
            self._refuse_sql_answered("aggregate")
        for expr in (*args, *kwargs.values()):
            self._check_computed_expression(expr, "aggregate")
        return super().aggregate(*args, **kwargs)

    def update(self, **kwargs: Any) -> int:
        if self._verifying:
            self._refuse_sql_answered("update")
        updated: int = super().update(**kwargs)
        return updated

    def delete(self) -> Any:
        if self._verifying:
            self._refuse_sql_answered("delete")
        return super().delete()

    def earliest(self, *fields: Any) -> Any:
        if self._verifying:
            self._refuse_limit_one("earliest")
        self._refuse_encrypted_get_latest("earliest", fields)
        return super().earliest(*fields)

    def latest(self, *fields: Any) -> Any:
        if self._verifying:
            self._refuse_limit_one("latest")
        self._refuse_encrypted_get_latest("latest", fields)
        return super().latest(*fields)

    def _refuse_limit_one(self, method: str) -> None:
        raise FieldsealNotSupported(
            f"`{method}()` is not available on a queryset filtered by an "
            "encrypted column: it is LIMIT 1 applied by the database before "
            "spec §7.5 re-verification drops collision rows -- the same "
            "failure first() exists to avoid, behind a different name. Use "
            ".order_by(field).first() (or .last()), which scan verified "
            "rows, or .candidates() for bucket semantics."
        )

    # -- ordering, grouping and computation over ciphertext (G20, #80) -----
    #
    # A different refusal family from the ones above. Those protect §7.5
    # re-verification, apply only while `_verifying`, and are lifted by
    # `.candidates()`. These refuse SQL that *reads envelope bytes* --
    # sorting, grouping, deduplicating, byte-reading aggregation -- which is
    # meaningless on every queryset, obligations or none, and
    # `.candidates()` does not lift them: bucket semantics are a meaningful
    # thing to accept for a filter; ciphertext order has no semantics to
    # accept. Measured before the refusals were written: MIN() over
    # ciphertext returns whichever envelope sorts first (decrypted cleanly,
    # presented as the minimum), GROUP BY returns one group per row under
    # keys that print identically, ORDER BY produces a stable-looking order
    # with no meaning. Plain non-distinct Count(field) reads no bytes and is
    # exempt (G23) -- see _is_exempt_plain_count.

    def order_by(self, *field_names: Any) -> Any:
        """Refuses ordering that would sort envelope bytes.

        Spec §7.10 lists ORDER BY over ciphertext as unsupported; §10.2
        requires refusing over degrading. The index *sibling* stays
        orderable -- deterministic, documented as meaningless, occasionally
        useful as a stable tiebreaker. What this method cannot see is
        `Meta.ordering`, which the SQL compiler applies directly without
        calling it -- system check E009 covers the declaration.
        """
        for item in field_names:
            hit = self._encrypted_ref(item)
            if hit is not None:
                self._refuse_ciphertext_order(hit, "order_by")
            cond = self._encrypted_condition_ref(item)
            if cond is not None:
                self._refuse_ungoverned_condition(cond, "order_by")
        return super().order_by(*field_names)

    def distinct(self, *field_names: Any) -> Any:
        for item in field_names:
            hit = self._encrypted_ref(item)
            if hit is not None:
                self._refuse_distinct_over_ciphertext(hit[1])
        if not field_names:
            name = self._encrypted_values_select()
            if name is not None:
                self._refuse_distinct_over_ciphertext(name)
        return super().distinct(*field_names)

    def annotate(self, *args: Any, **kwargs: Any) -> Any:
        self._refuse_ciphertext_computation(args, kwargs, "annotate")
        self._refuse_embedded_index(args, kwargs, "annotate")
        return super().annotate(*args, **kwargs)

    def alias(self, *args: Any, **kwargs: Any) -> Any:
        self._refuse_ciphertext_computation(args, kwargs, "alias")
        self._refuse_embedded_index(args, kwargs, "alias")
        return super().alias(*args, **kwargs)

    def _refuse_embedded_index(self, args: Any, kwargs: Any,
                               method: str) -> None:
        """Refuse `Exists(qs)` / `Subquery(qs)` over a blind-index queryset.

        `resolve_expression` catches the embedding on the one route where
        Django resolves the *queryset* (`filter(pk__in=qs)`). `Exists` and
        `Subquery` take `qs.query` in their constructor and never call it,
        so every expression route reached SQL unrefused in both directions --
        as an annotation, as a positional `filter()`/`exclude()` argument, as
        an expression child of a `Q`, and as a keyword operand.
        Measured before this walk existed:
        `annotate(has=Exists(Patient.objects.filter(email=v)))
        .filter(has=True)` served bucket matches as answers with no
        obligation recorded anywhere, and the `.candidates()` form under
        `.filter(has=False)` dropped the collision row -- G24's shape,
        arriving through an annotation.

        Refused in both directions rather than only the subtractive one,
        because an alias carries no position: `filter(has=True)` and
        `filter(has=False)` are the same annotation and this method cannot
        see which is coming. So the remedy it names is the one that is right
        either way -- materialize the verified rows and pass their primary
        keys. Per spec §10.2 it does not point at `.candidates()`, which
        would be the wrong answer for half the callers who followed it.
        """
        for expr in (*args, *kwargs.values()):
            query = _embedded_index_query(expr, expressions_only=True)
            if query is None:
                continue
            raise FieldsealNotSupported(
                f"`{method}()` embeds a queryset filtered by an encrypted "
                "column as a subquery (Exists, Subquery). The subquery runs "
                "entirely in the database, where spec §7.5 re-verification "
                "cannot run, so the annotation would be computed from "
                "unverified index candidates -- and the alias is then "
                "usable in a subtractive position (`filter(alias=False)`), "
                "where the §7.4 bucket removes rows that belong in the "
                "answer and nothing can put them back (spec §10.2, G24 "
                "[#100]). Materialize the verified rows first and annotate "
                "from their primary keys "
                "(Exists(Model.objects.filter(pk__in=[o.pk for o in qs])))."
            )

    def _refuse_ciphertext_computation(self, args: Any, kwargs: Any,
                                       method: str) -> None:
        """Two hazards: an expression computing over an encrypted column,
        and an aggregate grouping by one (`values("email").annotate(...)`
        makes the values projection the GROUP BY)."""
        from django.db.models import F

        exprs = [*args, *kwargs.values()]
        for expr in exprs:
            if isinstance(expr, F):
                # A bare column reference only selects the column, and the
                # converter decrypts what comes back -- exact, so allowed.
                continue
            self._check_computed_expression(expr, method)
        if any(getattr(e, "contains_aggregate", False) for e in exprs):
            name = self._encrypted_values_select()
            if name is not None:
                self._refuse_ciphertext_grouping(name, method)

    def _refuse_projection_hazards(self, method: str,
                                   items: tuple[Any, ...]) -> None:
        """values()/values_list() hazards beyond projection itself.

        The projection alone is legitimate: the column comes back and the
        converter decrypts it. Refused here are (a) an expression argument
        that computes over the ciphertext, and (b) a projection under
        DISTINCT, where dedup runs on envelope bytes and removes nothing.
        """
        from django.db.models import F

        from .fields import Encrypted

        for item in items:
            if not isinstance(item, (str, F)):
                self._check_computed_expression(item, method)
        if not self.query.distinct:
            return
        names = [i for i in items if isinstance(i, str)]
        names += [i.name for i in items if isinstance(i, F)]
        if not items:
            names = [f.name for f in self.model._meta.concrete_fields]
        for name in names:
            field, _, _ = resolve_path(self.model, name)
            if isinstance(field, Encrypted):
                self._refuse_distinct_over_ciphertext(name)

    def _check_computed_expression(self, expr: Any, method: str) -> None:
        """The three hazards a computed expression can carry, most specific
        refusal first: reading envelope bytes; an encrypted column inside a
        condition the queryset's filter path never sees (an aggregate's
        `filter=`, a `When.condition`); and a `filter=` on the otherwise
        served plain count."""
        hit = self._encrypted_ref(expr)
        if hit is not None and not self._is_plain_count_shape(expr):
            self._refuse_ciphertext_compute(hit, method)
        cond = self._encrypted_condition_ref(expr)
        if cond is not None:
            self._refuse_ungoverned_condition(cond, method)
        if hit is not None and getattr(expr, "filter", None) is not None:
            self._refuse_filtered_count(hit, method)

    def _is_plain_count_shape(self, expr: Any) -> bool:
        """The G23 carve-out ([#89]): a plain, non-distinct COUNT of a bare
        column reads null-ness, never envelope bytes, and the spec §10.2
        NULL-preservation invariant makes it exact -- a value is stored as
        a non-NULL envelope and NULL stays NULL, so `COUNT(col)` over
        envelopes equals `COUNT(col)` over the plaintexts.

        Deliberately the bare shape only. `distinct=True` compares envelopes
        and counts rows; `Count(Length(...))` reads bytes through the inner
        function -- both fall back to the bytes refusal. A `filter=` is
        judged separately by `_check_computed_expression`, so its refusal can
        state its own (different) reason instead of a false bytes claim.
        """
        from django.db.models import Count, F

        if not isinstance(expr, Count) or getattr(expr, "distinct", False):
            return False
        sources = expr.get_source_expressions()
        if not sources or not isinstance(sources[0], F):
            return False
        return all(self._encrypted_ref(s) is None for s in sources[1:])

    def _encrypted_condition_ref(self, expr: Any) -> tuple[Any, str] | None:
        """The `(Encrypted field, path)` referenced inside a condition the
        queryset's filter path never sees, or None.

        An aggregate's `filter=` and a `When.condition` hold a `Q` that is
        resolved when the *expression* compiles, not when `.filter()` runs --
        so the lookup arrives without the §7.5 obligations and refusals this
        queryset attaches. Measured before this walk existed: an equality
        there compiled to an index-bucket match and was served unverified --
        `Count("created", filter=Q(email=...))` returned bucket counts and a
        `When(email=...)` branch fired on a bucket match, both silently.
        `iter_reference_names` cannot see any of it, because a `Q` is a tree
        of `(path, value)` tuples, not an expression.
        """
        from django.db.models import Q

        from .fields import Encrypted

        stack = [expr]
        conditions: list[Any] = []
        while stack:
            node = stack.pop()
            for attr in ("filter", "condition"):
                q = getattr(node, attr, None)
                if isinstance(q, Q):
                    conditions.append(q)
            getter = getattr(node, "get_source_expressions", None)
            if getter is not None:
                stack.extend(getter())
        while conditions:
            q = conditions.pop()
            for child in q.children:
                if isinstance(child, type(q)):
                    conditions.append(child)
                elif isinstance(child, tuple) and len(child) == 2:
                    field, _, _ = resolve_path(self.model, str(child[0]))
                    if isinstance(field, Encrypted):
                        return field, str(child[0])
                else:
                    hit = self._encrypted_ref(child)
                    if hit is not None:
                        return hit
        return None

    def _refuse_ungoverned_condition(self, hit: tuple[Any, str],
                                     method: str) -> None:
        field, name = hit
        raise FieldsealNotSupported(
            f"`{method}()` places a condition on the encrypted column "
            f"{field.model.__name__}.{field.name} inside an aggregate "
            "`filter=` or a `When(...)`. Conditions there are resolved when "
            "the expression compiles, outside the queryset's filter path "
            "where this adapter attaches its refusals and spec §7.5 "
            "obligations -- an equality here compiles to an index-bucket "
            "match that is never re-verified, so the database counts or "
            "branches on §7.4 collisions as if they were matches, silently. "
            "Measured, not hypothetical: before this refusal, "
            "Count(..., filter=Q(email=...)) returned bucket counts with "
            "nothing raised. Put the condition on the queryset "
            "(.filter(...)), where every lookup gets its governed treatment."
        )

    def _refuse_filtered_count(self, hit: tuple[Any, str],
                               method: str) -> None:
        field, name = hit
        raise FieldsealNotSupported(
            f"`{method}()` refuses Count({name!r}, filter=...). The count "
            "itself reads only null-ness and is served bare (spec §7.10's "
            "non-null-count row), but §10.2's carve-out is the plain shape "
            "only, and a `filter=` condition lives outside the queryset's "
            "governed filter path. Apply the condition to the queryset and "
            "count the bare column -- "
            f".filter(<condition>).aggregate(n=Count({name!r})) is the same "
            "count -- or materialize and count in Python."
        )

    def _encrypted_ref(self, item: Any) -> tuple[Any, str] | None:
        """The `(Encrypted field, path)` an ordering or expression item
        references, or None."""
        from .fields import Encrypted

        for name in iter_reference_names(item):
            field, _, _ = resolve_path(self.model, name)
            if isinstance(field, Encrypted):
                return field, name
        return None

    def _encrypted_values_select(self) -> str | None:
        from .fields import Encrypted

        for name in getattr(self.query, "values_select", ()) or ():
            field, _, _ = resolve_path(self.model, str(name))
            if isinstance(field, Encrypted):
                return str(name)
        return None

    def _refuse_encrypted_get_latest(self, method: str,
                                     fields: tuple[Any, ...]) -> None:
        names: tuple[Any, ...] = fields
        if not names:
            latest_by = getattr(self.model._meta, "get_latest_by", None)
            if not latest_by:
                return
            names = (tuple(latest_by)
                     if isinstance(latest_by, (list, tuple))
                     else (latest_by,))
        for item in names:
            hit = self._encrypted_ref(item)
            if hit is not None:
                self._refuse_ciphertext_order(hit, method)
            cond = self._encrypted_condition_ref(item)
            if cond is not None:
                self._refuse_ungoverned_condition(cond, method)

    def _refuse_ciphertext_order(self, hit: tuple[Any, str],
                                 method: str) -> None:
        field, name = hit
        raise FieldsealNotSupported(
            f"`{method}({name!r})` is not available: "
            f"{field.model.__name__}.{field.name} stores a randomized "
            "envelope, so the database would sort by envelope bytes -- an "
            "order that is stable per row and means nothing, which is worse "
            "than failing because it looks deliberate. Spec §7.10 lists "
            "ORDER BY over ciphertext as unsupported; §10.2 requires "
            "refusing over degrading (G20). Materialize and sort in Python "
            "after decryption -- sorted(qs, key=...) -- order by a "
            "plaintext column, or order by the index sibling for a "
            "deterministic (and documented meaningless) tiebreaker."
        )

    def _refuse_ciphertext_compute(self, hit: tuple[Any, str],
                                   method: str) -> None:
        field, name = hit
        raise FieldsealNotSupported(
            f"`{method}()` references the encrypted column "
            f"{field.model.__name__}.{field.name} inside an expression that "
            "reads envelope bytes. Measured, not hypothetical: MIN() "
            "returns whichever envelope sorts first -- it decrypts cleanly "
            "and is presented as the minimum -- SUM() produces garbage the "
            "read path then misreports as NOT_CIPHERTEXT, COUNT(DISTINCT) "
            "counts envelopes rather than values, LENGTH() reports "
            "ciphertext size. Materialize the rows and compute in Python "
            "after decryption. (A plain, non-distinct "
            f"Count({name!r}) is served -- it reads null-ness, not bytes, "
            "and spec §7.10's non-null-count row makes it exact under the "
            "NULL-preservation invariant.)"
        )

    def _refuse_ciphertext_grouping(self, name: str, method: str) -> None:
        raise FieldsealNotSupported(
            f"`{method}()` would GROUP BY the encrypted column {name!r}, "
            "which is in this queryset's values() projection: every "
            "randomized envelope is its own group, so the aggregates come "
            "back wrong -- one group per row -- under group keys that "
            "decrypt and print identically. Group in Python after "
            "decryption (sort the decrypted values, then "
            "itertools.groupby), or group by a plaintext column."
        )

    def _refuse_distinct_over_ciphertext(self, name: str) -> None:
        raise FieldsealNotSupported(
            f"`distinct()` over the encrypted column {name!r} deduplicates "
            "nothing: a randomized suite writes a different envelope for "
            "every row, so each one is already distinct and rows holding "
            "the same value come back as duplicates -- silently. "
            "Deduplicate in Python after decryption, or apply distinct() "
            "to a plaintext projection."
        )

    def resolve_expression(self, *args: Any, **kwargs: Any) -> Any:
        """Refuses embedding as a subquery (`__in=qs`, `Subquery`, `Exists`).

        A subquery runs entirely inside the database, where §7.5
        re-verification cannot run, so it would hand the outer query
        unverified index candidates -- silently, since the outer query has no
        idea its operand was approximate.
        """
        if self._verifying:
            raise FieldsealNotSupported(
                "A queryset filtered by an encrypted column cannot be "
                "embedded as a subquery (`__in=qs`, Subquery, Exists): the "
                "subquery runs entirely in the database, where spec §7.5 "
                "re-verification cannot run, so the outer query would "
                "receive unverified index candidates. Materialize the "
                "verified rows first and pass their primary keys "
                "(filter(x__pk__in=[obj.pk for obj in qs])), or embed "
                "qs.candidates() in a positive filter() to accept bucket "
                "semantics -- a subtractive position is refused there too "
                "(spec §10.2, G24 [#100])."
            )
        return super().resolve_expression(*args, **kwargs)

    def _combinator_query(self, combinator: str, *other_qs: Any,
                          all: bool = False) -> Any:
        """Refuses `union`/`intersection`/`difference` on either side.

        The combined statement runs entirely in the database; the encrypted
        side contributes unverified candidates, and this queryset's
        obligations cannot be applied to rows the *other* side contributed --
        an AND-composition argument that only holds within one WHERE clause.
        Checked across every operand because `plain.union(verified)` embeds
        the verified side's SQL just as surely as `verified.union(plain)`.
        (`tests/test_query_private_api.py` pins that the three public methods
        still funnel through here.)

        `.candidates()` lifts this for `union` and `intersection` and not
        for `difference`, which is G24's rule applied to set operators
        rather than a second one: widen the bucket and a union or an
        intersection returns *more* rows, which §7.5 trims, while a
        difference returns fewer and the missing ones are not in the result
        to be put back.
        """
        for qs in (self, *other_qs):
            if isinstance(qs, FieldsealQuerySet) and qs._verifying:
                raise FieldsealNotSupported(
                    f"`{combinator}()` is not available with a queryset "
                    "filtered by an encrypted column: the combined statement "
                    "is answered by the database, so the encrypted side "
                    "would contribute unverified index candidates that spec "
                    "§7.5 re-verification never sees. Materialize the "
                    "verified rows first (list(qs)) and combine in Python, "
                    "or combine .candidates() and take on §7.5 yourself -- "
                    "union() and intersection() only, since difference() "
                    "subtracts the bucket rather than widening it."
                )
        if combinator == "difference":
            for qs in other_qs:
                if isinstance(qs, FieldsealQuerySet) and qs._bucketed:
                    self._refuse_subtractive(
                        "`difference()` subtracts a queryset whose rows a "
                        "blind index selected (`.candidates()`)."
                    )
        return super()._combinator_query(combinator, *other_qs, all=all)

    def _refuse_projection(self, method: str) -> None:
        raise FieldsealNotSupported(
            f"`{method}()` is not available on a queryset filtered by an "
            "encrypted column. Spec §7.5 re-verification needs the encrypted "
            "column's decrypted value for every candidate row, and this "
            "projection decides which columns come back -- so verification "
            "would be running against rows it cannot check. Materialize the "
            f"verified rows first and project in Python, or call {method}() "
            "on .candidates() and take on §7.5 yourself."
        )

    def values(self, *fields: Any, **expressions: Any) -> Any:
        if self._verifying:
            self._refuse_projection("values")
        self._refuse_projection_hazards(
            "values", (*fields, *expressions.values()))
        return super().values(*fields, **expressions)

    def values_list(self, *fields: Any, **kwargs: Any) -> Any:
        if self._verifying:
            self._refuse_projection("values_list")
        self._refuse_projection_hazards("values_list", fields)
        return super().values_list(*fields, **kwargs)

    def only(self, *fields: Any) -> Any:
        if self._verifying:
            self._refuse_projection("only")
        return super().only(*fields)

    def defer(self, *fields: Any) -> Any:
        if self._verifying:
            self._refuse_projection("defer")
        return super().defer(*fields)


class FieldsealManager(models.Manager.from_queryset(FieldsealQuerySet)):  # type: ignore[misc]
    """The manager a model with an indexed encrypted column must use.

    Installed automatically when the model declares no manager of its own
    (see `apps.install_managers`); required by system check **E008** when it
    does, because the adapter must not silently replace a manager somebody
    wrote on purpose.
    """
