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

**What re-verification compares** is G19 ([#78]): `normalize(stored)` against
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
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from django.db import models

from .errors import FieldsealNotSupported


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
        return clone

    # -- the opt-out (docs/12 §3.2, decision C) ----------------------------

    def candidates(self) -> FieldsealQuerySet:
        """Return the raw index candidates, **unverified**.

        The escape hatch for callers who need SQL semantics -- pagination,
        `count()` pushed down, a `LIMIT` the database can honour. What comes
        back is a superset of the answer: spec §7.4 *mandates* collisions in a
        truncated index, so some rows will not hold the value asked for. The
        caller takes on §7.5.

        Every refusal below is lifted, including the filter-time ones
        (`exclude`, `Q` under OR or negation): the SQL semantics they refuse
        are exactly what this method hands over. The one thing it cannot lift
        is a relation traversal onto another model's encrypted column, which
        is refused at compile time for every queryset -- the opt-in there is
        the owning model's own `.candidates()`, embedded:
        `filter(rel__in=Owner.objects.filter(col=v).candidates())`.
        """
        clone: FieldsealQuerySet = self._chain()
        clone._fieldseal_verify = False
        return clone

    @property
    def _verifying(self) -> bool:
        return bool(self._fieldseal_verify and self._fieldseal_obligations)

    # -- recording obligations --------------------------------------------

    def _filter_or_exclude(self, negate: bool, args: Any, kwargs: Any) -> Any:
        found = self._encrypted_predicates(args, kwargs, negate)
        clone = super()._filter_or_exclude(negate, args, kwargs)
        if found:
            clone._fieldseal_obligations = (*self._fieldseal_obligations, *found)
        return clone

    def _encrypted_predicates(self, args: Any, kwargs: Any,
                              negate: bool) -> list[_Obligation]:
        if not self._fieldseal_verify:
            # `.candidates()` has taken §7.5 off this queryset, so there is
            # nothing to record and no refusal to make: an escape hatch that
            # refuses the same things is not one.
            return []
        out: list[_Obligation] = []
        for key in list(kwargs):
            ob = self._predicate(key, kwargs, negate)
            if ob is not None:
                out.append(ob)
        for arg in args:
            out.extend(self._q_obligations(arg, "negated" if negate else None))
        return out

    def _predicate(self, key: str, kwargs: dict[str, Any],
                   negate: bool) -> _Obligation | None:
        """One keyword predicate: an obligation, a pass-through, or a raise.

        `kwargs` is taken whole rather than the value alone so that an
        `__in` iterable can be materialized *in place*: this method consumes
        it to build the obligation, and Django consumes it again to compile
        the SQL -- a generator handed to both would arrive at the second
        consumer exhausted.
        """
        from .fields import Encrypted

        field, lookup, traversed = self._resolve(key)
        if not isinstance(field, Encrypted):
            return None
        value = kwargs[key]
        if lookup == "isnull" or (lookup == "exact" and value is None):
            # Served exactly by the envelope column (`IS [NOT] NULL`; Django
            # itself rewrites `exact=None` to `isnull`). No blind index is
            # touched, so there is no candidate set to verify and negation
            # loses nothing -- allowed in every combination.
            return None
        if traversed:
            self._refuse_traversal(key, field)
        if negate:
            raise FieldsealNotSupported(
                f"`exclude({key}=...)` is not available on an encrypted "
                "column. The SQL excludes the whole index bucket, and "
                "spec §7.4 mandates that the bucket holds rows whose "
                "value differs -- so the query drops rows it should have "
                "kept, and they never reach the adapter for §7.5 "
                "re-verification to put back. A filter's false positives "
                "are recoverable; an exclusion's false negatives are not. "
                "Fetch the matches with filter() and exclude their "
                "primary keys, or use .candidates() and accept the "
                "semantics."
            )
        if lookup == "in":
            value = kwargs[key] = list(value)
        return self._obligation(field, lookup, value, key)

    def _resolve(self, key: str) -> tuple[Any, str, bool]:
        """Resolve `key` to `(terminal field, lookup name, crossed a relation)`.

        `email__in` is `(email, "in", False)`; `patient__email` walks the
        relation (forward or reverse) and is `(email, "exact", True)`. A part
        that is not a field on the model reached so far ends the walk and
        names the lookup; an unresolvable first part (an annotation, `pk`)
        returns no field and the predicate is not ours to judge.
        """
        parts = key.split("__")
        model = self.model
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

    def _q_obligations(self, node: Any, reason: str | None) -> list[_Obligation]:
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
        """
        from django.db.models import Q

        from .fields import Encrypted

        if not isinstance(node, Q):
            return []
        if reason is None:
            if node.negated:
                reason = "negated"
            elif node.connector != Q.AND:
                reason = f"{node.connector}-combined"
        out: list[_Obligation] = []
        for i, child in enumerate(node.children):
            if isinstance(child, Q):
                out.extend(self._q_obligations(child, reason))
                continue
            if not isinstance(child, (tuple, list)) or len(child) != 2:
                continue
            key, value = str(child[0]), child[1]
            field, lookup, traversed = self._resolve(key)
            if not isinstance(field, Encrypted):
                continue
            if lookup == "isnull" or (lookup == "exact" and value is None):
                continue  # precise on the envelope column; see _predicate
            if traversed:
                self._refuse_traversal(key, field)
            if reason is not None:
                raise FieldsealNotSupported(
                    f"`Q({key}=...)` reaches an encrypted column through a "
                    f"{reason} combination. A candidate row may be present "
                    "because another branch matched, so spec §7.5 "
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
        return super().earliest(*fields)

    def latest(self, *fields: Any) -> Any:
        if self._verifying:
            self._refuse_limit_one("latest")
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
                "qs.candidates() to accept bucket semantics."
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
                    "or combine .candidates() and take on §7.5 yourself."
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
        return super().values(*fields, **expressions)

    def values_list(self, *fields: Any, **kwargs: Any) -> Any:
        if self._verifying:
            self._refuse_projection("values_list")
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
