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
inherit a wrong answer.
"""

from __future__ import annotations

from typing import Any

from django.db import models

from .errors import FieldsealNotSupported


class _Obligation:
    """One encrypted-column predicate that SQL matched approximately.

    Targets are normalized at `filter()` time rather than per row: the query
    value is normalized once, every candidate row once, and `exact` and `in`
    then share one membership test.
    """

    __slots__ = ("field_name", "lookup", "normalized", "raw", "normalizer")

    def __init__(self, field_name: str, lookup: str, normalized: frozenset[bytes],
                 raw: frozenset[bytes], normalizer: str) -> None:
        self.field_name = field_name
        self.lookup = lookup
        self.normalized = normalized
        #: Targets whose *normalization was refused* -- a `bucket` column's
        #: unindexable values (docs/09 §7.2). They share one index marker, so
        #: SQL cannot separate them and only a raw comparison can.
        self.raw = raw
        self.normalizer = normalizer

    def matches(self, value: Any, field: Any) -> bool:
        from .codec import to_bytes

        if value is None:
            # NULL never equals a value. Django's own `exact` agrees, and the
            # row could not have been indexed in the first place.
            return False
        as_bytes = to_bytes(field.inner, value)
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
        from .fields import Encrypted

        out: list[_Obligation] = []
        for key, value in kwargs.items():
            field, lookup = self._resolve(key)
            if field is None or not isinstance(field, Encrypted):
                continue
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
            out.append(self._obligation(field, lookup, value, key))
        for arg in args:
            self._reject_q(arg, negate)
        return out

    def _resolve(self, key: str) -> tuple[Any, str]:
        """Split `email__in` into (field, "in"); `email` into (field, "exact")."""
        parts = key.split("__")
        lookup = "exact"
        if len(parts) > 1 and not self._is_field(parts[-1]):
            lookup = parts[-1]
            parts = parts[:-1]
        if len(parts) != 1:
            # A relation traversal (`patient__email`). The join target's own
            # manager is what would have to verify, and this queryset cannot
            # reach into it, so it is refused rather than served unverified.
            return None, lookup
        return self._is_field(parts[0]), lookup

    def _is_field(self, name: str) -> Any:
        try:
            return self.model._meta.get_field(name)
        except Exception:  # noqa: BLE001 - FieldDoesNotExist and friends
            return None

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
        values = list(value) if lookup == "in" else [value]
        if lookup == "in" and not values:
            # `__in=[]` matches nothing in SQL and must keep doing so.
            return _Obligation(field.name, lookup, frozenset(), frozenset(),
                               decl.normalize)
        normalized: set[bytes] = set()
        raw: set[bytes] = set()
        for v in values:
            as_bytes = to_bytes(field.inner, v)
            n = _normalize_or_none(decl.normalize, as_bytes)
            if n is None:
                raw.add(as_bytes)
            else:
                normalized.add(n)
        return _Obligation(field.name, lookup, frozenset(normalized),
                           frozenset(raw), decl.normalize)

    def _reject_q(self, node: Any, negate: bool) -> None:
        """Refuse any `Q` that reaches an encrypted column other than as a
        plain AND of positive terms.

        Under OR, a candidate row may have been returned because the *other*
        branch matched, so dropping it on a failed encrypted-column check
        would remove a legitimate result. Verification would have to evaluate
        the whole predicate in Python to be correct, which is a different and
        much larger feature. Refusing is the §10.2 behaviour.
        """
        from django.db.models import Q

        from .fields import Encrypted

        if not isinstance(node, Q):
            return
        unsafe = negate or node.negated or node.connector != Q.AND
        for child in node.children:
            if isinstance(child, Q):
                self._reject_q(child, unsafe)
                continue
            if not isinstance(child, (tuple, list)) or len(child) != 2:
                continue
            field, _ = self._resolve(str(child[0]))
            if not isinstance(field, Encrypted):
                continue
            raise FieldsealNotSupported(
                f"`Q({child[0]}=...)` reaches an encrypted column through a "
                f"{'negated' if unsafe and node.negated or negate else 'non-AND'} "
                "combination. A candidate row may be present because another "
                "branch matched, so spec §7.5 re-verification cannot decide "
                "it without evaluating the whole predicate in Python. Split "
                "the encrypted term into its own filter() call, or use "
                ".candidates() and take on §7.5 yourself."
                if unsafe else
                f"`Q({child[0]}=...)` on an encrypted column is not available "
                "yet; pass it as a keyword argument to filter() instead."
            )

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
            field = self.model._meta.get_field(ob.field_name)
            if not ob.matches(getattr(row, ob.field_name, None), field):
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

    # -- refusals ----------------------------------------------------------

    def __getitem__(self, k: Any) -> Any:
        if isinstance(k, slice) and self._verifying and self._result_cache is None:
            raise FieldsealNotSupported(
                "Slicing a queryset filtered on an encrypted column is not "
                "available. LIMIT/OFFSET is applied by the database before "
                "spec §7.5 re-verification drops collision rows, so the page "
                "comes back short and the next page starts in the wrong "
                "place -- spec §7.5 states outright that pagination built "
                "directly on an indexed encrypted column is incorrect. The "
                "documented pattern is over-fetch → decrypt → filter → "
                "paginate: use .candidates() and paginate that yourself, or "
                "materialize with list(qs) and slice in Python."
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
