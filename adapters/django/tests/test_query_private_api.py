"""Pins on the private Django API `FieldsealQuerySet` depends on.

Decision C (`docs/12` §3.2) buys a safe default at the price of overriding
`_fetch_all`, which Django does not document as an extension point. The
failure mode of an upstream change is the worst one available: verification
silently stops happening and `filter()` starts returning collision rows, with
every other test still green because they exercise behaviour rather than
mechanism.

So each assumption is asserted here, against the installed Django, with a
message saying what to do. **A failure in this file is not a bug in this
file** -- it means Django moved and the L2 path needs re-verifying by hand.
"""

from __future__ import annotations

import inspect

import pytest
from django.db.models import QuerySet

from fieldseal_django.query import FieldsealQuerySet

from .models import Patient

pytestmark = pytest.mark.django_db


def test_fetch_all_still_exists_and_is_what_materializes():
    assert hasattr(QuerySet, "_fetch_all"), (
        "Django no longer defines QuerySet._fetch_all. The §7.5 "
        "re-verification hook is gone; find where results are materialized "
        "now, or L2 is returning unverified candidates."
    )


def test_fetch_all_body_still_matches_what_we_mirrored():
    """`FieldsealQuerySet._fetch_all` re-implements Django's rather than
    calling it, so that candidates are dropped *before* prefetch runs.

    That is only safe while Django's body is the two steps we mirrored. If
    upstream adds a third, ours silently skips it.
    """
    source = inspect.getsource(QuerySet._fetch_all)
    for fragment in (
        "self._result_cache is None",
        "self._result_cache = list(self._iterable_class(self))",
        "self._prefetch_related_lookups",
        "self._prefetch_done",
        "self._prefetch_related_objects()",
    ):
        assert fragment in source, (
            f"QuerySet._fetch_all no longer contains {fragment!r}. "
            "fieldseal_django.query.FieldsealQuerySet._fetch_all mirrors this "
            "method; re-read Django's version and update the mirror, or "
            "re-verification will run against the wrong rows -- or not at all."
        )
    # Nothing else should be in there. A third responsibility means the mirror
    # is now incomplete.
    body = [ln.strip() for ln in source.splitlines()[1:] if ln.strip()]
    assert len(body) <= 6, (
        "QuerySet._fetch_all has grown beyond the body this adapter mirrors:\n"
        + source
    )


def test_count_and_exists_still_bypass_the_result_cache():
    """The reason `count()`/`exists()` are overridden at all.

    If Django ever routes them through `_fetch_all`, the overrides become
    redundant rather than wrong -- but the reverse change, in a Django where
    they were routed and stopped being, is what this catches.
    """
    assert "get_count" in inspect.getsource(QuerySet.count)
    assert "has_results" in inspect.getsource(QuerySet.exists)


def test_first_and_last_are_still_implemented_by_slicing():
    """`first()`/`last()` are overridden because Django slices, and a slice
    applies LIMIT before verification."""
    for method in (QuerySet.first, QuerySet.last):
        assert "[:1]" in inspect.getsource(method), (
            "Django's first()/last() no longer slice. The override in "
            "fieldseal_django.query may now be unnecessary -- check before "
            "removing it, because the slice is what made it necessary."
        )


def test_filter_and_exclude_still_funnel_through_filter_or_exclude():
    """Obligations are recorded in `_filter_or_exclude`. If either public
    method stops routing there, encrypted-column predicates stop being
    recorded and verification silently does nothing."""
    for method in (QuerySet.filter, QuerySet.exclude):
        assert "_filter_or_exclude(" in inspect.getsource(method)


def test_chaining_still_funnels_through_clone():
    """`_clone` is where the obligations are carried across `order_by`,
    `filter`, `using` and everything else that chains."""
    assert "self._clone()" in inspect.getsource(QuerySet._chain)


def test_the_obligations_actually_survive_a_representative_chain():
    """The behavioural half of the pin: the mechanism tests above can all pass
    while the wiring is broken, so this asserts the outcome."""
    qs = (Patient.objects.filter(email="ada@example.com")
          .order_by("pk")
          .using("default")
          .distinct())
    assert qs._fieldseal_obligations, (
        "obligations were lost while chaining; filter() results would be "
        "unverified candidates"
    )
    assert isinstance(qs, FieldsealQuerySet)


def test_get_still_samples_through_a_limit():
    """`get()` is overridden because Django's applies LIMIT MAX_GET_RESULTS
    before materializing -- a window over *candidates*, so a §7.4 bucket
    larger than the window can hide the true match past it."""
    source = inspect.getsource(QuerySet.get)
    assert "MAX_GET_RESULTS" in source and "set_limits" in source, (
        "Django's get() no longer samples through MAX_GET_RESULTS. The "
        "get() override in fieldseal_django.query may now be unnecessary -- "
        "check how get() materializes before removing it."
    )


def test_int_indexing_still_compiles_to_a_limit():
    """`qs[0]` is refused because Django compiles it to LIMIT k,1 before
    verification -- the same failure first() exists to avoid."""
    assert "set_limits(k, k + 1)" in inspect.getsource(QuerySet.__getitem__), (
        "Django's __getitem__ no longer applies set_limits(k, k + 1) for "
        "int indices. Re-read it and re-decide whether the int-index "
        "refusal in fieldseal_django.query is still needed."
    )


def test_earliest_still_applies_limit_one():
    assert "set_limits(high=1)" in inspect.getsource(QuerySet._earliest), (
        "Django's _earliest no longer applies LIMIT 1 in SQL. The "
        "earliest()/latest() refusals in fieldseal_django.query exist "
        "because of that limit; re-verify before relaxing them."
    )


def test_combinators_still_funnel_through_combinator_query():
    """The union/intersection/difference refusal lives in
    `_combinator_query`; if a public method stops routing there, an
    encrypted side would be combined unverified."""
    for method in (QuerySet.union, QuerySet.intersection, QuerySet.difference):
        assert "_combinator_query(" in inspect.getsource(method), (
            f"{method.__name__}() no longer routes through "
            "_combinator_query; the refusal in fieldseal_django.query is "
            "being bypassed and unverified candidates can be combined."
        )


def test_iterators_still_bypass_fetch_all():
    """`iterator()`/`aiterator()` are overridden because they stream from
    `_iterable_class` without `_fetch_all` -- if Django starts routing them
    through it, the overrides become redundant (verify, then simplify)."""
    for method in (QuerySet._iterator, QuerySet.aiterator):
        source = inspect.getsource(method)
        assert "_iterable_class" in source and "_fetch_all" not in source


def test_async_methods_still_delegate_to_the_sync_overrides():
    """Every other async method must keep wrapping its sync twin, because
    the sync methods are where verification lives. `aiterator` is the known
    exception and is overridden separately."""
    for name in ("aget", "afirst", "alast", "acount", "aexists",
                 "aearliest", "alatest", "aupdate", "adelete", "aaggregate"):
        source = inspect.getsource(getattr(QuerySet, name))
        assert f"sync_to_async(self.{name[1:]})" in source, (
            f"QuerySet.{name} no longer delegates to self.{name[1:]} via "
            "sync_to_async; it is bypassing the verifying override and "
            "needs one of its own in fieldseal_django.query."
        )


def test_exact_none_is_still_rewritten_to_isnull():
    """`filter(field=None)` records no obligation because Django itself
    rewrites `exact=None` to `isnull`, which compiles to a *precise*
    `IS NULL` on the envelope column. If that rewrite disappears, None
    reaches EncryptedExact and the design must be revisited."""
    from django.db.models.sql.query import Query

    assert 'get_lookup("isnull")' in inspect.getsource(Query.build_lookup), (
        "Django's build_lookup no longer rewrites exact=None to isnull. "
        "The NULL-equality path in fieldseal_django.query._predicate "
        "leans on that rewrite; re-verify filter(field=None) end to end."
    )
