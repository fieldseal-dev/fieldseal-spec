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
