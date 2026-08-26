"""Regressions for the PR #79 (L2) review round.

Reviewer 2 found three: relation traversal served unverified, NULL equality
broken at filter() time, and plain-AND `Q` refused against the documented
contract. Working through those surfaced more of the same shape -- fetch
paths still answered inside a database-side LIMIT window (`get()`'s
MAX_GET_RESULTS sample, int indexing, `earliest`/`latest`), paths bypassing
`_fetch_all` entirely (`iterator`, `aiterator`, subquery embedding,
combinators), and `.candidates()` not lifting the filter-time refusals its
own docstring told callers to rely on. Each class names its finding.
"""

from __future__ import annotations

import asyncio

import pytest
from django.db.models import Q, QuerySet

from fieldseal_django.errors import FieldsealNotSupported

from .models import Patient, Visit
from .test_l2 import _forge_collision

pytestmark = pytest.mark.django_db


@pytest.fixture
def rows():
    return [
        Patient.objects.create(email="ada@example.com", note="a", age=36),
        Patient.objects.create(email="grace@example.com", note="g", age=45),
        Patient.objects.create(email="alan@example.com", note="t", age=41),
    ]


class TestNullSemantics:
    """`IS NULL` is exact: NULL plaintext stores NULL in both columns, so no
    blind index is touched and no obligation is recorded -- in any
    combination, negation included."""

    @pytest.fixture
    def named(self):
        return [
            Patient.objects.create(email="a@example.com", nickname="ada"),
            Patient.objects.create(email="b@example.com", nickname=None),
        ]

    def test_filter_none_returns_the_null_rows(self, named):
        found = Patient.objects.filter(nickname=None)
        assert [p.pk for p in found] == [named[1].pk]

    def test_filter_none_records_no_obligation(self, named):
        """The SQL (`nickname IS NULL`, via Django's own exact-to-isnull
        rewrite) is already exact, so verification has nothing to add --
        and `to_bytes(None)` must never run for a read filter."""
        qs = Patient.objects.filter(nickname=None)
        assert qs._fieldseal_obligations == ()

    def test_exclude_none_is_allowed_and_exact(self, named):
        found = Patient.objects.exclude(nickname=None)
        assert [p.pk for p in found] == [named[0].pk]

    def test_isnull_lookups_work_both_ways(self, named):
        assert [p.pk for p in Patient.objects.filter(nickname__isnull=True)
                ] == [named[1].pk]
        assert [p.pk for p in Patient.objects.filter(nickname__isnull=False)
                ] == [named[0].pk]

    def test_in_with_none_keeps_sql_membership_semantics(self, named):
        """SQL `IN` never matches NULL and the compiled lookup drops None
        from the target list, so the obligation drops it too: the NULL row
        must not come back, and the non-NULL match must."""
        found = Patient.objects.filter(nickname__in=["ada", None])
        assert [p.pk for p in found] == [named[0].pk]

    def test_in_of_only_none_matches_nothing(self, named):
        assert list(Patient.objects.filter(nickname__in=[None])) == []


class TestRelationTraversal:
    """A join can reach the blind index, but §7.5 re-verification cannot
    follow it there -- so every traversal onto an encrypted column refuses,
    at filter() time on a FieldsealQuerySet and at compile time for every
    other queryset."""

    def test_traversal_refuses_at_filter_time(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Visit.objects.filter(patient__email="ada@example.com")
        assert "relation" in str(e.value)
        assert "candidates()" in str(e.value)

    def test_reverse_traversal_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.filter(visit__reason="checkup")
        assert "relation" in str(e.value)

    def test_traversal_in_a_q_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported):
            Visit.objects.filter(Q(patient__email="ada@example.com"))

    def test_a_plain_queryset_is_refused_at_compile_time(self, rows):
        """The layer that protects querysets this package never sees: a
        model with a plain manager (or a hand-built QuerySet) still cannot
        be served unverified candidates through a join."""
        qs = QuerySet(model=Visit).filter(patient__email="ada@example.com")
        with pytest.raises(FieldsealNotSupported) as e:
            list(qs)
        assert "owns the encrypted column" in str(e.value)

    def test_isnull_through_a_relation_is_allowed(self, rows):
        Visit.objects.create(patient=rows[0], reason="checkup")
        assert Visit.objects.filter(patient__email__isnull=False).count() == 1

    def test_a_non_encrypted_traversal_is_untouched(self, rows):
        visit = Visit.objects.create(patient=rows[0], reason="checkup")
        found = Visit.objects.filter(patient__pk=rows[0].pk)
        assert [v.pk for v in found] == [visit.pk]

    def test_the_documented_escape_hatches_work(self, rows):
        visit = Visit.objects.create(patient=rows[0], reason="checkup")
        Visit.objects.create(patient=rows[1], reason="intake")

        via_subquery = Visit.objects.filter(
            patient__in=Patient.objects.filter(
                email="ada@example.com").candidates())
        assert [v.pk for v in via_subquery] == [visit.pk]

        verified = [p.pk for p in
                    Patient.objects.filter(email="ada@example.com")]
        via_pks = Visit.objects.filter(patient__pk__in=verified)
        assert [v.pk for v in via_pks] == [visit.pk]


class TestPlainAndQ:
    """A plain AND of positive terms verifies exactly like keyword
    arguments: every returned row must satisfy the encrypted term too, so
    per-term verification is exact. Everything else still refuses."""

    def test_a_plain_q_verifies_like_a_keyword(self, rows):
        _forge_collision(onto=rows[1], like=rows[0])
        found = Patient.objects.filter(Q(email="ada@example.com"))
        assert [p.pk for p in found] == [rows[0].pk]

    def test_and_composition_keeps_the_obligation(self, rows):
        _forge_collision(onto=rows[1], like=rows[0])
        hit = Patient.objects.filter(
            Q(email="ada@example.com") & Q(pk=rows[0].pk))
        miss = Patient.objects.filter(
            Q(email="ada@example.com") & Q(pk=rows[1].pk))
        assert [p.pk for p in hit] == [rows[0].pk]
        assert list(miss) == []  # the collision row, dropped by §7.5

    def test_negation_still_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.filter(~Q(email="ada@example.com"))
        assert "negated" in str(e.value)

    def test_null_equality_in_a_q_is_allowed_anywhere(self, rows):
        """`Q(nickname=None)` is `IS NULL` -- exact -- so even OR is fine."""
        found = Patient.objects.filter(Q(nickname=None) | Q(pk=rows[0].pk))
        assert {p.pk for p in found} == {r.pk for r in rows}

    def test_in_accepts_a_generator_without_exhausting_it(self, rows):
        """The obligation and the SQL compiler both consume the iterable;
        the adapter materializes it in place so the second consumer does not
        see it empty (a keyword argument and a Q child alike)."""
        found = list(Patient.objects.filter(
            email__in=(e for e in ["ada@example.com"])))
        assert [p.pk for p in found] == [rows[0].pk]
        found = list(Patient.objects.filter(
            Q(email__in=(e for e in ["ada@example.com"]))))
        assert [p.pk for p in found] == [rows[0].pk]


class TestBeyondTheFetchWindow:
    """Paths that were still answered inside a database-side LIMIT window,
    or that bypassed `_fetch_all` entirely."""

    def test_get_finds_a_match_behind_a_full_window_of_collisions(self):
        """Django's get() samples LIMIT 21 candidates; a §7.4 bucket is
        allowed to be larger, and the true match may sit past the window."""
        decoys = [Patient.objects.create(email=f"decoy{i}@example.com")
                  for i in range(25)]
        target = Patient.objects.create(email="needle@example.com")
        like = Patient.objects.get(pk=target.pk)
        Patient.objects.filter(
            pk__in=[d.pk for d in decoys]).candidates().update(
            email_bidx=like.email_bidx)

        assert Patient.objects.get(email="needle@example.com").pk == target.pk

    def test_get_still_raises_multiple_for_two_true_matches(self):
        Patient.objects.create(email="twin@example.com")
        Patient.objects.create(email="twin@example.com")
        with pytest.raises(Patient.MultipleObjectsReturned):
            Patient.objects.get(email="twin@example.com")

    def test_get_still_raises_doesnotexist(self, rows):
        with pytest.raises(Patient.DoesNotExist):
            Patient.objects.get(email="nobody@example.com")

    def test_iterator_yields_only_verified_rows(self, rows):
        _forge_collision(onto=rows[1], like=rows[0])
        got = list(Patient.objects.filter(email="ada@example.com").iterator())
        assert [p.pk for p in got] == [rows[0].pk]
        raw = list(Patient.objects.filter(
            email="ada@example.com").candidates().iterator())
        assert {p.pk for p in raw} == {rows[0].pk, rows[1].pk}

    @pytest.mark.django_db(transaction=True)
    def test_aiterator_yields_only_verified_rows(self):
        """`aiterator` is the one async method that does not delegate to its
        sync twin, so it gets its own end-to-end check. `transaction=True`
        because the async iterable executes on another thread, whose
        connection cannot see this test's uncommitted rows otherwise."""
        kept = Patient.objects.create(email="async@example.com")
        other = Patient.objects.create(email="decoy@example.com")
        _forge_collision(onto=other, like=kept)

        async def collect():
            qs = Patient.objects.filter(email="async@example.com")
            return [p async for p in qs.aiterator()]

        got = asyncio.run(collect())
        assert [p.pk for p in got] == [kept.pk]

    def test_int_indexing_refuses(self, rows):
        qs = Patient.objects.filter(email="ada@example.com")
        with pytest.raises(FieldsealNotSupported):
            qs[0]

    def test_int_indexing_works_once_materialized(self, rows):
        qs = Patient.objects.filter(email="ada@example.com")
        assert list(qs)  # materializes and verifies
        assert qs[0].pk == rows[0].pk

    def test_earliest_and_latest_refuse(self, rows):
        qs = Patient.objects.filter(email="ada@example.com")
        with pytest.raises(FieldsealNotSupported):
            qs.earliest("created")
        with pytest.raises(FieldsealNotSupported):
            qs.latest("created")

    def test_combinators_refuse_on_either_side(self, rows):
        verifying = Patient.objects.filter(email="ada@example.com")
        with pytest.raises(FieldsealNotSupported):
            verifying.union(Patient.objects.all())
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().union(verifying)

    def test_a_verifying_queryset_refuses_to_become_a_subquery(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Visit.objects.filter(
                patient__in=Patient.objects.filter(email="ada@example.com"))
        assert "subquery" in str(e.value)


class TestCandidatesLiftsFilterTimeRefusals:
    """`.candidates()` lifts the filter-time refusals too -- `exclude`, `Q`
    under OR -- because the SQL semantics they refuse are exactly what it
    hands over. (Its own message told callers to do this; before the review
    round, the code refused them anyway.)"""

    def test_exclude_on_candidates_excludes_the_bucket(self, rows):
        remaining = Patient.objects.all().candidates().exclude(
            email="ada@example.com")
        assert rows[0].pk not in {p.pk for p in remaining}
        assert {rows[1].pk, rows[2].pk} <= {p.pk for p in remaining}

    def test_or_through_q_on_candidates_works(self, rows):
        both = Patient.objects.all().candidates().filter(
            Q(email="ada@example.com") | Q(email="grace@example.com"))
        assert {p.pk for p in both} == {rows[0].pk, rows[1].pk}
