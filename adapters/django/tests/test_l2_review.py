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
from django.db import connection
from django.db.models import Exists, OuterRef, Q, QuerySet, Subquery

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
    """`.candidates()` lifts the filter-time *verification* refusals --
    `Q` under OR -- because the SQL semantics they refuse are exactly what it
    hands over. (Its own message told callers to do this; before the review
    round, the code refused them anyway.) The `exclude` half of that sentence
    stood until G24; see the class below."""

    def test_or_through_q_on_candidates_works(self, rows):
        both = Patient.objects.all().candidates().filter(
            Q(email="ada@example.com") | Q(email="grace@example.com"))
        assert {p.pk for p in both} == {rows[0].pk, rows[1].pk}


class TestCandidatesDoesNotLiftNegation:
    """G24 ([#100]), decided 2026-09-06 in the Prisma adapter's direction:
    neither hatch lifts negation.

    The deciding argument is what the caller can do with what they were
    handed. Under `filter().candidates()` they hold a superset of the answer
    and can reach it by dropping rows -- that is §7.5, and handing it over is
    what the hatch is for. Under an exclusion they hold a *subset*, and no
    operation on it restores a row the database already removed. Every test
    below passed as a served query before G24 closed.
    """

    def test_the_wrong_answer_the_refusal_prevents(self, rows):
        """Measured, not described.

        The SQL the adapter used to compile for
        `candidates().exclude(email="ada@example.com")`, run directly --
        neither queryset lookup will emit it now, and the sibling column
        refuses `exact` on its own account, so a cursor is the only way left
        to produce the answer the refusal exists to prevent. Grace is not
        Ada, so she belongs in the exclusion; the bucket drops her, and
        nothing is raised.
        """
        _forge_collision(onto=rows[1], like=rows[0])
        bucket = Patient.objects.get(pk=rows[0].pk).email_bidx
        q = connection.ops.quote_name
        with connection.cursor() as cur:
            cur.execute(
                f"SELECT {q('id')} FROM {q(Patient._meta.db_table)} "
                f"WHERE NOT ({q('email_bidx')} = %s)", [bytes(bucket)])
            kept = {row[0] for row in cur.fetchall()}
        assert rows[1].pk not in kept  # dropped, and not recoverable from
        assert rows[2].pk in kept      # what the caller was handed

    @pytest.mark.parametrize("shape", [
        lambda qs: qs.exclude(email="ada@example.com"),
        lambda qs: qs.exclude(Q(email="ada@example.com")),
        lambda qs: qs.filter(~Q(email="ada@example.com")),
        # Nested under an AND: the negation is the child's own.
        lambda qs: qs.filter(Q(age=36) & ~Q(email="ada@example.com")),
        # Nested under an OR, which poisons `reason` first -- the shape that
        # requires tracking negation in its own slot rather than reading it
        # off the verification reason.
        lambda qs: qs.filter(Q(age=36) | ~Q(email="ada@example.com")),
        # XOR is negation once expanded, and drops rows the same way.
        lambda qs: qs.filter(Q(email="ada@example.com") ^ Q(age=36)),
    ], ids=["exclude-kw", "exclude-Q", "not-Q", "and-not-Q", "or-not-Q",
            "xor-Q"])
    def test_every_subtractive_shape_refuses_on_candidates(self, rows, shape):
        with pytest.raises(FieldsealNotSupported) as e:
            list(shape(Patient.objects.all().candidates()))
        assert "false negatives are not" in str(e.value)

    def test_the_message_no_longer_recommends_the_hatch(self, rows):
        """The ergonomic half of G24: the refusal text used to end "or use
        .candidates() and accept the semantics", which sent a caller
        following it onto irrecoverable semantics with nothing saying they
        differ in kind from the filter case."""
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.exclude(email="ada@example.com")
        msg = str(e.value)
        assert "never reach the adapter" in msg
        assert "does not lift this" in msg
        assert "or use .candidates()" not in msg

    def test_null_negation_is_still_exact_and_still_served(self, rows):
        """The carve-out G24 does not touch: `IS NOT NULL` reads the envelope
        column's null-ness, no bucket is involved, and negation loses
        nothing."""
        Patient.objects.create(email="x@example.com", nickname="ada")
        served = Patient.objects.all().candidates().exclude(nickname=None)
        assert [p.nickname for p in served] == ["ada"]
        assert list(Patient.objects.all().candidates().exclude(
            nickname__isnull=True)) == list(served)


class TestNegationIsAPositionNotAnOwner:
    """The G24 review's item 2: the refusal was ordered after the traversal
    check, so it never ran on a path whose owner is the querying model.

    `_refuse_cross_model` is the compile-time backstop the traversal branch
    hands off to, and it passes by design when the encrypted column belongs
    to the model being queried -- a self-referential path, an MTI parent, or
    a round trip out through a relation and back. A negated traversal of that
    shape fell out of both layers and was served. Position is the rule G24
    settled on; who owns the column does not enter into it.
    """

    def test_the_wrong_answer_the_reorder_prevents(self, rows):
        """Measured, not described -- the SQL the adapter compiled for
        `candidates().exclude(visit__patient__email=v)`, run directly.

        The round trip `Patient -> visit -> patient -> email` names the
        querying model at both ends, so nothing about it is cross-model and
        the compile-time backstop passes it. As in the sibling class, a
        cursor is the only way left to produce this: the queryset refuses it
        now, and the index column refuses `exact` on its own account.
        """
        _forge_collision(onto=rows[1], like=rows[0])
        Visit.objects.create(patient=rows[0], reason="checkup")
        Visit.objects.create(patient=rows[1], reason="checkup")
        bucket = Patient.objects.get(pk=rows[0].pk).email_bidx
        q = connection.ops.quote_name
        patients, visits = Patient._meta.db_table, Visit._meta.db_table
        fk = Visit._meta.get_field("patient").column
        with connection.cursor() as cur:
            cur.execute(
                f"SELECT {q('id')} FROM {q(patients)} WHERE NOT ({q('id')} IN "
                f"(SELECT v.{q(fk)} FROM {q(visits)} v INNER JOIN "
                f"{q(patients)} sub ON sub.{q('id')} = v.{q(fk)} "
                f"WHERE sub.{q('email_bidx')} = %s))", [bytes(bucket)])
            kept = {row[0] for row in cur.fetchall()}
        assert rows[1].pk not in kept  # Grace is not Ada and belongs in the
        assert rows[2].pk in kept      # exclusion; the bucket drops her

    @pytest.mark.parametrize("shape", [
        lambda qs: qs.exclude(visit__patient__email="ada@example.com"),
        lambda qs: qs.filter(~Q(visit__patient__email="ada@example.com")),
    ], ids=["exclude-kw", "not-Q"])
    def test_a_negated_round_trip_refuses_on_candidates(self, rows, shape):
        with pytest.raises(FieldsealNotSupported) as e:
            list(shape(Patient.objects.all().candidates()))
        assert "false negatives are not" in str(e.value)

    def test_a_negated_traversal_gets_the_subtractive_message(self, rows):
        """Not the traversal one, which recommends `.candidates()` and would
        be pointing at the hatch for a shape §10.2 now says it must not."""
        with pytest.raises(FieldsealNotSupported) as e:
            Visit.objects.exclude(patient__email="ada@example.com")
        msg = str(e.value)
        assert "false negatives are not" in msg
        assert "or use .candidates()" not in msg
        assert "embed bucket semantics" not in msg

    def test_a_positive_traversal_still_gets_the_traversal_message(self, rows):
        """The reorder moves one branch ahead of another; it must not swallow
        the branch it moved past."""
        with pytest.raises(FieldsealNotSupported) as e:
            Visit.objects.filter(patient__email="ada@example.com")
        assert "through a relation" in str(e.value)

    def test_negated_null_traversal_is_still_served(self, rows):
        """The carve-out survives the reorder: `IS NOT NULL` on a traversed
        column reads null-ness, touches no bucket, and is exact."""
        Visit.objects.create(patient=rows[0], reason="checkup")
        assert Visit.objects.exclude(patient__email__isnull=True).count() == 1


class TestABucketEmbeddedInASubtractivePosition:
    """The G24 review's item 3: `.candidates()` was refused in a subtractive
    position only when the encrypted column was named in that very predicate.

    Embedded as a subquery it is named nowhere -- `exclude(pk__in=qs)` is a
    predicate on `pk` -- and `resolve_expression`, which owns the embedding,
    is handed the operand without the position, so it cannot tell this from
    `filter(pk__in=qs)`, the shape three refusal messages recommend. The
    marks therefore travel on the `Query` and the position is read where it
    is visible: at `filter()`, `exclude()`, `difference()` and `annotate()`.
    """

    @pytest.fixture
    def bucket_qs(self):
        return Patient.objects.filter(email="ada@example.com").candidates()

    def test_the_wrong_answer_the_refusal_prevents(self, rows, bucket_qs):
        """Measured: the bucket holds Grace, so subtracting it removes her
        from an answer she belongs in, and she is not in the result for the
        caller to put back."""
        _forge_collision(onto=rows[1], like=rows[0])
        assert {p.pk for p in bucket_qs} == {rows[0].pk, rows[1].pk}
        kept = set(Patient.objects.all().candidates().exclude(
            pk__in=list(bucket_qs.values_list("pk", flat=True))
        ).values_list("pk", flat=True))
        assert rows[1].pk not in kept
        assert rows[2].pk in kept

    @pytest.mark.parametrize("shape", [
        lambda qs: Patient.objects.exclude(pk__in=qs),
        lambda qs: Patient.objects.filter(~Q(pk__in=qs)),
        lambda qs: Visit.objects.exclude(patient__in=qs),
        lambda qs: Patient.objects.all().difference(qs),
        lambda qs: Patient.objects.annotate(
            hit=Exists(qs.filter(pk=OuterRef("pk")))).filter(hit=False),
    ], ids=["exclude-in", "not-Q-in", "exclude-relation-in", "difference",
            "annotate-Exists"])
    def test_every_embedding_of_a_bucket_refuses(self, rows, bucket_qs, shape):
        with pytest.raises(FieldsealNotSupported):
            list(shape(bucket_qs))

    def test_the_positive_embedding_the_messages_recommend_still_works(
            self, rows, bucket_qs):
        """`filter(...__in=qs.candidates())` is what `_refuse_traversal`,
        `_refuse_cross_model` and `resolve_expression` all point callers at.
        It hands back a superset, which is what the hatch is for."""
        _forge_collision(onto=rows[1], like=rows[0])
        found = Patient.objects.all().candidates().filter(pk__in=bucket_qs)
        assert {p.pk for p in found} == {rows[0].pk, rows[1].pk}

    def test_union_and_intersection_still_lift(self, rows, bucket_qs):
        """Widen the bucket and both return *more* rows, so §7.5 still
        trims; only `difference` inverts."""
        other = Patient.objects.all().candidates().filter(pk=rows[2].pk)
        assert len(list(bucket_qs.union(other))) == 2
        assert list(bucket_qs.intersection(other)) == []

    def test_a_candidates_queryset_that_touched_no_index_still_embeds(
            self, rows):
        """`.candidates()` alone is not a bucket -- it is an exact queryset
        with §7.5 handed over and nothing to hand over. Refusing it would be
        refusing on the method name rather than on the semantics."""
        plain = Patient.objects.all().candidates().filter(pk=rows[0].pk)
        assert [p.pk for p in Patient.objects.exclude(pk__in=plain)] == [
            rows[1].pk, rows[2].pk]

    def test_a_verifying_queryset_in_an_annotation_refuses_too(self, rows):
        """Found while fixing the above, and the same defect: `Exists(qs)`
        keeps `qs.query` and never calls `resolve_expression`, so the refusal
        that guards `filter(pk__in=qs)` was bypassed in the *verifying*
        direction as well -- bucket matches served as answers with no
        obligation recorded anywhere."""
        with pytest.raises(FieldsealNotSupported) as e:
            list(Patient.objects.annotate(hit=Exists(
                Patient.objects.filter(email="ada@example.com").filter(
                    pk=OuterRef("pk")))).filter(hit=True))
        assert "Materialize the verified rows first" in str(e.value)
        assert ".candidates()" not in str(e.value)

    @pytest.mark.parametrize("shape", [
        lambda e: Patient.objects.filter(e),
        lambda e: Patient.objects.exclude(e),
        lambda e: Patient.objects.filter(Q(e)),
        lambda e: Patient.objects.annotate(hit=e).filter(hit=True),
    ], ids=["filter-positional", "exclude-positional", "Q-child", "annotate"])
    @pytest.mark.parametrize("hatched", [False, True],
                             ids=["verifying", "candidates"])
    def test_every_expression_route_refuses(self, rows, shape, hatched):
        """`annotate()` was not the only door. An `Exists`/`Subquery` also
        arrives as a positional `filter()`/`exclude()` argument and as an
        expression child of a `Q` -- neither of which is a `Q` leaf the walk
        visits, nor a queryset `resolve_expression` is called on. Measured
        before this test: `filter(Exists(qs))` returned the bucket as the
        answer and `exclude(Exists(qs.candidates()))` dropped the collision
        row, silently, in both hatch states.
        """
        inner = Patient.objects.filter(email="ada@example.com")
        if hatched:
            inner = inner.candidates()
        with pytest.raises(FieldsealNotSupported) as e:
            list(shape(Exists(inner.filter(pk=OuterRef("pk")))))
        assert "as a subquery" in str(e.value)

    def test_a_subquery_as_a_keyword_operand_refuses(self, rows):
        """The same wrapper in the other operand position. The bare queryset
        spelling (`pk__in=qs`) is deliberately untouched here -- that one has
        `resolve_expression` beneath it and, for `.candidates()`, is the
        shape the refusal messages recommend."""
        with pytest.raises(FieldsealNotSupported) as e:
            list(Patient.objects.filter(pk=Subquery(
                Patient.objects.filter(email="ada@example.com")
                .candidates().values("pk")[:1])))
        assert "as a subquery" in str(e.value)

    def test_the_wrong_answer_the_expression_routes_allowed(self, rows):
        """Measured, not described -- the SQL those routes compiled to, run
        directly, since every queryset spelling of it now refuses."""
        _forge_collision(onto=rows[1], like=rows[0])
        bucket = Patient.objects.get(pk=rows[0].pk).email_bidx
        q = connection.ops.quote_name
        table = Patient._meta.db_table
        inner = (f"SELECT 1 FROM {q(table)} sub WHERE sub.{q('id')} = "
                 f"p.{q('id')} AND sub.{q('email_bidx')} = %s")
        with connection.cursor() as cur:
            cur.execute(
                f"SELECT p.{q('id')} FROM {q(table)} p WHERE EXISTS ({inner})",
                [bytes(bucket)])
            matched = {row[0] for row in cur.fetchall()}
            cur.execute(
                f"SELECT p.{q('id')} FROM {q(table)} p WHERE NOT EXISTS "
                f"({inner})", [bytes(bucket)])
            kept = {row[0] for row in cur.fetchall()}
        assert matched == {rows[0].pk, rows[1].pk}  # Grace, as a match
        assert rows[1].pk not in kept               # and then dropped
        assert rows[2].pk in kept
