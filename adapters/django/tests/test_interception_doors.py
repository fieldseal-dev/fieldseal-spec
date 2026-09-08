"""#118: `_filter_or_exclude` was not the only door to the blind index.

Two routes reached the index sibling without passing the queryset layer, so
every L2 rule that lives there -- §7.5 obligation recording, the `OR`
refusal, the G24 subtractive refusal -- was simply absent on them:

- **`complex_filter(Q)`** calls `query.add_q` directly. Django's own body
  routes the *dict* form through `_filter_or_exclude`, so only the `Q` form
  was open. Closed by overriding it with the same walk `filter(Q(...))` runs.
- **`Model._base_manager`** is a plain `Manager` returning a plain
  `QuerySet`, so on the *owning* model there is no queryset layer at all --
  and the compile-time backstop for the traversal case
  (`_refuse_cross_model`) passes there by design, because the owner is the
  querying model. Closed one layer down, in `_IndexedLookup`, which is the
  only place both routes and every future one must pass through.

Neither is a method a caller has to type. Django reaches `limit_choices_to`
through both, at five sites; `TestLimitChoicesTo` below is the end-to-end
proof, and it found a route the issue did not list.
"""

from __future__ import annotations

import pytest
from django import forms
from django.db import connection
from django.db.models import Exists, OuterRef, Q, QuerySet

from fieldseal_django.errors import FieldsealNotSupported
from fieldseal_django.fields import _IndexedLookup

from .models import Patient, Referral, Visit
from .test_l2 import _forge_collision

pytestmark = pytest.mark.django_db

V = "ada@example.com"


@pytest.fixture
def rows():
    return [
        Patient.objects.create(email="ada@example.com", note="a", age=36),
        Patient.objects.create(email="grace@example.com", note="g", age=45),
        Patient.objects.create(email="alan@example.com", note="t", age=41),
    ]


class TestComplexFilterRecordsTheObligation:
    """Door 1. Measured before the override existed: `complex_filter(Q(...))`
    returned the collision row as a match, with `_fieldseal_obligations`
    empty and `_verifying` false -- so `_fetch_all` had nothing to
    re-verify and no way to know it should."""

    def test_a_colliding_candidate_is_dropped(self, rows):
        _forge_collision(onto=rows[1], like=rows[0])
        found = Patient.objects.complex_filter(Q(email=V))
        assert [p.pk for p in found] == [rows[0].pk]

    def test_the_obligation_survives_chaining(self, rows):
        _forge_collision(onto=rows[1], like=rows[0])
        chained = Patient.objects.complex_filter(Q(email=V)).order_by("-pk")
        assert [p.pk for p in chained] == [rows[0].pk]
        assert chained.count() == 1

    def test_the_dict_form_was_already_covered(self, rows):
        """Django's own body sends it through `_filter_or_exclude`. Pinned so
        that the override cannot quietly become the only covered route."""
        _forge_collision(onto=rows[1], like=rows[0])
        found = Patient.objects.complex_filter({"email": V})
        assert [p.pk for p in found] == [rows[0].pk]

    def test_membership_verifies_and_a_generator_survives(self, rows):
        """The walk consumes an `__in` iterable and the SQL compiler consumes
        it again; the same in-place materialization `filter(Q(...))` does."""
        _forge_collision(onto=rows[1], like=rows[0])
        found = Patient.objects.complex_filter(
            Q(email__in=(e for e in [V])))
        assert [p.pk for p in found] == [rows[0].pk]

    def test_null_equality_is_still_served_exactly(self, rows):
        """`IS NULL` touches no index, so it records no obligation and is
        allowed in every combination -- on this route too."""
        named = Patient.objects.create(email="n@example.com", nickname="nick")
        found = Patient.objects.complex_filter(
            Q(nickname=None) | Q(pk=rows[0].pk))
        assert {p.pk for p in found} == {r.pk for r in rows}
        assert named.pk not in {p.pk for p in found}


class TestComplexFilterRefusesWhatFilterRefuses:
    """The same door, from the other side: every refusal `filter()` carries
    was absent here, and each was measured serving a wrong answer first."""

    def test_a_negated_q_is_refused(self, rows):
        """Measured before: `[alan]` -- Grace dropped with the bucket, and
        the answer is `[grace, alan]`."""
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.complex_filter(~Q(email=V))
        assert "negated" in str(e.value)

    def test_candidates_does_not_lift_the_negation(self, rows):
        """G24 scopes the refusal by position, not by who opted out of
        §7.5: `.candidates()` hands over a superset, and no operation on an
        exclusion's result restores a row the database already removed."""
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().candidates().complex_filter(~Q(email=V))

    def test_an_or_combination_is_refused(self, rows):
        """Measured before: the whole bucket, unverified."""
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.complex_filter(Q(email=V) | Q(nickname="zz"))
        assert "OR combination" in str(e.value)

    def test_an_embedded_index_subquery_is_refused(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.complex_filter(
                Q(Exists(Patient.objects.filter(email=V))))
        assert "Subquery" in str(e.value)

    def test_a_relation_traversal_is_refused(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Visit.objects.complex_filter(Q(patient__email=V))
        assert "through a relation" in str(e.value)

    def test_candidates_still_serves_the_bucket(self, rows):
        """The hatch is not collateral damage: a positive term on a
        `.candidates()` queryset still hands back the §7.4 bucket."""
        _forge_collision(onto=rows[1], like=rows[0])
        found = Patient.objects.all().candidates().complex_filter(Q(email=V))
        assert {p.pk for p in found} == {rows[0].pk, rows[1].pk}


class TestAQuerysetWithNoLayerIsRefused:
    """Door 2. `Patient._base_manager` is a plain `Manager` -- Django builds
    it that way so its own internals are not filtered by a custom default
    manager -- so nothing above the lookup can re-verify. Measured before
    the refusal existed: `filter()` served the whole bucket as the answer
    and `exclude()` dropped it entire, with nothing raised on either."""

    def test_base_manager_filter_is_refused(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            list(Patient._base_manager.filter(email=V))
        assert "no fieldseal layer" in str(e.value)

    def test_base_manager_exclude_is_refused(self, rows):
        with pytest.raises(FieldsealNotSupported):
            list(Patient._base_manager.exclude(email=V))

    def test_base_manager_complex_filter_is_refused(self, rows):
        """Both doors at once, which is the combination `ForeignKey.validate`
        walks."""
        with pytest.raises(FieldsealNotSupported):
            list(Patient._base_manager.complex_filter(Q(email=V)))

    def test_a_hand_built_plain_queryset_is_refused(self, rows):
        with pytest.raises(FieldsealNotSupported):
            list(QuerySet(Patient).filter(email=V))

    def test_an_unlayered_subquery_is_refused_from_a_verifying_queryset(
            self, rows):
        """The refusal is at compile time, so it holds wherever the query
        ends up -- including embedded in a queryset that *does* verify, where
        the outer layer has no obligation for the inner term."""
        with pytest.raises(FieldsealNotSupported):
            list(Patient.objects.filter(
                Exists(Patient._base_manager.filter(email=OuterRef("pk")))))
        with pytest.raises(FieldsealNotSupported):
            list(Patient.objects.filter(
                pk__in=Patient._base_manager.filter(email=V)))

    def test_the_refusal_is_scoped_to_the_index_and_nothing_else(self, rows):
        """`_base_manager` is Django's own read path for FK validation,
        cascade collection and `refresh_from_db`. Only a predicate that
        compiles onto the blind index is refused; a primary key, an
        `IS NULL` on an encrypted column (exact on the envelope column, no
        index touched) and an unfiltered read all stay served, or the
        refusal would break the framework rather than the wrong answer."""
        ref = Referral.objects.create(patient=rows[0])
        base = Patient._base_manager
        assert [p.pk for p in base.filter(pk=rows[0].pk)] == [rows[0].pk]
        assert list(base.filter(email__isnull=True)) == []
        assert {p.pk for p in base.all()} == {r.pk for r in rows}
        rows[0].refresh_from_db()
        assert ref.patient.pk == rows[0].pk
        rows[0].delete()  # cascade collection, through `_base_manager`
        assert not Referral.objects.filter(pk=ref.pk).exists()


class TestTheBoundaryTheMarkDoesNotReach:
    """The review round on this PR (reviewer 1, blocking) found the first
    cut's backstop too narrow, and the tests above did not catch it.

    The mark says a `FieldsealQuerySet` owns the `Query` the lookup compiles
    for. It does not say that queryset is the one answering the statement,
    and the two come apart at a subquery boundary: `Exists(qs)` takes
    `qs.query` and never touches the queryset again, so from a plain manager
    the *inner* query carries a real mark, `_refuse_unlayered` passes, and
    the rows are fetched by an enclosing statement with no §7.5 layer. The
    shape `TestAQuerysetWithNoLayerIsRefused` refuses was rewritable as a
    correlated `Exists` and served.
    """

    @staticmethod
    def _correlated():
        return Patient.objects.filter(pk=OuterRef("pk"), email=V)

    def test_a_verifying_subquery_under_a_plain_outer_is_refused(self, rows):
        """Measured before: `[1, 2]` -- the §7.4 bucket, unverified, from
        the manager whose direct `filter(email=v)` is refused."""
        _forge_collision(onto=rows[1], like=rows[0])
        with pytest.raises(FieldsealNotSupported) as e:
            list(Patient._base_manager.filter(Exists(self._correlated())))
        assert "inside a subquery" in str(e.value)

    def test_the_negated_form_is_refused_too(self, rows):
        """The dangerous direction, and the one that made this blocking:
        measured before, `[3]` -- G24's subtractive wrong answer, where the
        answer is `[2, 3]`. A positive-only fix would have left it."""
        _forge_collision(onto=rows[1], like=rows[0])
        with pytest.raises(FieldsealNotSupported):
            list(Patient._base_manager.exclude(Exists(self._correlated())))

    def test_an_uncorrelated_exists_is_refused(self, rows):
        """Measured before: `[1, 2, 3]` -- the whole table, because an
        unverified bucket that is merely non-empty makes `EXISTS` true for
        every row."""
        with pytest.raises(FieldsealNotSupported):
            list(Patient._base_manager.filter(
                Exists(Patient.objects.filter(email=V))))

    def test_a_verifying_outer_still_refuses_at_the_queryset_layer(
            self, rows):
        """The same embedding under a `FieldsealQuerySet` was already
        refused (#117), with a fuller message. The compile-time rule must
        not take that case over: it is the second layer, not the first."""
        with pytest.raises(FieldsealNotSupported) as e:
            list(Patient.objects.filter(Exists(self._correlated())))
        assert "Subquery" in str(e.value)

    def test_candidates_still_embeds_in_a_positive_position(self, rows):
        """The refusal keys on `verify`, not on the index mark, so the shape
        three refusal messages recommend is untouched -- from a plain outer
        too, where nothing else would have stopped it. Bucket semantics were
        asked for and are what come back."""
        _forge_collision(onto=rows[1], like=rows[0])
        cands = Patient.objects.filter(email=V).candidates()
        found = Patient.objects.filter(pk__in=cands)
        assert {p.pk for p in found} == {rows[0].pk, rows[1].pk}

    def test_the_subtractive_operand_residue_from_a_plain_outer(self, rows):
        """**A documented residue, asserted as one so it cannot drift.**

        `.candidates()` in a *subtractive* operand is refused on any
        `FieldsealQuerySet` (G24, the bucket-as-operand rule), and there is
        no lookup-layer backstop for it: the outer predicate is on a plain
        column, so no `_IndexedLookup` compiles anywhere in the statement
        and the compile-time layer is never consulted. From a plain manager
        the rule therefore has nobody to read it. This is the same residue
        `docs/12` §3.2 already records for a model with no encrypted column
        of its own, with the owning model's `_base_manager` as a second
        instance -- and it stays a residue rather than a hole because the
        caller had to build the bucket deliberately to reach it.
        """
        _forge_collision(onto=rows[1], like=rows[0])
        cands = Patient.objects.filter(email=V).candidates()
        with pytest.raises(FieldsealNotSupported):
            list(Patient.objects.exclude(pk__in=cands))
        # No layer to read the position: served, and short by the collision.
        served = list(Patient._base_manager.exclude(pk__in=cands))
        assert {p.pk for p in served} == {rows[2].pk}


class TestTheRefusalsAreDistinct:
    """Reviewer 2, finding 2: the message assertions above cannot by
    themselves show *which* backstop fired. This calls the two directly, on
    the shape door 2 is about, and shows the cross-model one provably
    passes there -- which is the whole reason door 2 needed a second
    check."""

    def test_cross_model_passes_where_the_layer_check_fires(self, rows):
        query = Patient._base_manager.filter(email=V).query
        compiler = query.get_compiler(connection=connection)
        lookup = query.where.children[0]
        assert isinstance(lookup, _IndexedLookup)

        # Owner is the querying model, so this one passes by design ...
        assert lookup._refuse_cross_model(compiler) is None
        # ... and the queryset layer is what is missing.
        with pytest.raises(FieldsealNotSupported) as e:
            lookup._refuse_unlayered(compiler)
        assert "no fieldseal layer" in str(e.value)


class TestLimitChoicesTo:
    """Why the two doors are more than an unusual method call.

    `tests.models.Referral` declares `limit_choices_to=Q(email=...)` on its
    FK -- not a shape to copy, but the one declaration that puts Django
    itself on both routes. Each test below is a path an ordinary application
    walks without naming `complex_filter` or `_base_manager` anywhere.
    """

    @pytest.fixture
    def forged(self, rows):
        _forge_collision(onto=rows[1], like=rows[0])
        return rows

    def test_full_clean_refuses_rather_than_validating_against_a_bucket(
            self, forged):
        """`ForeignKey.validate` applies `limit_choices_to` through
        `_base_manager.complex_filter(Q)`: both doors at once, reached from
        an ordinary `full_clean()`. It cannot be served -- there is no
        queryset layer on that manager to put one on."""
        with pytest.raises(FieldsealNotSupported):
            Referral(patient=forged[0]).full_clean()

    def test_get_choices_now_verifies_instead_of_offering_a_collision(
            self, forged):
        """`Field.get_choices` uses `_default_manager.complex_filter(Q)` --
        door 1 alone, so this one is *fixed* rather than refused. Before the
        override the choice list offered Grace as a patient whose email is
        Ada's; she is the §7.4 collision the index mandates."""
        field = Referral._meta.get_field("patient")
        choices = field.get_choices(include_blank=False)
        assert [pk for pk, _ in choices] == [forged[0].pk]

    def test_a_modelform_choice_list_refuses(self, forged):
        """Not on #118's list, and it contradicts the issue's parenthetical:
        `forms.models.apply_limit_choices_to_to_formfield` does wrap the
        condition in `Exists(...)`, which #117 refuses -- but on Django 6.1
        it builds that subquery from **`_base_manager`**, so the queryset it
        embeds carries no index mark and #117's walk never sees one. A fifth
        site, and door 2 again. Measured before: the form offered both Ada
        and the collision row.
        """
        class ReferralForm(forms.ModelForm):
            class Meta:
                model = Referral
                fields = ["patient"]

        with pytest.raises(FieldsealNotSupported):
            list(ReferralForm().fields["patient"].queryset)
