"""L2: index rewriting plus mandatory spec §7.5 re-verification (docs/12 §3.2).

Decision C: `_fetch_all` re-verifies by default, `.candidates()` opts out.
Every test here is about one of the two halves being useless without the
other -- the rewrite alone returns collisions, and verification alone has
nothing to narrow.
"""

from __future__ import annotations

import pytest
from django.db.models import Count, Q

from fieldseal_django.errors import FieldsealNotSupported

from .models import Patient

pytestmark = pytest.mark.django_db


@pytest.fixture
def rows():
    return [
        Patient.objects.create(email="ada@example.com", note="a", age=36),
        Patient.objects.create(email="grace@example.com", note="g", age=45),
        Patient.objects.create(email="alan@example.com", note="t", age=41),
    ]


def _forge_collision(onto, like):
    """Write one row's index value onto another.

    The index is truncated to 15 bits, so a natural collision is not
    reproducible in a small fixture. Forging one presents the queryset with
    exactly the situation the database would: a bucket holding a row whose
    plaintext differs. `.candidates()` is required here because `update()` is
    refused on a verifying queryset.
    """
    target = Patient.objects.get(pk=like.pk)
    Patient.objects.filter(pk=onto.pk).candidates().update(
        email_bidx=target.email_bidx)


class TestEqualityRoundTrips:
    def test_exact_finds_the_row(self, rows):
        found = list(Patient.objects.filter(email="ada@example.com"))
        assert [p.pk for p in found] == [rows[0].pk]

    def test_exact_finds_nothing_for_an_absent_value(self, rows):
        assert not Patient.objects.filter(email="nobody@example.com").exists()

    def test_in_finds_the_membership(self, rows):
        found = Patient.objects.filter(
            email__in=["ada@example.com", "alan@example.com"])
        assert {p.pk for p in found} == {rows[0].pk, rows[2].pk}

    def test_empty_in_matches_nothing(self, rows):
        assert list(Patient.objects.filter(email__in=[])) == []

    def test_the_sql_touches_the_index_column(self, rows):
        """The rewrite must compile against the sibling, not the ciphertext.

        Asserted on the SQL rather than on the result, because a query that
        compared against the ciphertext column would return zero rows and
        look exactly like an ordinary miss.
        """
        sql = str(Patient.objects.filter(email="ada@example.com").query)
        assert "email_bidx" in sql


class TestReVerification:
    """The half that makes the rewrite correct."""

    def test_a_colliding_candidate_is_dropped(self, rows):
        _forge_collision(onto=rows[1], like=rows[0])

        candidates = Patient.objects.filter(email="ada@example.com").candidates()
        assert {p.pk for p in candidates} == {rows[0].pk, rows[1].pk}

        verified = Patient.objects.filter(email="ada@example.com")
        assert [p.pk for p in verified] == [rows[0].pk]

    def test_count_counts_verified_rows_not_candidates(self, rows):
        _forge_collision(onto=rows[1], like=rows[0])
        qs = Patient.objects.filter(email="ada@example.com")
        assert qs.candidates().count() == 2
        assert qs.count() == 1

    def test_exists_is_false_when_only_collisions_match(self, rows):
        """The failure `exists()` would otherwise have: a bucket holding only
        rows whose value differs still makes `SELECT 1 ... LIMIT 1` true."""
        _forge_collision(onto=rows[1], like=rows[0])
        Patient.objects.filter(pk=rows[0].pk).candidates().delete()

        qs = Patient.objects.filter(email="ada@example.com")
        assert qs.candidates().exists() is True
        assert qs.exists() is False

    def test_first_skips_a_leading_collision(self, rows):
        """Django implements `first()` as `[:1]`, so a colliding candidate
        ordered first would return it -- or `None` after verification -- while
        a real match sits in the next row."""
        earlier = Patient.objects.create(email="zz@example.com", note="z")
        _forge_collision(onto=earlier, like=rows[0])

        qs = Patient.objects.filter(
            email="ada@example.com").order_by("email_bidx", "pk")
        assert qs.first().pk == rows[0].pk

    def test_verification_survives_chaining(self, rows):
        """`_clone` must carry the obligations, or any chained queryset
        silently returns candidates while the unchained one verifies."""
        _forge_collision(onto=rows[1], like=rows[0])
        chained = Patient.objects.filter(email="ada@example.com").order_by("-pk")
        assert [p.pk for p in chained] == [rows[0].pk]

    def test_a_null_column_never_matches(self):
        """A NULL row cannot equal an indexed target -- under a non-NULL
        query it must always be dropped. (A NULL row only legitimately
        reaches a result set through `IS NULL` predicates, which record no
        obligation at all; see TestNullSemantics.)"""
        qs = Patient.objects.filter(email="ada@example.com")
        (obligation,) = qs._fieldseal_obligations
        assert obligation.matches(None) is False
        assert obligation.matches("ada@example.com") is True


class TestNormalizedEquality:
    """G19 (#78): equality is equality **under the column's normalizer**."""

    def test_a_case_variant_matches(self, rows):
        row = Patient.objects.create(email="Ada.L@Example.COM", note="c")
        found = Patient.objects.filter(email="ada.l@example.com")
        assert [p.pk for p in found] == [row.pk]

    def test_a_canonically_equivalent_spelling_matches(self):
        """Precomposed U+00E9 against decomposed e + U+0301: one text to every
        reader, two byte strings, and the index already merged them."""
        row = Patient.objects.create(email="rené@example.com", note="n")
        found = Patient.objects.filter(email="rené@example.com")
        assert [p.pk for p in found] == [row.pk]

    def test_a_genuinely_different_value_still_does_not_match(self, rows):
        assert not Patient.objects.filter(email="ada@example.org").exists()


class TestRefusals:
    """Every path that answers from SQL would answer about candidates."""

    def test_exclude_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.exclude(email="ada@example.com")
        assert "never reach the adapter" in str(e.value)

    def test_slicing_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.filter(email="ada@example.com")[0:2]
        assert "over-fetch" in str(e.value)

    @pytest.mark.parametrize("call", [
        lambda qs: qs.update(note="x"),
        lambda qs: qs.delete(),
        lambda qs: qs.values("pk"),
        lambda qs: list(qs.values_list("pk", flat=True)),
        lambda qs: qs.only("pk"),
        lambda qs: qs.defer("note"),
        lambda qs: qs.aggregate(n=Count("pk")),
    ])
    def test_sql_answered_paths_refuse(self, rows, call):
        qs = Patient.objects.filter(email="ada@example.com")
        with pytest.raises(FieldsealNotSupported):
            call(qs)

    def test_or_through_q_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.filter(Q(email="ada@example.com") | Q(note="g"))

    def test_a_column_with_no_index_refuses_equality(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.filter(note="a")
        assert "no BlindIndex" in str(e.value)

    def test_an_unsupported_lookup_still_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.filter(email__contains="ada")


class TestCandidatesOptOut:
    """An escape hatch that refuses the same things is not one."""

    def test_candidates_allows_slicing_and_sql_paths(self, rows):
        qs = Patient.objects.filter(email="ada@example.com").candidates()
        assert list(qs[0:1])
        assert qs.count() >= 1
        assert list(qs.values_list("pk", flat=True))

    def test_candidates_survives_chaining(self, rows):
        qs = Patient.objects.filter(email="ada@example.com").candidates()
        assert list(qs.order_by("pk")[0:1])
