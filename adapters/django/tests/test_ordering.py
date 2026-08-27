"""G20 (#80): ordering, grouping, DISTINCT and computation over ciphertext.

A refusal family orthogonal to §7.5 verification: SQL that *computes on
envelope bytes* is meaningless on every queryset, obligations or none, and
`.candidates()` does not lift it. The measured failures that justify each
refusal (recorded in the issue before the refusals were written): ORDER BY
returns a stable-looking order with no meaning; GROUP BY returns one group
per row under keys that decrypt and print identically; MIN() returns
whichever envelope sorts first, decrypted cleanly and presented as the
minimum; SUM() produces garbage misreported as NOT_CIPHERTEXT.
"""

from __future__ import annotations

import pytest
from django.db import models
from django.db.models import Count, F, Min, Q, Sum
from django.db.models.functions import Length
from django.test.utils import isolate_apps

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta
from fieldseal_django.errors import FieldsealNotSupported

from .models import Patient, Visit

pytestmark = pytest.mark.django_db


@pytest.fixture
def rows():
    return [
        Patient.objects.create(email="m@x.com", age=30),
        Patient.objects.create(email="a@x.com", age=40),
        Patient.objects.create(email="a2@x.com", age=35),
    ]


class TestOrderBy:
    def test_order_by_an_encrypted_column_refuses(self, rows):
        for spec in ("email", "-email", "+email"):
            with pytest.raises(FieldsealNotSupported) as e:
                Patient.objects.all().order_by(spec)
            assert "envelope bytes" in str(e.value)

    def test_mixed_ordering_refuses_too(self, rows):
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().order_by("pk", "email")

    def test_an_unindexed_encrypted_column_refuses_the_same(self, rows):
        """Ordering is meaningless with or without a blind index."""
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().order_by("note")

    def test_expressions_are_seen_through(self, rows):
        from django.db.models.functions import Lower

        for expr in (F("email"), F("email").asc(), Lower("email")):
            with pytest.raises(FieldsealNotSupported):
                Patient.objects.all().order_by(expr)

    def test_ordering_through_a_relation_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported):
            Visit.objects.all().order_by("patient__email")

    def test_plaintext_sibling_and_random_ordering_still_work(self, rows):
        assert list(Patient.objects.all().order_by("created"))
        assert list(Patient.objects.all().order_by("-pk"))
        assert list(Patient.objects.all().order_by("email_bidx", "pk"))
        assert list(Patient.objects.all().order_by("?"))

    def test_candidates_does_not_lift_the_refusal(self, rows):
        """Bucket semantics are a meaningful thing to accept for a filter;
        ciphertext order has no semantics to accept."""
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().candidates().order_by("email")


class TestEarliestLatest:
    def test_earliest_and_latest_by_an_encrypted_column_refuse(self, rows):
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().earliest("age")
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().latest("age")

    def test_earliest_by_a_plaintext_column_works(self, rows):
        assert Patient.objects.all().earliest("created").pk == rows[0].pk

    def test_the_plaintext_get_latest_by_fallback_still_works(self, rows):
        """The no-argument path reads Meta.get_latest_by; a plaintext
        declaration (Patient's is `created`) must pass the check and reach
        Django untouched -- the refusal is for encrypted targets only."""
        assert Patient.objects.all().earliest().pk == rows[0].pk
        assert Patient.objects.all().latest().pk == rows[-1].pk

    @isolate_apps("tests")
    def test_get_latest_by_is_read_when_no_fields_are_given(self):
        """`earliest()` with no arguments falls back to Meta.get_latest_by,
        which never passes through order_by() -- the refusal must read it
        itself. Refused before any SQL, so no table is needed."""

        class Diary(models.Model):
            secret = Encrypted(
                models.CharField(max_length=50),
                column_uuid="018f3c2e-0000-7000-8000-0000000000a1",
                index=BlindIndex(
                    index_id="exact", idf="hmac-sha512",
                    normalize="nfc-casefold-v1", truncate_bits=15,
                    projected_population=100_000),
            )
            secret_bidx = Encrypted.index_column("secret")
            fieldseal = FieldsealMeta(
                table_uuid="018f3c2e-0000-7000-8000-0000000000a0")

            class Meta:
                get_latest_by = "secret"

        with pytest.raises(FieldsealNotSupported):
            Diary.objects.earliest()


class TestAggregates:
    """MIN() over two ages {30, 40} was measured returning 40 -- the
    byte-wise minimum *envelope* decrypts cleanly to an arbitrary row's
    value, presented as the minimum. Nothing raised."""

    def test_aggregates_referencing_an_encrypted_column_refuse(self, rows):
        # Plain Count("email") is deliberately absent: it reads null-ness,
        # not bytes, and is served -- the G23 carve-out, tested below.
        for agg in (Min("age"), Sum("age"), Count("email", distinct=True)):
            with pytest.raises(FieldsealNotSupported) as e:
                Patient.objects.all().aggregate(x=agg)
            assert "envelope bytes" in str(e.value)

    def test_aggregates_over_plaintext_still_work(self, rows):
        assert Patient.objects.all().aggregate(n=Count("pk")) == {"n": 3}

    def test_annotate_with_an_encrypted_aggregate_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().annotate(total=Sum("age"))

    def test_annotate_with_a_function_over_ciphertext_refuses(self, rows):
        """LENGTH(email) would report ciphertext size as if it were the
        value's length -- a silently wrong number, not an error."""
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().annotate(n=Length("email"))

    def test_a_bare_f_annotation_is_allowed_and_decrypts(self, rows):
        """`F("email")` only *selects* the column; the converter decrypts
        what comes back, so the annotation is exact."""
        got = Patient.objects.all().annotate(e=F("email")).order_by("pk")[0]
        assert got.e == got.email

    def test_relation_counts_still_work(self, rows):
        Visit.objects.create(patient=rows[0], reason="checkup")
        got = Patient.objects.all().annotate(n=Count("visit")).order_by("pk")
        assert [p.n for p in got] == [1, 0, 0]


class TestPlainCountCarveOut:
    """G23 (#89): plain non-distinct COUNT reads null-ness, never envelope
    bytes, so under the §10.2 NULL-preservation invariant it is exact and
    served. The shapes that DO read bytes -- distinct, an inner function, a
    filtered form -- stay refused, and the shared exactness expectation
    mirrors the Prisma suite so the two adapters cannot diverge again."""

    @pytest.fixture
    def noted(self):
        return [
            Patient.objects.create(email="a@x.com", age=1, note="first"),
            Patient.objects.create(email="b@x.com", age=2, note="second"),
            Patient.objects.create(email="c@x.com", age=3, note=None),
        ]

    def test_count_over_an_encrypted_column_is_served_and_exact(self, noted):
        assert Patient.objects.all().aggregate(n=Count("note")) == {"n": 2}
        # And the column on a NULL row contributes zero.
        only_null = Patient.objects.filter(pk=noted[2].pk)
        assert only_null.aggregate(n=Count("note")) == {"n": 0}

    def test_the_empty_string_is_a_value_and_counts(self, noted):
        # The trap for a lazy evaluator: '' is non-NULL, becomes an
        # envelope, and counts -- absence is NULL and only NULL.
        Patient.objects.create(email="d@x.com", age=4, note="")
        assert Patient.objects.all().aggregate(n=Count("note")) == {"n": 3}

    def test_writing_null_moves_the_count(self, noted):
        # The update-path half of the invariant: value -> NULL must land as
        # NULL, or the count silently desyncs.
        p = noted[0]
        p.note = None
        p.save()
        assert Patient.objects.all().aggregate(n=Count("note")) == {"n": 1}

    def test_annotate_serves_the_same_shape(self, noted):
        got = (Patient.objects.all()
               .annotate(n=Count("note")).order_by("pk"))
        assert [p.n for p in got] == [1, 1, 0]

    def test_grouped_by_plaintext_stays_exact(self, noted):
        got = (Patient.objects.all()
               .values("created")
               .annotate(n=Count("note")))
        assert sum(r["n"] for r in got) == 2

    def test_distinct_count_stays_refused(self, noted):
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().aggregate(n=Count("note", distinct=True))

    def test_count_of_a_function_over_ciphertext_stays_refused(self, noted):
        # Count(Length(enc)) reads bytes through the inner function; the
        # carve-out is the bare column only.
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().aggregate(n=Count(Length("note")))

    def test_a_filtered_count_is_not_the_plain_shape(self, noted):
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().aggregate(
                n=Count("note", filter=Q(age__isnull=False)))

    def test_the_refusal_message_names_the_carve_out(self, noted):
        # The false "COUNT computes on bytes" claim is what G23 was filed
        # on; the message that remains must point at the served shape.
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.all().aggregate(n=Count(Length("note")))
        assert "is served" in str(e.value)

    def test_the_sql_answered_rule_still_governs_verifying_querysets(
            self, noted):
        # On a queryset filtered by an encrypted column the database counts
        # bucket matches (spec §7.4 collisions included), so the §7.5 rule
        # refuses regardless of the carve-out.
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.filter(email="a@x.com").aggregate(
                n=Count("note"))


class TestGroupingAndDistinct:
    def test_grouping_by_an_encrypted_column_refuses(self, rows):
        """The measured case: 4 rows with a duplicate email returned four
        groups of n=1, two of them printing the identical key."""
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.all().values("email").annotate(n=Count("pk"))
        assert "group" in str(e.value)

    def test_grouping_by_a_plaintext_column_works(self, rows):
        got = Patient.objects.all().values("created").annotate(n=Count("pk"))
        assert sum(r["n"] for r in got) == 3

    def test_the_projection_alone_is_still_allowed(self, rows):
        """values("email") without grouping is a plain read: the column
        comes back and the converter decrypts it."""
        emails = {r["email"] for r in Patient.objects.all().values("email")}
        assert emails == {"m@x.com", "a@x.com", "a2@x.com"}

    def test_distinct_with_an_encrypted_field_name_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.all().distinct("email")
        assert "deduplicates nothing" in str(e.value)

    def test_distinct_over_an_encrypted_projection_refuses(self, rows):
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().values("email").distinct()
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().values_list("email", flat=True).distinct()

    def test_the_reverse_order_of_calls_is_caught_too(self, rows):
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.all().distinct().values("email")

    def test_distinct_without_fields_on_model_rows_still_works(self, rows):
        assert Patient.objects.all().distinct().count() == 3

    def test_distinct_over_a_plaintext_projection_still_works(self, rows):
        assert list(Patient.objects.all().values("created").distinct())


class TestE009:
    """Meta.ordering / Meta.get_latest_by naming an encrypted column: the
    compiler applies both directly, where the queryset refusal cannot see
    them, so the declaration is the only interception point."""

    def _issues(self, apps):
        from fieldseal_django.checks import check_fieldseal

        return [i for i in check_fieldseal(apps=apps)
                if i.id == "fieldseal.E009"]

    def test_meta_ordering_over_an_encrypted_column_is_an_error(self):
        with isolate_apps("tests") as apps:
            class Bad(models.Model):
                secret = Encrypted(
                    models.CharField(max_length=50),
                    column_uuid="018f3c2e-0000-7000-8000-0000000000b1")
                fieldseal = FieldsealMeta(
                    table_uuid="018f3c2e-0000-7000-8000-0000000000b0")

                class Meta:
                    ordering = ["-secret"]

            (issue,) = self._issues(apps)
        assert "Meta.ordering" in issue.msg
        assert "envelope bytes" in issue.hint

    def test_get_latest_by_over_an_encrypted_column_is_an_error(self):
        with isolate_apps("tests") as apps:
            class AlsoBad(models.Model):
                secret = Encrypted(
                    models.CharField(max_length=50),
                    column_uuid="018f3c2e-0000-7000-8000-0000000000c1")
                fieldseal = FieldsealMeta(
                    table_uuid="018f3c2e-0000-7000-8000-0000000000c0")

                class Meta:
                    get_latest_by = "secret"

            (issue,) = self._issues(apps)
        assert "get_latest_by" in issue.msg

    def test_plaintext_ordering_declarations_are_clean(self):
        with isolate_apps("tests") as apps:
            class Fine(models.Model):
                secret = Encrypted(
                    models.CharField(max_length=50),
                    column_uuid="018f3c2e-0000-7000-8000-0000000000d1")
                when = models.DateTimeField(auto_now_add=True)
                fieldseal = FieldsealMeta(
                    table_uuid="018f3c2e-0000-7000-8000-0000000000d0")

                class Meta:
                    ordering = ["-when"]
                    get_latest_by = "when"

            assert self._issues(apps) == []


class TestW005:
    """The admin's two ordering doors: `ModelAdmin.ordering` breaks every
    changelist request; a sortable encrypted column breaks on a header
    click. Both now raise (G20), so the warning tells people at startup."""

    def _w005(self, admin_registry):
        from fieldseal_django.checks import check_fieldseal

        return [i for i in check_fieldseal(admin_registry=admin_registry)
                if i.id == "fieldseal.W005"]

    def test_model_admin_ordering_warns(self):
        class FakeAdmin:
            ordering = ("email",)

        (issue,) = self._w005({Patient: FakeAdmin()})
        assert "ordering" in issue.msg

    def test_a_sortable_encrypted_column_warns(self):
        class FakeAdmin:
            list_display = ("email", "created")

        (issue,) = self._w005({Patient: FakeAdmin()})
        assert "sortable" in issue.msg

    def test_sortable_by_excluding_the_column_silences_it(self):
        class FakeAdmin:
            list_display = ("email", "created")
            sortable_by = ("created",)

        assert self._w005({Patient: FakeAdmin()}) == []

    def test_admin_order_field_pointing_at_an_encrypted_column_warns(self):
        class FakeAdmin:
            list_display = ("shown",)

            def shown(self, obj):  # pragma: no cover - never rendered
                return "x"

            shown.admin_order_field = "email"

        (issue,) = self._w005({Patient: FakeAdmin()})
        assert "email" in issue.msg

    def test_a_plaintext_changelist_is_clean(self):
        class FakeAdmin:
            list_display = ("created",)
            ordering = ("-created",)

        assert self._w005({Patient: FakeAdmin()}) == []

    def test_an_unsortable_method_shadowing_a_field_name_is_clean(self):
        """An admin *method* named after an encrypted field, without
        admin_order_field, is not sortable in Django -- warning on it would
        be a false positive (found in the PR #82 review)."""

        class FakeAdmin:
            list_display = ("email",)

            def email(self, obj):  # pragma: no cover - never rendered
                return "redacted"

        assert self._w005({Patient: FakeAdmin()}) == []
