"""Regressions for the defects found in and after the PR #73 review round.

Each test names the finding it holds. Two of these are silent-wrong-answer
defects that a fully green suite did not catch, which is the reason they get
their own file rather than being folded quietly into the others.
"""

from __future__ import annotations

import base64

import pytest
from django.core import serializers
from django.db import models
from django.test import override_settings
from django.test.utils import isolate_apps

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta
from fieldseal_django.errors import FieldsealNotSupported

from .models import COL_EMAIL, TABLE_PATIENT, Patient

pytestmark = pytest.mark.django_db


class TestLoaddataIsRefused:
    """Reviewer 1's blocking finding, confirmed worse than reported.

    Before the fix: a fixture reloaded through the ordinary path arrived as
    the base64 of an envelope, passed `to_python` as ordinary text, was
    stored, and was encrypted **again** -- so the row read back as base64
    instead of the plaintext, silently. An `IntegerField` column survived,
    which made the corruption per-inner-type and invisible to a smoke test
    on the wrong column.
    """

    def test_reloading_a_fixture_raises_instead_of_double_encrypting(self):
        Patient.objects.create(email="ada@example.com", note="hello", age=36)
        dump = serializers.serialize("json", Patient.objects.all())
        Patient.objects.all().delete()

        # Django's deserializer wraps a field error in DeserializationError
        # and keeps the message, which is the behaviour we want: it names the
        # model and pk alongside our explanation.
        from django.core.serializers.base import DeserializationError

        with pytest.raises(DeserializationError) as e:
            for obj in serializers.deserialize("json", dump):
                obj.save()
        msg = str(e.value)
        assert "loaddata" in msg
        # The operator's next question is "then how do I move this data".
        assert "backfill" in msg
        assert Patient.objects.count() == 0

    def test_dumpdata_still_emits_ciphertext(self):
        """The refusal must not undo the leak fix: `dumpdata` writing
        plaintext into a fixture file is the failure `value_to_string`
        exists to prevent."""
        Patient.objects.create(email="ada@example.com")
        out = serializers.serialize("json", Patient.objects.all())
        assert "ada@example.com" not in out

    def test_ordinary_plaintext_is_unaffected(self):
        """The refusal keys on the core's §3.4 recognition, so a value that
        merely looks like base64 must still save."""
        p = Patient.objects.create(email="a@b.com", note="aGVsbG8gd29ybGQ=")
        assert Patient.objects.get(pk=p.pk).note == "aGVsbG8gd29ybGQ="

    def test_a_non_envelope_base64_string_is_unaffected(self):
        blob = base64.b64encode(b"\x01\x00\x00 not an envelope").decode()
        p = Patient.objects.create(email="a@b.com", note=blob)
        assert Patient.objects.get(pk=p.pk).note == blob


class TestMakemigrations:
    """`makemigrations` failed outright before the fix: `BlindIndex` had no
    `deconstruct()`, so Django's serializer refused any model carrying one.

    No reviewer found this. The suite builds its schema straight from the
    models through `pytest-django`, so a green run never touched the
    migration machinery every real deployment hits first.
    """

    def test_a_blind_index_is_serializable_into_a_migration(self):
        from django.db.migrations.writer import MigrationWriter

        idx = BlindIndex(idf="hmac-sha512", truncate_bits=15,
                         projected_population=100_000)
        text, imports = MigrationWriter.serialize(idx)
        assert "BlindIndex" in text
        assert "projected_population=100000" in text
        # Defaults stay out, so a migration reads as the declaration did.
        assert "skewed" not in text

    def test_an_override_is_serializable(self):
        from django.db.migrations.writer import MigrationWriter

        from fieldseal_django import Override

        text, _ = MigrationWriter.serialize(
            Override(reason="r", approved_by="a", date="2026-08-25"))
        assert "Override" in text and "approved_by='a'" in text

    def test_makemigrations_runs(self):
        """The end-to-end guard: this is the command that failed, and no unit
        test on `deconstruct()` alone would have caught it -- the serializer
        is what refused, three frames further in."""
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command("makemigrations", "tests", dry_run=True, verbosity=1,
                     stdout=out)
        assert "Patient" in out.getvalue()

    def test_the_whole_field_deconstructs_and_reconstructs(self):
        """`docs/12` §1.1 leans on `deconstruct()` for rename safety: the
        surrogate UUIDs must survive into the migration."""
        from django.db.migrations.writer import MigrationWriter

        field = Patient._meta.get_field("email")
        name, path, args, kwargs = field.deconstruct()
        assert kwargs["column_uuid"] == COL_EMAIL
        text, _ = MigrationWriter.serialize(field)
        assert COL_EMAIL in text


class TestConstraintSitesAreAllChecked:
    """E005 inspected only `Meta.constraints` with a `fields` list, so it
    passed models it exists to reject."""

    def _ids(self, apps):
        from fieldseal_django.checks import check_fieldseal

        return sorted(i.id for i in check_fieldseal(apps=apps))

    def test_unique_together_is_caught(self):
        with isolate_apps("tests") as apps:
            class Bad(models.Model):
                email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL)
                other = models.CharField(max_length=8)

                class Meta:
                    unique_together = [("email", "other")]

                fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

            assert "fieldseal.E005" in self._ids(apps)

    def test_meta_indexes_is_caught(self):
        with isolate_apps("tests") as apps:
            class Bad(models.Model):
                email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL)

                class Meta:
                    indexes = [models.Index(fields=["email"], name="ix_email")]

                fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

            assert "fieldseal.E005" in self._ids(apps)

    def test_an_expression_constraint_is_caught(self):
        with isolate_apps("tests") as apps:
            class Bad(models.Model):
                email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL)

                class Meta:
                    constraints = [models.UniqueConstraint(
                        models.F("email"), name="uq_email_expr")]

                fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

            assert "fieldseal.E005" in self._ids(apps)


class TestConfigurationErrorsAreNotE003:
    """Reviewer 1 #3: a project that has not configured FIELDSEAL yet saw
    "the core refused an index declaration", which sends them to look at
    models that are fine."""

    def test_missing_key_provider_is_E007_not_E003(self):
        from fieldseal_django.checks import check_fieldseal

        with override_settings(FIELDSEAL={"ALLOWED_SUITES": {0xFF01},
                                          "WRITE_SUITE": 0xFF01}):
            ids = sorted(i.id for i in check_fieldseal())
        assert "fieldseal.E007" in ids
        assert "fieldseal.E003" not in ids

    def test_an_unknown_setting_key_is_E007(self):
        from fieldseal_django.checks import check_fieldseal

        with override_settings(FIELDSEAL={"KEY_PROVIDR": None}):
            ids = sorted(i.id for i in check_fieldseal())
        assert "fieldseal.E007" in ids


class TestAdminSearchFieldsWarning:
    """W001 was specified in `docs/12` §5 and simply missing."""

    def test_an_encrypted_field_in_search_fields_warns(self):
        from fieldseal_django.checks import check_fieldseal

        class FakeAdmin:
            search_fields = ("email", "note")

        issues = check_fieldseal(admin_registry={Patient: FakeAdmin()})
        w001 = [i for i in issues if i.id == "fieldseal.W001"]
        assert len(w001) == 2
        assert "icontains" in w001[0].hint

    def test_a_plaintext_search_field_does_not_warn(self):
        from fieldseal_django.checks import check_fieldseal

        class FakeAdmin:
            search_fields = ("created",)

        issues = check_fieldseal(admin_registry={Patient: FakeAdmin()})
        assert [i for i in issues if i.id == "fieldseal.W001"] == []


class TestReadPathsTheMatrixClaims:
    """The matrix cited `test_save_then_read_returns_the_plaintext` for
    `.values()`, which does not exercise it. The claim was true; the citation
    was not."""

    def test_values_decrypts(self):
        Patient.objects.create(email="ada@example.com", age=36)
        assert Patient.objects.values("email", "age").first() == {
            "email": "ada@example.com", "age": 36}

    def test_values_list_decrypts(self):
        Patient.objects.create(email="ada@example.com")
        assert Patient.objects.values_list("email", flat=True).first() == \
            "ada@example.com"

    def test_only_decrypts(self):
        Patient.objects.create(email="ada@example.com")
        assert Patient.objects.only("email").first().email == "ada@example.com"

    def test_raw_decrypts(self):
        """Django decrypts raw *results* even though it cannot encrypt raw
        *parameters* (`docs/04` §1)."""
        Patient.objects.create(email="ada@example.com")
        rows = list(Patient.objects.raw(
            f"SELECT id, email FROM {Patient._meta.db_table}"))
        assert rows[0].email == "ada@example.com"


class TestUpdateAndWhenConditions:
    def test_plain_update_encrypts(self):
        """Reviewer 1 #4: the matrix cited the bulk_update test for this row."""
        from .test_value_path import raw_column

        p = Patient.objects.create(email="a@example.com", note="before")
        Patient.objects.filter(pk=p.pk).update(note="after")
        assert Patient.objects.get(pk=p.pk).note == "after"
        assert b"after" not in raw_column(p.pk, "note")

    def test_a_when_condition_may_reference_any_column(self):
        """Reviewer 3 #2: the walker inspects `result` and `default` but not
        `condition`, deliberately -- a condition selects rows, it does not
        decide stored bytes. Asserted rather than merely intended."""
        from django.db.models import Case, F, TextField, Value, When
        from django.db.models.functions import Cast

        field = Patient._meta.get_field("note")
        field._assert_literal_expression(
            Case(When(age__gt=F("id"), then=Value("x")), default=Value("y"),
                 output_field=TextField()))
        # ... while a computed *result* is still refused.
        with pytest.raises(FieldsealNotSupported):
            field._assert_literal_expression(
                Case(When(age__gt=1, then=Cast(F("email"), TextField())),
                     default=Value("y"), output_field=TextField()))


class TestClientLifecycle:
    def test_changing_settings_rebuilds_the_client(self):
        """Reviewer 3 #12: the `setting_changed` -> `reset_client()` path had
        no test."""
        from fieldseal_django.apps import get_client

        first = get_client()
        assert get_client() is first
        with override_settings(FIELDSEAL={**__import__(
                "django.conf", fromlist=["settings"]).settings.FIELDSEAL}):
            assert get_client() is not first
