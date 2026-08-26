"""`on_unindexable` and the refusal message (`docs/12` §10).

`encrypt` does not normalize and `blind_index` does, so a value containing a
code point the pinned Unicode version does not define **stores perfectly well
and cannot be fingerprinted**. §10.3 says the right answer differs by column
and a single rule is wrong somewhere: `Patient.email` is machine-shaped and
keeps `refuse`; `Person.legal_name` is exactly where a rare character
legitimately appears and takes `bucket`.

U+0378 is used throughout as the unassigned code point. It is unassigned in
Unicode 17.0.0 -- the version `nfc-casefold-v1` pins -- and the assertion
that it still is belongs to the core's own suite, not here.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from fieldseal_django import unindexable

from .models import Patient, Person

pytestmark = pytest.mark.django_db

#: Unassigned in Unicode 17.0.0, so `nfc-casefold-v1` refuses it.
UNASSIGNED = "͸"


class TestRefuse:
    """The default. A write fails, and it fails as a *field* error."""

    def test_the_write_raises_a_field_level_validation_error(self):
        with pytest.raises(ValidationError) as e:
            Patient.objects.create(email=f"ada{UNASSIGNED}@example.com")
        # §10.1: keyed to the field, so a ModelForm renders it beside the
        # offending input rather than as a non-field error or a 500.
        assert "email" in e.value.message_dict

    def test_the_form_path_refuses_before_the_database_is_touched(self):
        """This is the path §10.1 is actually about.

        `full_clean()` is what every `ModelForm` calls before `save()`, so the
        refusal lands as a field error with no INSERT attempted and no
        transaction involved. `Encrypted.validate()` is what makes that true;
        without it the first refusal would come from `pre_save`, three frames
        into the INSERT.
        """
        person = Patient(email=f"ada{UNASSIGNED}@example.com")
        with pytest.raises(ValidationError) as e:
            person.full_clean()
        assert "email" in e.value.message_dict
        assert Patient.objects.count() == 0  # the connection is still usable

    def test_a_direct_create_raises_but_marks_the_transaction(self):
        """The consequence of `create()` skipping `full_clean()`, recorded
        rather than hidden.

        The index can only be derived in `pre_save`, which runs *inside* the
        INSERT -- and any exception out of `Model.save()` trips its
        `transaction.atomic(savepoint=False)`, so the connection needs a
        rollback before it will answer another query. That is Django's
        behaviour for every exception in `save()`, not something this adapter
        chose, and it is why the form path exists and is documented as the
        supported one.
        """
        from django.db import transaction

        with transaction.atomic():
            with pytest.raises(ValidationError):
                Patient.objects.create(email=f"ada{UNASSIGNED}@example.com")
            assert transaction.get_connection().needs_rollback
            transaction.set_rollback(False)

        assert Patient.objects.count() == 0

    def test_a_lookup_for_such_a_value_raises_rather_than_returning_nothing(self):
        """§10.1: 'never returns an empty queryset'.

        An empty result page would tell the reader their name does not exist
        here, when what is true is that we cannot spell it yet.
        """
        Patient.objects.create(email="ada@example.com")
        with pytest.raises(ValidationError) as e:
            list(Patient.objects.filter(email=f"ada{UNASSIGNED}@example.com"))
        assert "email" in e.value.message_dict


class TestTheMessage:
    """§10.2 is normative in shape. Each of its three demands is a test."""

    def test_it_names_the_character_and_its_position(self):
        msg = unindexable.user_message("nfc-casefold-v1",
                                       f"Ada{UNASSIGNED}Lovelace", noun="name")
        assert UNASSIGNED in msg
        # "Ada" is three characters, so the offender is the 4th.
        assert "4th character" in msg

    def test_it_puts_the_fault_on_the_system(self):
        msg = unindexable.user_message("nfc-casefold-v1",
                                       f"Ada{UNASSIGNED}", noun="name")
        assert "gap on our side" in msg
        assert "not a problem with your name" in msg
        # Wording that blames the reader is wrong on the facts: the value is
        # a name, and the pinned tables are what is behind.
        for blaming in ("invalid", "illegal", "not allowed", "unsupported character"):
            assert blaming not in msg.lower()

    def test_it_offers_a_route_that_ends_with_the_value_stored(self):
        msg = unindexable.user_message("nfc-casefold-v1",
                                       f"Ada{UNASSIGNED}", noun="name")
        assert "contact support" in msg.lower()
        assert "different spelling" in msg.lower()

    def test_the_noun_comes_from_the_column(self):
        assert "this name" in unindexable.user_message(
            "nfc-casefold-v1", UNASSIGNED, noun="name")
        assert "this value" in unindexable.user_message(
            "nfc-casefold-v1", UNASSIGNED)

    def test_the_operator_detail_is_kept_out_of_the_user_message(self):
        """§10.2 requirement 2 does not survive a code point in the same
        sentence, so the engineer-facing half is a separate string."""
        value = f"Ada{UNASSIGNED}"
        user = unindexable.user_message("nfc-casefold-v1", value, noun="name")
        detail = unindexable.operator_detail("nfc-casefold-v1", value)
        assert "U+0378" in detail and "index 3" in detail
        assert "U+0378" not in user
        assert "Unicode" not in user

    def test_the_detail_reaches_the_validation_error_params(self):
        with pytest.raises(ValidationError) as e:
            Patient.objects.create(email=f"a{UNASSIGNED}@example.com")
        (error,) = e.value.error_dict["email"]
        assert error.code == "fieldseal_unindexable"
        assert "U+0378" in error.params["detail"]

    def test_the_ordinal_is_not_embarrassing(self):
        """11th/12th/13th, not 11st/12nd/13rd. Cheap to get wrong and it
        undermines a message whose whole job is to sound like someone
        competent wrote it."""
        for n, want in [(1, "1st"), (2, "2nd"), (3, "3rd"), (4, "4th"),
                        (11, "11th"), (12, "12th"), (13, "13th"),
                        (21, "21st"), (22, "22nd"), (23, "23rd"), (111, "111th")]:
            msg = unindexable.user_message(
                "nfc-casefold-v1", "a" * (n - 1) + UNASSIGNED)
            assert f"({want} character)" in msg, (n, msg)


class TestBucket:
    """The escape hatch, and the reason it needs no query special-casing."""

    def test_the_row_saves(self):
        row = Person.objects.create(legal_name=f"Ada{UNASSIGNED}Lovelace")
        assert Person.objects.get(pk=row.pk).legal_name == f"Ada{UNASSIGNED}Lovelace"

    def test_the_index_column_holds_the_marker_not_null(self):
        """docs/09 §7.2: storing *no* index is not on the menu -- that is the
        silent missing row spec §10.2 forbids."""
        row = Person.objects.create(legal_name=f"Ada{UNASSIGNED}Lovelace")
        stored = Person.objects.filter(pk=row.pk).candidates().values_list(
            "legal_name_bidx", flat=True)[0]
        assert stored is not None
        assert len(bytes(stored)) == 2  # ceil(15/8)

    def test_the_row_is_findable_by_its_own_value(self):
        """The whole point. A query derives the same marker unaided -- the
        bucket is one more §7.4 collision class, not a new mechanism, so the
        query path needs no special case at all."""
        row = Person.objects.create(legal_name=f"Ada{UNASSIGNED}Lovelace")
        found = Person.objects.filter(legal_name=f"Ada{UNASSIGNED}Lovelace")
        assert [p.pk for p in found] == [row.pk]

    def test_two_different_unindexable_values_do_not_match_each_other(self):
        """They share one marker, so SQL cannot separate them -- §7.5
        re-verification is what keeps them apart, and this is the case where
        it is doing all the work rather than trimming a collision."""
        a = Person.objects.create(legal_name=f"Ada{UNASSIGNED}")
        Person.objects.create(legal_name=f"Grace{UNASSIGNED}")

        candidates = Person.objects.filter(
            legal_name=f"Ada{UNASSIGNED}").candidates()
        assert candidates.count() == 2

        found = Person.objects.filter(legal_name=f"Ada{UNASSIGNED}")
        assert [p.pk for p in found] == [a.pk]

    def test_an_ordinary_value_never_lands_in_the_bucket(self):
        """A query for an indexable value derives an ordinary index and never
        touches the marker, because a bucketed row by definition contains a
        character no accepted value can contain."""
        Person.objects.create(legal_name=f"Ada{UNASSIGNED}")
        ordinary = Person.objects.create(legal_name="Grace Hopper")
        found = Person.objects.filter(legal_name="Grace Hopper")
        assert [p.pk for p in found] == [ordinary.pk]


class TestLocate:
    def test_it_uses_the_core_as_the_oracle_and_finds_the_first_offender(self):
        assert unindexable.locate_unindexable(
            "nfc-casefold-v1", f"ab{UNASSIGNED}c") == (2, UNASSIGNED)

    def test_a_clean_value_locates_nothing(self):
        assert unindexable.locate_unindexable("nfc-casefold-v1", "abc") is None

    def test_a_normalizer_that_never_refuses_locates_nothing(self):
        assert unindexable.locate_unindexable("identity", UNASSIGNED) is None
