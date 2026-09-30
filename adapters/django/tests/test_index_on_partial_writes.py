"""The blind index is written with its column on every write path (#240).

The index is derived in the index column's `pre_save`, and Django does not
call `pre_save` on every write: `QuerySet.update()` and `bulk_update()` never
do, `save(update_fields=...)` does only for the fields it names, and the
conflict half of a `bulk_create` upsert sets only the named columns. Each of
those wrote the new envelope and left the old index, so the row could not be
found by its new value and nothing raised.

Every positive test here asserts the two things that were false before: the
row is found by its new value, and its stored index equals the one an
ordinary `create()` of the same value stores.
"""

from __future__ import annotations

import pytest
from django.db.models import Value

from fieldseal_django.errors import FieldsealNotSupported

from .models import Patient
from .test_value_path import raw_column

pytestmark = pytest.mark.django_db


def _index(pk: int, column: str = "email_bidx") -> bytes | None:
    raw = raw_column(pk, column)
    return None if raw is None else bytes(raw)


def _reference_index(email: str) -> bytes:
    """What `create()` stores as the index for `email`: the `pre_save` path,
    which #240 did not touch."""
    ref = Patient.objects.create(email=email)
    out = _index(ref.pk)
    ref.delete()
    assert out is not None
    return out


def _found(email: str) -> list[int]:
    return [p.pk for p in Patient.objects.filter(email=email)]


class TestBulkUpdate:
    def test_the_index_follows_the_column(self):
        p = Patient.objects.create(email="a@example.com")
        p.email = "b@example.com"
        Patient.objects.bulk_update([p], ["email"])
        assert _found("b@example.com") == [p.pk]
        assert _found("a@example.com") == []
        assert _index(p.pk) == _reference_index("b@example.com")

    def test_naming_the_index_column_too_derives_it_rather_than_trusting_it(self):
        """The instance's own index attribute is stale by construction: it was
        loaded, or derived, for the old value."""
        p = Patient.objects.get(pk=Patient.objects.create(
            email="a@example.com").pk)
        p.email = "b@example.com"
        Patient.objects.bulk_update([p], ["email", "email_bidx"])
        assert _found("b@example.com") == [p.pk]
        assert _index(p.pk) == _reference_index("b@example.com")

    def test_every_instance_gets_its_own_index(self):
        rows = [Patient.objects.create(email=f"old{i}@example.com")
                for i in range(3)]
        for i, p in enumerate(rows):
            p.email = f"new{i}@example.com"
        Patient.objects.bulk_update(rows, ["email"], batch_size=2)
        for i, p in enumerate(rows):
            assert _found(f"new{i}@example.com") == [p.pk]

    def test_a_null_value_nulls_the_index(self):
        # Loaded, not just created, so the instance carries the old index:
        # a write that trusted the attribute would store it again.
        p = Patient.objects.get(pk=Patient.objects.create(
            email="a@example.com", nickname="ada").pk)
        assert _index(p.pk, "nickname_bidx") is not None
        p.nickname = None
        Patient.objects.bulk_update([p], ["nickname"])
        assert _index(p.pk, "nickname_bidx") is None

    def test_an_unindexed_column_is_written_as_before(self):
        p = Patient.objects.create(email="a@example.com", note="before")
        before = _index(p.pk)
        p.note = "after"
        Patient.objects.bulk_update([p], ["note"])
        assert Patient.objects.get(pk=p.pk).note == "after"
        assert _index(p.pk) == before


class TestUpdate:
    def test_the_index_follows_the_column(self):
        p = Patient.objects.create(email="a@example.com")
        Patient.objects.filter(pk=p.pk).update(email="b@example.com")
        assert _found("b@example.com") == [p.pk]
        assert _found("a@example.com") == []
        assert _index(p.pk) == _reference_index("b@example.com")

    def test_a_null_value_nulls_the_index(self):
        p = Patient.objects.create(email="a@example.com", nickname="ada")
        Patient.objects.filter(pk=p.pk).update(nickname=None)
        assert _index(p.pk, "nickname_bidx") is None

    def test_an_expression_is_refused_on_an_indexed_column(self):
        """A `Value` is a literal the column itself accepts, but the index
        cannot be derived from an expression, and writing the column alone
        is the defect."""
        p = Patient.objects.create(email="a@example.com")
        before = (bytes(raw_column(p.pk, "email")), _index(p.pk))
        with pytest.raises(FieldsealNotSupported, match="blind index"):
            Patient.objects.filter(pk=p.pk).update(email=Value("b@example.com"))
        assert (bytes(raw_column(p.pk, "email")), _index(p.pk)) == before

    def test_the_column_and_its_index_in_one_call_are_refused(self):
        p = Patient.objects.create(email="a@example.com")
        before = (bytes(raw_column(p.pk, "email")), _index(p.pk))
        with pytest.raises(FieldsealNotSupported, match="drop 'email_bidx'"):
            Patient.objects.filter(pk=p.pk).update(
                email="b@example.com", email_bidx=b"\x00\x00")
        assert (bytes(raw_column(p.pk, "email")), _index(p.pk)) == before


class TestSaveWithUpdateFields:
    def test_the_column_without_its_index_is_refused(self):
        p = Patient.objects.create(email="a@example.com")
        before = (bytes(raw_column(p.pk, "email")), _index(p.pk))
        p.email = "b@example.com"
        with pytest.raises(FieldsealNotSupported, match="'email_bidx'"):
            p.save(update_fields=["email"])
        assert (bytes(raw_column(p.pk, "email")), _index(p.pk)) == before

    def test_naming_both_writes_both(self):
        p = Patient.objects.create(email="a@example.com")
        p.email = "b@example.com"
        p.save(update_fields=["email", "email_bidx"])
        assert _found("b@example.com") == [p.pk]
        assert _index(p.pk) == _reference_index("b@example.com")

    def test_other_fields_are_not_affected(self):
        p = Patient.objects.create(email="a@example.com", note="before")
        p.note = "after"
        p.save(update_fields=["note"])
        assert Patient.objects.get(pk=p.pk).note == "after"

    def test_update_or_create_still_finds_the_row_by_its_new_value(self):
        """Django's `update_or_create` saves with `update_fields` and adds
        every field that overrides `pre_save`, which the index column does."""
        p = Patient.objects.create(email="a@example.com")
        Patient.objects.update_or_create(
            pk=p.pk, defaults={"email": "b@example.com"})
        assert _found("b@example.com") == [p.pk]


class TestBulkCreateUpsert:
    def test_the_conflict_update_writes_the_index_with_the_column(self):
        p = Patient.objects.create(email="a@example.com")
        Patient.objects.bulk_create(
            [Patient(pk=p.pk, email="b@example.com")],
            update_conflicts=True, update_fields=["email"],
            unique_fields=["id"])
        assert _found("b@example.com") == [p.pk]
        assert _index(p.pk) == _reference_index("b@example.com")
