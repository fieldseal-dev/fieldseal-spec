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
from django.db import connection
from django.db.models import Value

from fieldseal_django.errors import FieldsealNotSupported
from fieldseal_django.fields import index_siblings

from .models import Patient, TwoIndexColumns
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
        """Even a `Value` that would encrypt, one carrying the column as its
        `output_field`, is refused on an indexed column: the index cannot be
        derived from an expression, and writing the column alone is the
        defect. A bare `Value` is refused a step earlier, for not encrypting
        at all."""
        p = Patient.objects.create(email="a@example.com")
        before = (bytes(raw_column(p.pk, "email")), _index(p.pk))
        field = Patient._meta.get_field("email")
        with pytest.raises(FieldsealNotSupported, match="blind index"):
            Patient.objects.filter(pk=p.pk).update(
                email=Value("b@example.com", output_field=field))
        with pytest.raises(FieldsealNotSupported, match="output_field"):
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


def _stored(p: Patient) -> tuple[bytes, bytes | None]:
    return bytes(raw_column(p.pk, "email")), _index(p.pk)


class TestReviewRound1:
    """The #242 review: each finding the reviewer ran, as a test."""

    # 1. An expression as the instance attribute.
    def test_bulk_update_refuses_an_expression_attribute_on_an_indexed_column(self):
        """It was indexed by its repr, and its literal stored as plaintext."""
        p = Patient.objects.get(pk=Patient.objects.create(
            email="a@example.com").pk)
        before, attr = _stored(p), p.email_bidx
        p.email = Value("b@example.com")
        with pytest.raises(FieldsealNotSupported, match="expression"):
            Patient.objects.bulk_update([p], ["email"])
        assert _stored(p) == before
        assert p.email_bidx == attr

    def test_a_caller_built_value_is_refused_rather_than_stored_as_plaintext(self):
        """`Value("x")` resolves to a `CharField`, so Django sent its literal
        to the database unencrypted. Unindexed columns, both paths."""
        p = Patient.objects.get(pk=Patient.objects.create(
            email="a@example.com", note="before").pk)
        before = bytes(raw_column(p.pk, "note"))
        with pytest.raises(FieldsealNotSupported, match="output_field"):
            Patient.objects.filter(pk=p.pk).update(note=Value("secret"))
        p.note = Value("secret")
        with pytest.raises(FieldsealNotSupported, match="expression"):
            Patient.objects.bulk_update([p], ["note"])
        # Still usable: the refusal came before `bulk_update`'s `atomic()`.
        assert bytes(raw_column(p.pk, "note")) == before

    def test_the_field_itself_refuses_a_value_without_its_output_field(self):
        """The layer under the queryset, for a manager that is not ours."""
        field = Patient._meta.get_field("note")
        with pytest.raises(FieldsealNotSupported, match="output_field"):
            field._assert_literal_expression(Value("secret"))
        field._assert_literal_expression(Value("x", output_field=field))
        field._assert_literal_expression(Value(None))

    # 2. Positional `update_fields`.
    def test_a_positional_update_fields_gets_the_index_too(self):
        p = Patient.objects.create(email="a@example.com")
        Patient.objects.bulk_create(
            [Patient(pk=p.pk, email="b@example.com")],
            None, False, True, ["email"], ["id"])
        assert _found("b@example.com") == [p.pk]
        assert _index(p.pk) == _reference_index("b@example.com")

    # 3. Two index columns over one source.
    def _two(self, pk: int) -> tuple[bytes, bytes]:
        with connection.cursor() as cur:
            cur.execute(
                "SELECT email_bidx, email_bidx2 FROM "
                + connection.ops.quote_name(TwoIndexColumns._meta.db_table)
                + " WHERE id = %s", [pk])
            a, b = cur.fetchone()
        return bytes(a), bytes(b)

    def _two_reference(self, email: str) -> tuple[bytes, bytes]:
        ref = TwoIndexColumns.objects.create(email=email)
        out = self._two(ref.pk)
        ref.delete()
        assert out[0] == out[1]
        return out

    def test_both_index_columns_are_known(self):
        assert [f.name for f in index_siblings(TwoIndexColumns)["email"]] == [
            "email_bidx", "email_bidx2"]

    def test_update_writes_both_index_columns(self):
        t = TwoIndexColumns.objects.create(email="a@example.com")
        TwoIndexColumns.objects.filter(pk=t.pk).update(email="b@example.com")
        assert self._two(t.pk) == self._two_reference("b@example.com")

    def test_bulk_update_writes_both_index_columns(self):
        t = TwoIndexColumns.objects.create(email="a@example.com")
        t.email = "b@example.com"
        TwoIndexColumns.objects.bulk_update([t], ["email"])
        assert self._two(t.pk) == self._two_reference("b@example.com")

    def test_save_with_update_fields_must_name_both(self):
        t = TwoIndexColumns.objects.create(email="a@example.com")
        before = self._two(t.pk)
        t.email = "b@example.com"
        with pytest.raises(FieldsealNotSupported, match="'email_bidx2'"):
            t.save(update_fields=["email", "email_bidx"])
        with pytest.raises(FieldsealNotSupported, match="'email_bidx'"):
            t.save(update_fields=["email", "email_bidx2"])
        assert self._two(t.pk) == before
        t.save(update_fields=["email", "email_bidx", "email_bidx2"])
        assert self._two(t.pk) == self._two_reference("b@example.com")

    # 4. `save()` after `only()` / `defer()`.
    @pytest.mark.parametrize("load", [
        lambda qs: qs.only("email"), lambda qs: qs.defer("email_bidx")])
    def test_a_deferred_load_is_named_in_the_refusal(self, load):
        """Django restricts the save to the loaded fields itself; the caller
        wrote no `update_fields`, so the message must not say they did."""
        pk = Patient.objects.create(email="a@example.com").pk
        before = (bytes(raw_column(pk, "email")), _index(pk))
        p = load(Patient.objects).get(pk=pk)
        p.email = "b@example.com"
        with pytest.raises(FieldsealNotSupported) as e:
            p.save()
        assert "only()" in str(e.value) and "defer()" in str(e.value)
        assert "update_fields" not in str(e.value)
        assert (bytes(raw_column(pk, "email")), _index(pk)) == before

    def test_an_explicit_update_fields_keeps_its_own_message(self):
        p = Patient.objects.create(email="a@example.com")
        with pytest.raises(FieldsealNotSupported, match="update_fields"):
            p.save(update_fields=["email"])

    # 6. Instances are left as they were when the call fails.
    def test_a_call_django_rejects_leaves_the_instances_alone(self):
        good = Patient.objects.get(pk=Patient.objects.create(
            email="a@example.com").pk)
        attr = good.email_bidx
        good.email = "b@example.com"
        with pytest.raises(ValueError):
            Patient.objects.bulk_update(
                [good, Patient(email="c@example.com")], ["email"])
        assert good.email_bidx == attr

    def test_a_refused_value_leaves_earlier_instances_alone(self):
        good = Patient.objects.get(pk=Patient.objects.create(
            email="a@example.com").pk)
        bad = Patient.objects.get(pk=Patient.objects.create(
            email="c@example.com").pk)
        attr = good.email_bidx
        good.email = "b@example.com"
        bad.email = Value("d@example.com")
        with pytest.raises(FieldsealNotSupported):
            Patient.objects.bulk_update([good, bad], ["email"])
        assert good.email_bidx == attr

    # 8. The mapping is built once per model.
    def test_the_sibling_mapping_is_cached_per_model(self):
        assert index_siblings(Patient) is index_siblings(Patient)
