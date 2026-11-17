"""PR #280 review: the compile-time stale-index check (#240).

Findings 1 and 2 need a multi-table-inheritance child whose indexed column
lives on the parent. The adapter's own client refuses that shape (each model
declares the index, and the client rejects the duplicate), so it is reachable
only with `FIELDSEAL["CLIENT"]`. The models are built in an isolated app
registry, so the shared test models and the default client are untouched,
and the client is supplied here, as the reviewer's reproduction did.
"""

from __future__ import annotations

import pytest
from django.db import connection, models, transaction
from django.db.models import Value
from django.test import override_settings
from django.test.utils import isolate_apps

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta
from fieldseal_django.apps import build_index_registry, reset_client
from fieldseal_django.errors import FieldsealNotSupported

from .models import Patient
from .test_checks import _client
from .test_index_on_partial_writes import _found, _index, _reference_index, _stored

TABLE_MTI = "018f3c2e-0000-7000-8000-0000000000a0"
COL_MTI_EMAIL = "018f3c2e-0000-7000-8000-0000000000a1"


def _mti_models():
    with isolate_apps("tests") as apps:

        class MtiParent(models.Model):
            email = Encrypted(
                models.EmailField(),
                column_uuid=COL_MTI_EMAIL,
                index=BlindIndex(
                    index_id="exact",
                    idf="hmac-sha512",
                    normalize="nfc-casefold-v1",
                    truncate_bits=15,
                    projected_population=100_000,
                ),
            )
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_MTI)

            class Meta:
                app_label = "tests"

        class MtiChild(MtiParent):
            label = models.CharField(max_length=50, default="")

            class Meta:
                app_label = "tests"

    return apps, MtiParent, MtiChild


class TestMultiTableInheritance:
    pytestmark = pytest.mark.django_db(transaction=True)

    @pytest.fixture
    def mti(self):
        apps, parent, child = _mti_models()
        decls = []
        for d in [*build_index_registry(), *build_index_registry(apps)]:
            if d not in decls:
                decls.append(d)
        with connection.schema_editor() as editor:
            editor.create_model(parent)
            editor.create_model(child)
        reset_client()
        try:
            with override_settings(FIELDSEAL={"CLIENT": _client(decls)}):
                yield parent, child
        finally:
            reset_client()
            with connection.schema_editor() as editor:
                editor.delete_model(child)
                editor.delete_model(parent)

    @staticmethod
    def _raw(model, column, pk):
        key = "id" if not model._meta.parents else "mtiparent_ptr_id"
        with connection.cursor() as cur:
            cur.execute(
                f"SELECT {column} FROM {model._meta.db_table} "
                f"WHERE {key} = %s", [pk])
            return cur.fetchone()[0]

    def test_finding1_child_bulk_update_through_the_fieldseal_manager(self, mti):
        """The parent table's UPDATE is a second `UpdateQuery` Django builds
        for the child; the derived mark has to reach it."""
        parent, child = mti
        c = child.objects.create(email="a@x.org", label="one")
        c.email = "b@x.org"
        child.objects.bulk_update([c], ["email"])
        assert child.objects.get(email="b@x.org").pk == c.pk
        ref = parent.objects.create(email="b@x.org")
        assert (bytes(self._raw(parent, "email_bidx", c.pk))
                == bytes(self._raw(parent, "email_bidx", ref.pk)))

    def test_finding2_atomic_undoes_the_child_table_write(self, mti):
        """Django runs the child table's UPDATE before it compiles the
        parent's, so the refusal comes after one statement has run.
        `atomic()` around the call undoes it."""
        _, child = mti
        c = child.objects.create(email="a@x.org", label="one")
        with pytest.raises(FieldsealNotSupported, match="email_bidx"):
            with transaction.atomic():
                child._base_manager.filter(pk=c.pk).update(
                    label="CHANGED", email="b@x.org")
        assert self._raw(child, "label", c.pk) == "one"

    def test_finding2_outside_atomic_the_child_table_is_written(self, mti):
        """Pinned because the docs state it: under autocommit the child's
        columns are written before the refusal. The parent's are not."""
        parent, child = mti
        c = child.objects.create(email="a@x.org", label="one")
        before = bytes(self._raw(parent, "email_bidx", c.pk))
        assert connection.get_autocommit()
        with pytest.raises(FieldsealNotSupported):
            child._base_manager.filter(pk=c.pk).update(
                label="CHANGED", email="b@x.org")
        assert self._raw(child, "label", c.pk) == "CHANGED"
        assert bytes(self._raw(parent, "email_bidx", c.pk)) == before
        assert child.objects.get(email="a@x.org").pk == c.pk


@pytest.mark.django_db
class TestSingleTable:
    def test_finding3_upsert_updating_only_the_index_is_refused(self):
        p = Patient.objects.create(email="a@example.com")
        before = _stored(p)
        for manager in (Patient._base_manager, Patient.objects):
            with pytest.raises(FieldsealNotSupported, match="'email'"), \
                    transaction.atomic():
                manager.bulk_create(
                    [Patient(pk=p.pk, email="b@example.com")],
                    update_conflicts=True, update_fields=["email_bidx"],
                    unique_fields=["id"])
        assert _stored(p) == before

    def test_finding4_an_explicit_value_expression_is_left_to_the_caller(self):
        """Only the `Case` a plain `bulk_update` builds is refused."""
        p = Patient.objects.create(email="a@example.com")
        derived = _reference_index("b@example.com")
        Patient._base_manager.filter(pk=p.pk).update(
            email="b@example.com", email_bidx=Value(derived))
        assert _found("b@example.com") == [p.pk]
        assert _index(p.pk) == derived

    def test_finding6_the_refusal_names_a_remedy_that_works_without_the_manager(self):
        p = Patient.objects.create(email="a@example.com")
        with pytest.raises(FieldsealNotSupported, match=r"`save\(\)`"), \
                transaction.atomic():
            Patient._base_manager.filter(pk=p.pk).update(email="b@example.com")


def test_finding7_the_hook_exists_only_on_an_indexed_column():
    """Django's Postgres INSERT compiler keeps its UNNEST bulk insert only
    when no field has `get_placeholder_sql`."""
    email = Patient._meta.get_field("email")
    note = Patient._meta.get_field("note")
    assert email.index is not None and note.index is None
    assert hasattr(email, "get_placeholder_sql")
    assert hasattr(email, "get_placeholder")
    assert not hasattr(note, "get_placeholder_sql")
    assert not hasattr(note, "get_placeholder")


@pytest.mark.django_db
def test_finding8_the_check_runs_once_per_statement(monkeypatch):
    import fieldseal_django.fields as fields

    calls = []
    real = fields.index_siblings

    def counting(model):
        calls.append(model)
        return real(model)

    objs = [Patient.objects.create(email=f"{i}@example.com") for i in range(5)]
    for o in objs:
        o.email = "x" + o.email
    monkeypatch.setattr(fields, "index_siblings", counting)
    Patient.objects.bulk_update(objs, ["email"])
    checked = [m for m in calls if m is Patient]
    # The queryset asks once per call to derive; the field check asks once
    # per statement, not once per instance.
    assert len(checked) <= 4, len(checked)
