"""The verifying manager: auto-installed, or E008 (docs/12 §3.2, §5).

Decision C puts §7.5 re-verification on the *default* path so that nothing
has to be remembered. That only holds if the manager arrives without being
asked for -- and only where the adapter can install it without overwriting a
choice the model author made.
"""

from __future__ import annotations

from django.db import models
from django.test.utils import isolate_apps

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta
from fieldseal_django.query import FieldsealManager, FieldsealQuerySet

from .models import COL_EMAIL, COL_NOTE, TABLE_PATIENT


def ids(issues):
    return sorted(i.id for i in issues)


def run_checks(apps=None):
    from fieldseal_django.checks import check_fieldseal

    return check_fieldseal(apps=apps)


def _index():
    return BlindIndex(index_id="exact", idf="hmac-sha512",
                      normalize="nfc-casefold-v1", truncate_bits=15,
                      projected_population=100_000)


def test_the_manager_is_installed_without_being_asked_for():
    """The shipped fixture model declares no manager and gets the verifying
    one, which is what makes `filter()` safe by default."""
    from .models import Patient

    assert isinstance(Patient.objects, FieldsealManager)
    assert isinstance(Patient.objects.all(), FieldsealQuerySet)


def test_a_model_with_no_index_is_left_alone():
    """Nothing to verify, so nothing to install. Touching every model with an
    encrypted column would be scope the adapter has not earned."""
    with isolate_apps("tests") as apps:
        class NoIndex(models.Model):
            note = Encrypted(models.TextField(), column_uuid=COL_NOTE,
                             null=True)

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert not isinstance(NoIndex.objects, FieldsealManager)
        assert "fieldseal.E008" not in ids(run_checks(apps))


def test_a_hand_written_manager_is_not_replaced_but_is_reported():
    """The adapter must not silently swap a manager somebody wrote.

    Replacing it would change behaviour the model author specified; leaving
    it unreported would ship the unverified queryset decision C exists to
    prevent. E008 is the third option.
    """
    with isolate_apps("tests") as apps:
        class Custom(models.Model):
            email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL,
                              index=_index())
            email_bidx = Encrypted.index_column("email")

            objects = models.Manager()

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert not isinstance(Custom.objects, FieldsealManager)
        issues = run_checks(apps)
        assert "fieldseal.E008" in ids(issues)
        msg = next(i.msg for i in issues if i.id == "fieldseal.E008")
        assert "does not re-verify" in msg


def test_mixing_the_queryset_in_satisfies_the_check():
    """The documented remedy has to actually work, or E008 is a dead end."""
    with isolate_apps("tests") as apps:
        class MyManager(FieldsealManager):
            pass

        class Mixed(models.Model):
            email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL,
                              index=_index())
            email_bidx = Encrypted.index_column("email")

            objects = MyManager()

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert "fieldseal.E008" not in ids(run_checks(apps))
