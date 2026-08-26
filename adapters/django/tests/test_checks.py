"""System checks (docs/12 §5).

Two of these catch failures that are otherwise *silent*, which is why they
are startup errors rather than documentation: a mis-ordered index sibling
writes a stale index and the row stops being findable with nothing raised,
and a missing `projected_population` would let a column be indexed at a
truncation length nobody sized.
"""

from __future__ import annotations

from django.db import models
from django.test.utils import isolate_apps

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta

from .models import COL_EMAIL, TABLE_PATIENT


def ids(issues):
    return sorted(i.id for i in issues)


def run_checks(apps=None):
    from fieldseal_django.checks import check_fieldseal

    return check_fieldseal(apps=apps)


def test_index_declared_before_its_source_is_E001():
    with isolate_apps("tests") as apps:
        class Bad(models.Model):
            email_bidx = Encrypted.index_column("email")
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(projected_population=100_000))

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert "fieldseal.E001" in ids(run_checks(apps))

def test_declared_index_with_no_sibling_column_is_E001():
    """The mirror failure: the declaration promises L2 and nothing stores it,
    so every lookup would find nothing."""

    with isolate_apps("tests") as apps:
        class Bad(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(projected_population=100_000))

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert "fieldseal.E001" in ids(run_checks(apps))

def test_unique_on_ciphertext_is_E002():
    with isolate_apps("tests") as apps:
        class Bad(models.Model):
            email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL,
                              unique=True)

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        issues = run_checks(apps)
        assert "fieldseal.E002" in ids(issues)
        # The hint must say why moving it to the index column is also wrong --
        # that is the move a reader would otherwise make next (spec §7.10, G12).
        hint = next(i.hint for i in issues if i.id == "fieldseal.E002")
        assert "index column" in hint and "§7.4" in hint

def test_missing_projected_population_is_E003():
    with isolate_apps("tests") as apps:
        class Bad(models.Model):
            email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL,
                              index=BlindIndex())
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert "fieldseal.E003" in ids(run_checks(apps))

def test_truncation_outside_the_band_is_E003_from_the_core():
    """The adapter does not re-implement the §7.4 band; it surfaces the core's
    refusal at startup. `b=30` for P=100,000 is far above the band."""

    with isolate_apps("tests") as apps:
        class Bad(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(truncate_bits=30, projected_population=100_000))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert "fieldseal.E003" in ids(run_checks(apps))

def test_missing_fieldseal_meta_is_E004():
    with isolate_apps("tests") as apps:
        class Bad(models.Model):
            email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL)

        assert "fieldseal.E004" in ids(run_checks(apps))

def test_db_index_on_ciphertext_is_W002():
    with isolate_apps("tests") as apps:
        class Noisy(models.Model):
            email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL,
                              db_index=True)

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert "fieldseal.W002" in ids(run_checks(apps))

def test_base64_storage_is_W003():
    with isolate_apps("tests") as apps:
        class Noisy(models.Model):
            email = Encrypted(models.EmailField(), column_uuid=COL_EMAIL,
                              storage="base64")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        assert "fieldseal.W003" in ids(run_checks(apps))

def test_the_shipped_models_are_clean():
    """The suite's own models must pass every check, or the checks are
    measuring nothing."""
    assert run_checks() == []
