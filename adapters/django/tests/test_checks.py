"""System checks (docs/12 §5).

Two of these catch failures that are otherwise *silent*, which is why they
are startup errors rather than documentation: a mis-ordered index sibling
writes a stale index and the row stops being findable with nothing raised,
and a missing `projected_population` would let a column be indexed at a
truncation length nobody sized.
"""

from __future__ import annotations

from django.db import models
from django.test.utils import isolate_apps, override_settings

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


# -- E006: a hand-supplied client must match the models exactly (G18) ---------
#
# This check shipped as a `W004` warning, and untested, because the core kept
# its validated registry private (docs/09 §2 now requires the accessor). Both
# directions are covered here because only one of them is loud: a client
# missing a declared index fails every lookup on that column at runtime, while
# a client carrying an extra index stores values for a column under rules no
# model states and nothing ever raises.


def _client(indexes):
    from fieldseal import Fieldseal
    from fieldseal.keyprovider import StaticKeyProvider

    from .settings import DEK, INDEX_KEY, KEY_ID

    return Fieldseal(
        key_provider=StaticKeyProvider(
            key_id=KEY_ID, tenant_dek=DEK, tenant_index_key=INDEX_KEY),
        allowed_suites={0xFF01}, write_suite=0xFF01,
        indexes=indexes, arm_provisional_suites=True)


def _model_declarations(apps=None):
    from fieldseal_django.apps import build_index_registry

    return build_index_registry(apps)


def test_matching_hand_built_client_passes():
    from fieldseal_django.apps import reset_client

    reset_client()
    client = _client(_model_declarations())
    with override_settings(FIELDSEAL={"CLIENT": client}):
        assert "fieldseal.E006" not in ids(run_checks())
    reset_client()


def test_client_missing_a_declared_index_is_E006():
    from fieldseal_django.apps import reset_client

    reset_client()
    with override_settings(FIELDSEAL={"CLIENT": _client([])}):
        issues = run_checks()
        assert "fieldseal.E006" in ids(issues)
        msg = next(i.msg for i in issues if i.id == "fieldseal.E006")
        assert "absent from the client" in msg
    reset_client()


def test_client_carrying_an_undeclared_index_is_E006():
    """The silent direction: nothing at runtime would report this."""
    from dataclasses import replace

    from fieldseal_django.apps import reset_client

    decls = _model_declarations()
    extra = replace(decls[0], column_uuid=bytes(range(16, 32)))
    reset_client()
    with override_settings(FIELDSEAL={"CLIENT": _client([*decls, extra])}):
        issues = run_checks()
        assert "fieldseal.E006" in ids(issues)
        msg = next(i.msg for i in issues if i.id == "fieldseal.E006")
        assert "declared on no model" in msg
    reset_client()


def test_client_with_different_resolved_parameters_is_E006():
    """The key alone is not enough. A registry key is
    (table_uuid, column_uuid, index_id), so a client can carry exactly the
    right set of indexes and still derive different values for every one of
    them -- a raised Argon2 cost or a different truncation length is a *new
    index* under spec §7.8, not a reconfiguration of an existing one."""
    from dataclasses import replace

    from fieldseal_django.apps import reset_client

    decls = _model_declarations()
    retruncated = [replace(d, truncate_bits=14) for d in decls]
    assert retruncated != decls
    reset_client()
    with override_settings(FIELDSEAL={"CLIENT": _client(retruncated)}):
        issues = run_checks()
        assert "fieldseal.E006" in ids(issues)
        assert "different resolved parameters" in next(
            i.msg for i in issues if i.id == "fieldseal.E006")
    reset_client()


def test_W004_is_withdrawn():
    """The stopgap must be gone, not merely superseded: two ids reporting the
    same condition is how a check suite starts lying about coverage."""
    from fieldseal_django.apps import reset_client

    reset_client()
    with override_settings(FIELDSEAL={"CLIENT": _client([])}):
        assert "fieldseal.W004" not in ids(run_checks())
    reset_client()


def test_client_does_not_disable_E003():
    """FIELDSEAL['CLIENT'] must not silently switch off the core's gates.

    `build_client` returns a supplied client immediately, without assembling
    the registry -- so on this path the core never sees the model
    declarations, and the §7.4 band and §7.6 cardinality gate that E003
    exists to surface would run against nothing. Found while implementing
    E006 (G18): the registry comparison has to validate the model side
    anyway, which is what makes the gate reachable here at all.
    """
    from fieldseal_django.apps import reset_client

    with isolate_apps("tests") as apps:
        class Ungated(models.Model):
            # P below the §7.6 gate with no logged override: the core refuses
            # this declaration at construction.
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(projected_population=64, truncate_bits=4))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        reset_client()
        with override_settings(FIELDSEAL={"CLIENT": _client([])}):
            assert "fieldseal.E003" in ids(run_checks(apps))
        reset_client()
