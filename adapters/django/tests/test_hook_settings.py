"""`FIELDSEAL["ON_WARNING"]` and `FIELDSEAL["METRICS"]` (#306 item 2).

The core's two client hooks (`docs/09` §2, built in the Python core by
#223), passed to `Fieldseal(...)` as they are. Also pinned here: the system
check's routing of a failed client build, which these settings made more
likely to be wrong -- a refused hook, like a refused `WRITE_SUITE`, used to be
reported as E003, "the core refused an index declaration".
"""

from __future__ import annotations

import contextlib
import warnings

import pytest
from django.conf import settings
from django.test import override_settings
from fieldseal.errors import (
    FieldsealWarning,
    NotCiphertext,
    ReadModeWarning,
    StaticKeyProviderWarning,
)

from fieldseal_django.apps import build_client, get_client, reset_client
from fieldseal_django.errors import FieldsealConfigurationError
from fieldseal_django.signals import plaintext_read_counts

from .models import Patient
from .test_checks import _client, _model_declarations
from .test_index_check_review import _mti_models
from .test_plaintext_read_signal import patient, plant


def _ids(issues):
    return sorted(i.id for i in issues)


def _issues(apps=None):
    from fieldseal_django.checks import check_fieldseal

    return check_fieldseal(apps=apps)


@contextlib.contextmanager
def fieldseal(**changes):
    """The test settings with `changes` applied, and a client built from
    them on first use."""
    cfg = {**settings.FIELDSEAL, **changes}
    try:
        with override_settings(FIELDSEAL=cfg):
            reset_client()
            yield
    finally:
        reset_client()


class Recorder:
    """A `METRICS` object with both methods."""

    def __init__(self):
        self.plaintext_reads = 0
        self.decrypt_errors: list[str] = []

    def plaintext_read(self):
        self.plaintext_reads += 1

    def decrypt_error(self, code):
        self.decrypt_errors.append(code)


# -- ON_WARNING --------------------------------------------------------------


def test_on_warning_receives_the_static_key_provider_warning_instead_of_warnings():
    got: list[FieldsealWarning] = []
    with fieldseal(ON_WARNING=got.append), \
            warnings.catch_warnings(record=True) as shown:
        warnings.simplefilter("always")
        get_client()
    assert [type(w) for w in got] == [StaticKeyProviderWarning]
    assert not [w for w in shown if issubclass(w.category, FieldsealWarning)]


def test_on_warning_receives_the_read_mode_warning():
    got: list[FieldsealWarning] = []
    with fieldseal(ON_WARNING=got.append, READ_MODE="permissive"):
        get_client()
    assert [type(w) for w in got] == [ReadModeWarning,
                                     StaticKeyProviderWarning]


def test_an_on_warning_that_raises_escalates_at_build_and_is_E010():
    """docs/09 §8.2: a raising handler makes the warning a hard failure."""
    def escalate(w):
        raise w

    with fieldseal(ON_WARNING=escalate):
        with pytest.raises(StaticKeyProviderWarning):
            build_client()
        ids = _ids(_issues())
    assert "fieldseal.E010" in ids
    assert "fieldseal.E003" not in ids


def test_a_non_callable_on_warning_is_E007_not_E003():
    """The core refuses it (`CONFIGURATION_ERROR`); the adapter does not
    repeat the rule, and the check reports it as configuration."""
    with fieldseal(ON_WARNING="log"):
        issues = _issues()
    assert "fieldseal.E003" not in _ids(issues)
    [e007] = [i for i in issues if i.id == "fieldseal.E007"]
    assert "on_warning must be a callable" in e007.msg


# -- METRICS -----------------------------------------------------------------


@pytest.mark.django_db
def test_metrics_receives_decrypt_errors_by_code():
    pk = patient(note="seen")
    plant(pk, "note", b"legacy note")
    m = Recorder()
    with fieldseal(METRICS=m, READ_MODE="strict"):
        with pytest.raises(NotCiphertext):
            Patient.objects.get(pk=pk)
    assert m.decrypt_errors == ["NOT_CIPHERTEXT"]
    assert m.plaintext_reads == 0


@pytest.mark.django_db
@pytest.mark.filterwarnings("ignore::fieldseal.errors.ReadModeWarning")
def test_metrics_plaintext_reads_equal_the_per_field_counts():
    """#306's question about #246: the two count the same reads at the same
    point, so with the adapter as the client's only reader the hook's calls,
    the core's `plaintext_reads` and the per-field counts agree. Neither
    feeds the other."""
    pks = [patient(note="seen", age=36) for _ in range(3)]
    plant(pks[0], "note", b"legacy one")
    plant(pks[1], "note", b"legacy two")
    plant(pks[1], "age", b"36")
    m = Recorder()
    with fieldseal(METRICS=m, READ_MODE="permissive"):
        assert len(list(Patient.objects.filter(pk__in=pks))) == 3
        counts = plaintext_read_counts()
        assert m.plaintext_reads == 3
        assert get_client().plaintext_reads == 3
        assert sum(counts.values()) == 3
    assert m.decrypt_errors == []


def test_a_metrics_class_instead_of_an_instance_is_E007_not_E003():
    with fieldseal(METRICS=Recorder):
        issues = _issues()
    assert "fieldseal.E003" not in _ids(issues)
    assert "fieldseal.E007" in _ids(issues)


# -- with FIELDSEAL["CLIENT"] -----------------------------------------------


@pytest.mark.parametrize("key, value", [
    ("ON_WARNING", lambda w: None),
    ("METRICS", Recorder()),
])
def test_a_hook_with_a_supplied_client_is_refused(key, value):
    """`build_client` returns a supplied client without reading other keys,
    so the hook would change nothing, silently."""
    client = _client(_model_declarations())
    with override_settings(FIELDSEAL={"CLIENT": client, key: value}):
        with pytest.raises(FieldsealConfigurationError,
                           match=f"{key}.*cannot be combined"):
            build_client()
        issues = _issues()
    [e007] = [i for i in issues if i.id == "fieldseal.E007"]
    assert key in e007.msg and "cannot be combined" in e007.msg


def test_a_client_setting_that_is_not_a_client_is_E007_not_E003():
    with override_settings(FIELDSEAL={"CLIENT": lambda: object()}):
        ids = _ids(_issues())
    assert "fieldseal.E007" in ids
    assert "fieldseal.E003" not in ids


# -- the check's routing ----------------------------------------------------


def test_a_write_suite_outside_allowed_suites_is_E007_not_E003():
    """The pre-existing misroute #310 listed: a refused client configuration
    read "the core refused an index declaration"."""
    with fieldseal(WRITE_SUITE=0x0001):
        issues = _issues()
    assert "fieldseal.E003" not in _ids(issues)
    [e007] = [i for i in issues if i.id == "fieldseal.E007"]
    assert "write_suite must be in allowed_suites" in e007.msg


def test_an_index_refused_by_the_core_is_still_E003_with_a_bad_setting():
    """Both wrong: the index is reported, under E003. The configuration
    follows once the index is fixed, one refusal at a time, as the core
    reports them."""
    from django.db import models
    from django.test.utils import isolate_apps

    from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta

    from .models import COL_EMAIL, TABLE_PATIENT

    with isolate_apps("tests") as apps:
        class Bad(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(suite_id=0xFF01, projected_population=100_000,
                                 truncate_bits=63))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        with fieldseal(METRICS=Recorder):
            issues = _issues(apps)
    [e003] = [i for i in issues if i.id == "fieldseal.E003"]
    assert "Bad.email (BlindIndex 'exact')" in e003.msg
    assert "fieldseal.E007" not in _ids(issues)


def test_an_index_inherited_through_multi_table_inheritance_is_still_E003():
    """Two declarations of one index, which the core refuses when it
    registers them. `docs/12` §6 lists it under E003."""
    apps, _, _ = _mti_models()
    issues = _issues(apps)
    [e003] = [i for i in issues if i.id == "fieldseal.E003"]
    assert "duplicate index declaration" in e003.msg
    assert "MtiChild.email" in e003.msg and "MtiParent.email" in e003.msg
