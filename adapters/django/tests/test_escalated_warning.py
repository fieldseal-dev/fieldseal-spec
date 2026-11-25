"""E010: building the client failed, and not because of an index (#306).

Since #223 the Python core warns at construction (spec §8: a
`StaticKeyProvider` outside test configuration). A deployment can escalate
that warning to an error with `-W error`, a `warnings` filter, or an
`on_warning` that raises (`docs/09` §8.2). `manage.py check` used to report
every exception from `build_client` as E003, "the core refused an index
declaration", which sends the operator to models that are fine. Measured in
the #223 review on the patient-directory demo: `-W error` gave E003 with the
text "StaticKeyProvider holds one key…".
"""

from __future__ import annotations

import warnings

import pytest
from django.db import models
from django.test import override_settings
from django.test.utils import isolate_apps
from fieldseal.errors import StaticKeyProviderWarning
from fieldseal.keyprovider import StaticKeyProvider

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta

from .models import COL_EMAIL, TABLE_PATIENT
from .settings import DEK, FIELDSEAL, INDEX_KEY, KEY_ID


def _issues(apps=None):
    from fieldseal_django.checks import check_fieldseal

    return check_fieldseal(apps=apps)


def _ids(issues):
    return sorted(i.id for i in issues)


def test_an_escalated_static_key_provider_warning_is_E010_not_E003():
    with warnings.catch_warnings():
        warnings.simplefilter("error", StaticKeyProviderWarning)
        issues = _issues()
    assert "fieldseal.E003" not in _ids(issues)
    [e010] = [i for i in issues if i.id == "fieldseal.E010"]
    assert "StaticKeyProviderWarning" in e010.msg
    assert "escalated" in e010.msg
    assert "not an index refusal" in e010.hint


def test_an_on_warning_that_raises_is_E010_not_E003():
    """The other escalation route: a hand-built client whose `on_warning`
    raises. The adapter does not expose `on_warning` (#306 item 2), so
    `FIELDSEAL["CLIENT"]` is the way to reach it today."""
    from fieldseal import Fieldseal

    from fieldseal_django.apps import build_index_registry

    def raise_it(w):
        raise w

    def client():
        return Fieldseal(
            key_provider=StaticKeyProvider(
                key_id=KEY_ID, tenant_dek=DEK, tenant_index_key=INDEX_KEY),
            allowed_suites={0xFF01}, write_suite=0xFF01,
            indexes=build_index_registry(),
            arm_provisional_suites=True, on_warning=raise_it)

    with override_settings(FIELDSEAL={**FIELDSEAL, "CLIENT": client}):
        ids = _ids(_issues())
    assert "fieldseal.E010" in ids
    assert "fieldseal.E003" not in ids


def test_a_key_provider_that_raises_is_E010_not_E003():
    def provider():
        raise RuntimeError("the secrets mount is not there")

    with override_settings(FIELDSEAL={**FIELDSEAL, "KEY_PROVIDER": provider}):
        issues = _issues()
    assert "fieldseal.E003" not in _ids(issues)
    [e010] = [i for i in issues if i.id == "fieldseal.E010"]
    assert "RuntimeError" in e010.msg
    assert "the secrets mount is not there" in e010.msg


def test_an_index_refusal_is_still_E003_with_the_warning_escalated():
    """The core validates the index registry before it warns, so a refused
    declaration keeps its own diagnosis even in a process running with
    `-W error`."""
    with isolate_apps("tests") as apps:
        class Bad(models.Model):
            email = Encrypted(
                models.EmailField(), column_uuid=COL_EMAIL,
                index=BlindIndex(suite_id=0xFF01))
            email_bidx = Encrypted.index_column("email")

            fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

        with warnings.catch_warnings():
            warnings.simplefilter("error", StaticKeyProviderWarning)
            ids = _ids(_issues(apps))
    assert "fieldseal.E003" in ids
    assert "fieldseal.E010" not in ids


def test_the_adapter_still_lets_the_core_warn():
    """The suite filters `StaticKeyProviderWarning` in its pytest config
    (#306 item 3). That is test configuration only: a client the adapter
    builds from these settings still warns."""
    from fieldseal_django.apps import build_client

    with pytest.warns(StaticKeyProviderWarning):
        build_client()
