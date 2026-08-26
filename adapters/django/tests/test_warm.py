"""`warm()` wiring (`docs/12` §7, spec §11.2).

Every field hook is synchronous (`docs/04` §1), so `docs/09` §8.2 confines
KMS unwrapping to `warm` and forbids the value path from blocking on network.
The consequence is exact and is what these tests are about: an
`EnvelopeKeyProvider` deployment whose cache is cold serves `KEY_UNAVAILABLE`
for **every** read until something warms it.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import call_command
from django.test.utils import override_settings

from fieldseal_django.warm import warm_contexts


def run(*args):
    out = StringIO()
    call_command("fieldseal_warm", *args, stdout=out)
    return out.getvalue()


class TestContexts:
    def test_every_encrypted_column_is_covered(self):
        contexts, _ = warm_contexts()
        columns = {(c.table_uuid, c.column_uuid) for c in contexts}
        # Patient.email, Patient.note, Patient.age, Patient.nickname,
        # Person.legal_name, Visit.reason.
        assert len(columns) == 6

    def test_an_indexed_column_warms_its_index_key_too(self):
        """spec §5.2: the index key is a **sibling** of the tenant DEK, not
        derived from it — so a cache warmed only for the data key still stalls
        every indexed lookup, and the failure looks like a slow query rather
        than a cold cache."""
        contexts, _ = warm_contexts()
        purposes = {c.purpose for c in contexts}
        assert "encrypt" in purposes
        assert "index:exact" in purposes

    def test_tenant_bound_columns_are_skipped_and_named(self):
        """The adapter cannot enumerate a deployment's tenants — they live in
        application data under a schema this package knows nothing about."""
        contexts, skipped = warm_contexts()
        assert "tests.TenantDoc.body" in skipped
        assert not any(c.tenant_id for c in contexts)

    def test_a_named_tenant_is_warmed(self):
        contexts, skipped = warm_contexts(tenants=["t1"])
        assert skipped == []
        assert any(c.tenant_id == b"t1" for c in contexts)

    def test_each_named_tenant_gets_its_own_context(self):
        """Per-tenant keys mean per-tenant cache entries; warming one tenant
        does nothing for the next."""
        contexts, _ = warm_contexts(tenants=["t1", "t2"])
        tenants = {c.tenant_id for c in contexts if c.tenant_id}
        assert tenants == {b"t1", b"t2"}


class TestCommand:
    def test_it_warms_and_says_what_it_warmed(self):
        out = run()
        assert "Warmed" in out

    def test_it_names_each_skipped_column_rather_than_counting_them(self):
        """"3 columns skipped" is not something an operator can act on at
        3am."""
        out = run()
        assert "tests.TenantDoc.body" in out
        assert "KEY_UNAVAILABLE" in out

    def test_supplying_the_tenant_removes_the_warning(self):
        out = run("--tenant", "t1")
        assert "skipped" not in out

    def test_warming_is_a_no_op_not_an_error_for_providers_without_it(self):
        """The suite runs on `StaticKeyProvider`, which holds its keys and
        needs no prefetch. docs/09 §8: warming is never required for
        correctness, so it must not be an error where it is pointless."""
        run()  # would raise if the no-op path were not real


class TestReadyHook:
    def test_it_is_off_by_default(self):
        """`ready()` runs for `makemigrations`, `shell`, `collectstatic` and
        every test process. Warming unconditionally would make a command that
        touches no encrypted row pay a KMS round trip — and fail hard when the
        key service is down, so a migration could not run because of it."""
        from django.conf import settings

        assert not settings.FIELDSEAL.get("WARM_ON_READY")

    def test_enabling_it_warms(self):
        from fieldseal_django.apps import FieldsealConfig, reset_client

        cfg = dict(__import__("django").conf.settings.FIELDSEAL)
        cfg["WARM_ON_READY"] = True
        cfg["WARM_TENANTS"] = ["t1"]
        with override_settings(FIELDSEAL=cfg):
            reset_client()
            app = FieldsealConfig.create("fieldseal_django")
            app._warm_on_ready()  # no warning: every column covered
            reset_client()

    def test_it_warns_rather_than_dying_when_warming_fails(self):
        """A web worker that exits on a transient KMS blip takes the
        deployment down for a condition the next request might not even
        have."""
        from fieldseal_django.apps import FieldsealConfig, reset_client

        cfg = {"WARM_ON_READY": True, "KEY_PROVIDER": lambda: 1 / 0,
               "ALLOWED_SUITES": {0xFF01}, "WRITE_SUITE": 0xFF01}
        with override_settings(FIELDSEAL=cfg):
            reset_client()
            app = FieldsealConfig.create("fieldseal_django")
            with pytest.warns(RuntimeWarning, match="warming failed"):
                app._warm_on_ready()
            reset_client()

    def test_it_warns_when_tenant_bound_columns_go_unwarmed(self):
        from fieldseal_django.apps import FieldsealConfig, reset_client

        cfg = dict(__import__("django").conf.settings.FIELDSEAL)
        cfg["WARM_ON_READY"] = True
        with override_settings(FIELDSEAL=cfg):
            reset_client()
            app = FieldsealConfig.create("fieldseal_django")
            with pytest.warns(RuntimeWarning, match="tenant-bound"):
                app._warm_on_ready()
            reset_client()
