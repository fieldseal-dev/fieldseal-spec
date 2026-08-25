"""Tenant binding (docs/12 §4) -- the L3 side channel, and its fail-closed rule.

Spec §10 rates Django's context binding as "documented contextvar side
channel ⚠️" because field types cannot see the record. The warning sign is
earned; what makes the arrangement safe rather than merely documented is that
an unset tenant refuses the write.
"""

from __future__ import annotations

import pytest
from fieldseal.errors import FieldsealError

from fieldseal_django import tenant_scope
from fieldseal_django.errors import FieldsealConfigurationError

from .models import TenantDoc

pytestmark = pytest.mark.django_db


def test_writing_without_a_tenant_refuses_rather_than_falling_back():
    """The failure this whole design is arranged around.

    Encrypting under a tenantless context would succeed, store a row no
    correctly configured reader can decrypt, and say nothing until someone
    tried to read it back.
    """
    with pytest.raises(FieldsealConfigurationError) as e:
        TenantDoc.objects.create(body="hello")
    msg = str(e.value)
    assert "tenant_bound" in msg
    # The message must name the paths that run outside the middleware, since
    # that is where this actually bites.
    assert "management commands" in msg and "set_tenant" in msg


def test_round_trip_within_one_tenant():
    with tenant_scope(b"tenant-a"):
        d = TenantDoc.objects.create(body="hello")
        assert TenantDoc.objects.get(pk=d.pk).body == "hello"


def test_another_tenant_cannot_read_the_row():
    """Context binding is cryptographic, not a filter: the wrong tenant
    derives a different record key, so the read fails rather than returning
    someone else's data."""
    with tenant_scope(b"tenant-a"):
        d = TenantDoc.objects.create(body="hello")
    with tenant_scope(b"tenant-b"), pytest.raises(FieldsealError):
        TenantDoc.objects.get(pk=d.pk)


def test_the_scope_is_restored_on_exit():
    from fieldseal_django import get_tenant

    with tenant_scope(b"outer"):
        with tenant_scope(b"inner"):
            assert get_tenant() == b"inner"
        assert get_tenant() == b"outer"
    assert get_tenant() is None


def test_a_str_tenant_is_encoded_utf8():
    """Accepting `str` is ergonomics; the encoding must be pinned, because a
    tenant id that encodes differently in two runtimes derives a different
    key and the rows stop being readable across them."""
    with tenant_scope("tenant-a"):
        d = TenantDoc.objects.create(body="hello")
    with tenant_scope(b"tenant-a"):
        assert TenantDoc.objects.get(pk=d.pk).body == "hello"
