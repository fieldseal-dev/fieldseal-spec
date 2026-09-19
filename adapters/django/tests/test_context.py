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


def _stored_index(pk: int) -> bytes:
    """The sibling column as the database holds it, not the adapter's view."""
    from django.db import connection

    with connection.cursor() as cur:
        cur.execute(f'SELECT "handle_bidx" FROM "{TenantDoc._meta.db_table}" '
                    "WHERE id = %s", [pk])
        (value,) = cur.fetchone()
    return bytes(value)


def test_a_tenant_bound_index_is_scoped_to_its_tenant():
    """The index half of the binding (spec §5.2, §7.2).

    The tenant enters the index context as it enters the envelope's, so the
    same value written in two tenants must store two index values. If it did
    not -- a tenantless index context on a tenant-bound column -- the index
    would link rows across tenants, which the envelope's binding exists to
    prevent, and nothing would fail.
    """
    with tenant_scope(b"tenant-a"):
        a = TenantDoc.objects.create(body="a", handle="ada@example.com")
    with tenant_scope(b"tenant-b"):
        b = TenantDoc.objects.create(body="b", handle="ada@example.com")
    assert _stored_index(a.pk) != _stored_index(b.pk)


def test_a_lookup_finds_only_its_own_tenants_row():
    with tenant_scope(b"tenant-a"):
        a = TenantDoc.objects.create(body="a", handle="ada@example.com")
    with tenant_scope(b"tenant-b"):
        TenantDoc.objects.create(body="b", handle="bob@example.com")
        assert list(TenantDoc.objects.filter(handle="ada@example.com")) == []
    with tenant_scope(b"tenant-a"):
        # nfc-casefold-v1 folds the operand as it folded the stored value.
        found = TenantDoc.objects.get(handle="ADA@example.com")
        assert found.pk == a.pk and found.handle == "ada@example.com"


def test_a_lookup_without_a_tenant_refuses():
    """Fail-closed on the query path too: a tenantless lookup would derive an
    index no tenant-bound row carries and return nothing, which reads as "no
    such row" rather than as the misconfiguration it is."""
    with tenant_scope(b"tenant-a"):
        TenantDoc.objects.create(body="a", handle="ada@example.com")
    with pytest.raises(FieldsealConfigurationError, match="tenant_bound"):
        list(TenantDoc.objects.filter(handle="ada@example.com"))


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
