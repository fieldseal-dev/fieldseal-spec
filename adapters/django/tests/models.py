"""Models for the adapter suite -- the `docs/12` §1 declaration shape."""

from __future__ import annotations

from django.db import models

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta

TABLE_PATIENT = "018f3c2e-0000-7000-8000-000000000001"
COL_EMAIL = "018f3c2e-0000-7000-8000-000000000002"
COL_NOTE = "018f3c2e-0000-7000-8000-000000000003"
COL_AGE = "018f3c2e-0000-7000-8000-000000000004"


class Patient(models.Model):
    """The worked example from `docs/12` §1."""

    email = Encrypted(
        models.EmailField(),
        column_uuid=COL_EMAIL,
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,
        ),
    )
    email_bidx = Encrypted.index_column("email")

    # No index: the common case, and the one that must refuse `exact` rather
    # than scanning or returning nothing.
    note = Encrypted(models.TextField(blank=True), column_uuid=COL_NOTE,
                     null=True)

    # A non-text inner type, to exercise the codec's `value_to_string` route.
    age = Encrypted(models.IntegerField(), column_uuid=COL_AGE, null=True)

    created = models.DateTimeField(auto_now_add=True)

    fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)


TABLE_DOC = "018f3c2e-0000-7000-8000-000000000010"
COL_BODY = "018f3c2e-0000-7000-8000-000000000011"


class TenantDoc(models.Model):
    """A tenant-bound column: the L3 side channel of `docs/12` §4.

    Django field types cannot see the record, so the tenant arrives through a
    contextvar. The property that matters is that an unset tenant *fails*
    rather than quietly encrypting under a tenantless context.
    """

    body = Encrypted(models.TextField(), column_uuid=COL_BODY)

    fieldseal = FieldsealMeta(table_uuid=TABLE_DOC, tenant_bound=True)
