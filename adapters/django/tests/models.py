"""Models for the adapter suite -- the `docs/12` §1 declaration shape."""

from __future__ import annotations

from django.db import models

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta, Override

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


TABLE_PERSON = "018f3c2e-0000-7000-8000-000000000020"
COL_LEGAL_NAME = "018f3c2e-0000-7000-8000-000000000021"


class Person(models.Model):
    """A `docs/12` §10.3 `bucket` column, and the case it exists for.

    A legal name is exactly where a character outside the pinned Unicode
    version legitimately appears, and refusing a person's name is a hard
    failure for that person. So this column takes the other side of §10.3's
    pair from `Patient.email`, which is machine-shaped and stays `refuse`.

    The override carries the same `{reason, approved_by, date}` ceremony spec
    §7.6 requires to relax the cardinality gate, and for the same reason: it
    is a per-column relaxation of a default-deny rule, so it should be a
    recorded act rather than a setting somebody copies.
    """

    legal_name = Encrypted(
        models.CharField(max_length=200),
        column_uuid=COL_LEGAL_NAME,
        unindexable_noun="name",
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,
            on_unindexable="bucket",
            unindexable_override=Override(
                reason="legal names legitimately contain post-pin characters; "
                       "refusing them is a hard failure for the person",
                approved_by="tests",
                date="2026-08-26",
            ),
        ),
    )
    legal_name_bidx = Encrypted.index_column("legal_name")

    fieldseal = FieldsealMeta(table_uuid=TABLE_PERSON)
