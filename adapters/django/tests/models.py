"""Models for the adapter suite -- the `docs/12` §1 declaration shape."""

from __future__ import annotations

from django.db import models
from django.db.models import Q

from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta, Override

TABLE_PATIENT = "018f3c2e-0000-7000-8000-000000000001"
COL_EMAIL = "018f3c2e-0000-7000-8000-000000000002"
COL_NOTE = "018f3c2e-0000-7000-8000-000000000003"
COL_AGE = "018f3c2e-0000-7000-8000-000000000004"
COL_NICKNAME = "018f3c2e-0000-7000-8000-000000000005"


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

    # Nullable *and* indexed: the combination the NULL query semantics need.
    # NULL plaintext stores NULL in both columns, so `filter(nickname=None)`
    # and `__isnull` are answered exactly by the envelope column with no
    # blind index involved.
    nickname = Encrypted(
        models.CharField(max_length=100),
        column_uuid=COL_NICKNAME,
        null=True,
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,
        ),
    )
    nickname_bidx = Encrypted.index_column("nickname")

    created = models.DateTimeField(auto_now_add=True)

    fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

    class Meta:
        # A *plaintext* get_latest_by: the earliest()/latest() no-argument
        # fallback must keep working when the declaration is fine (the
        # encrypted-declaration case is E009, tested in isolation).
        get_latest_by = "created"


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


TABLE_VISIT = "018f3c2e-0000-7000-8000-000000000030"
COL_REASON = "018f3c2e-0000-7000-8000-000000000031"


class Visit(models.Model):
    """A relation onto `Patient`, for the traversal refusals (docs/12 §3.2).

    It carries an indexed encrypted column of its own so its manager is the
    verifying one: the traversal refusal has two layers -- filter() time on a
    `FieldsealQuerySet`, compile time for every other queryset -- and this
    model exercises both (the second through a hand-built plain queryset).
    """

    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    reason = Encrypted(
        models.CharField(max_length=100),
        column_uuid=COL_REASON,
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,
        ),
    )
    reason_bidx = Encrypted.index_column("reason")

    fieldseal = FieldsealMeta(table_uuid=TABLE_VISIT)


class Referral(models.Model):
    """An FK whose `limit_choices_to` names an encrypted column ([#118]).

    Not a declaration anyone should write, and that is exactly why it is
    here: Django applies `limit_choices_to` through `complex_filter(Q)` at
    four sites, and two of them are not the caller's choice of manager.
    `ForeignKey.validate` uses `Patient._base_manager` -- a plain `Manager`
    -- so an ordinary `full_clean()` on this model reached the blind index
    with no queryset layer above it at all; `Field.get_choices` uses
    `_default_manager`, so a form choice list reached it through the
    verifying queryset but round the side of `_filter_or_exclude`, recording
    no §7.5 obligation. One declaration, both doors.
    """

    patient = models.ForeignKey(
        Patient,
        on_delete=models.CASCADE,
        limit_choices_to=Q(email="ada@example.com"),
    )
