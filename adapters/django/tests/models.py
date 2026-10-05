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
COL_HANDLE = "018f3c2e-0000-7000-8000-000000000012"


class TenantDoc(models.Model):
    """A tenant-bound column: the L3 side channel of `docs/12` §4.

    Django field types cannot see the record, so the tenant arrives through a
    contextvar. The property that matters is that an unset tenant *fails*
    rather than quietly encrypting under a tenantless context.
    """

    body = Encrypted(models.TextField(), column_uuid=COL_BODY)

    # Indexed *and* tenant-bound: the index path's half of the binding. The
    # tenant enters the index context exactly as it enters the envelope's, so
    # one value in two tenants is two index values and a lookup is scoped to
    # the tenant it runs under (spec §5.2, §7.2). Nullable so the rows the
    # other tenant tests write need not carry one.
    handle = Encrypted(
        models.CharField(max_length=100),
        column_uuid=COL_HANDLE,
        null=True,
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,
        ),
    )
    handle_bidx = Encrypted.index_column("handle")

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


TABLE_TWO_INDEXES = "018f3c2e-0000-7000-8000-000000000040"
COL_TWO_EMAIL = "018f3c2e-0000-7000-8000-000000000041"


class TwoIndexColumns(models.Model):
    """Two index columns over one source (#242 review).

    No system check forbids it, and `pre_save` derives each column on its
    own, so every path that writes the index outside `pre_save` has to write
    both as well.
    """

    email = Encrypted(
        models.EmailField(),
        column_uuid=COL_TWO_EMAIL,
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,
        ),
    )
    email_bidx = Encrypted.index_column("email")
    email_bidx2 = Encrypted.index_column("email")

    fieldseal = FieldsealMeta(table_uuid=TABLE_TWO_INDEXES)


# -- backfill fixtures (tools/backfill/PROCEDURE.md §6.1) ----------------------

TABLE_LEGACY_IN_PLACE = "018f3c2e-0000-7000-8000-000000000050"
COL_LEGACY_SECRET = "018f3c2e-0000-7000-8000-000000000051"
COL_LEGACY_MEMO = "018f3c2e-0000-7000-8000-000000000052"


class LegacyInPlace(models.Model):
    """The in-place shape: the encrypted column itself holds legacy bytes.

    Only a `binary` column can be in this state, and only when the legacy
    bytes are already spec §3.6's rendering of the value. The tests put them
    there with raw SQL, since every ORM write encrypts.
    """

    secret = Encrypted(
        models.CharField(max_length=100),
        column_uuid=COL_LEGACY_SECRET,
        null=True,
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,
        ),
    )
    secret_bidx = Encrypted.index_column("secret")
    memo = Encrypted(models.TextField(), column_uuid=COL_LEGACY_MEMO,
                     null=True)

    fieldseal = FieldsealMeta(table_uuid=TABLE_LEGACY_IN_PLACE)


TABLE_LEGACY_TWO_COLUMN = "018f3c2e-0000-7000-8000-000000000060"
COL_LEGACY_EMAIL = "018f3c2e-0000-7000-8000-000000000061"
COL_LEGACY_AGE = "018f3c2e-0000-7000-8000-000000000062"


class LegacyTwoColumn(models.Model):
    """The two-column shape (`docs/04` §11): a legacy plaintext column
    beside each encrypted one.

    `age_legacy` is text on purpose: a legacy value that is not an integer
    is refused by the codec while the write is compiled, which is the
    failure that has to stay one value's failure.
    """

    email_legacy = models.CharField(max_length=200, null=True)
    email = Encrypted(
        models.EmailField(),
        column_uuid=COL_LEGACY_EMAIL,
        null=True,
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,
        ),
    )
    email_bidx = Encrypted.index_column("email")
    age_legacy = models.CharField(max_length=20, null=True)
    age = Encrypted(models.IntegerField(), column_uuid=COL_LEGACY_AGE,
                    null=True)

    fieldseal = FieldsealMeta(table_uuid=TABLE_LEGACY_TWO_COLUMN)


TABLE_LEGACY_UUID_KEY = "018f3c2e-0000-7000-8000-000000000070"
COL_LEGACY_UUID_NAME = "018f3c2e-0000-7000-8000-000000000071"


class LegacyUuidKey(models.Model):
    """A UUID primary key, for the cursor's second key type."""

    id = models.UUIDField(primary_key=True)
    name_legacy = models.CharField(max_length=100, null=True)
    name = Encrypted(models.CharField(max_length=100),
                     column_uuid=COL_LEGACY_UUID_NAME, null=True)

    fieldseal = FieldsealMeta(table_uuid=TABLE_LEGACY_UUID_KEY)
