"""The value path (docs/12 §2) and the §6 coverage matrix rows it owns.

Every test here asserts one row of the matrix, so the matrix and the suite
cannot drift apart without one of them failing.
"""

from __future__ import annotations

import base64

import pytest
from django.core import serializers
from django.db import connection
from fieldseal import errors as core_errors

from fieldseal_django.errors import FieldsealNotSupported

from .models import Patient

pytestmark = pytest.mark.django_db


def raw_column(pk: int, column: str) -> bytes | None:
    """Read a column with the ORM out of the way.

    The point of the adapter is that the database never sees plaintext, and
    the only way to assert that is to look at the bytes the database actually
    holds rather than at what the ORM hands back.
    """
    with connection.cursor() as cur:
        cur.execute(
            f"SELECT {connection.ops.quote_name(column)} "
            f"FROM {connection.ops.quote_name(Patient._meta.db_table)} "
            "WHERE id = %s", [pk])
        value = cur.fetchone()[0]
    if value is None:
        return None
    return bytes(value) if not isinstance(value, bytes) else value


class TestRoundTrip:
    def test_save_then_read_returns_the_plaintext(self):
        p = Patient.objects.create(email="ada@example.com", note="seen 2026-08",
                                   age=36)
        got = Patient.objects.get(pk=p.pk)
        assert got.email == "ada@example.com"
        assert got.note == "seen 2026-08"
        assert got.age == 36

    def test_the_database_holds_an_envelope_not_the_plaintext(self):
        p = Patient.objects.create(email="ada@example.com")
        stored = raw_column(p.pk, "email")
        assert stored is not None
        assert b"ada@example.com" not in stored
        # spec §3.1: fmt_ver 0x01, then the big-endian suite id.
        assert stored[0] == 0x01
        assert stored[1:3] == b"\xff\x01"

    def test_two_writes_of_one_value_differ(self):
        """Spec §4.4: a fresh nonce and msg_seed on every write, including
        UPDATEs. Equal ciphertext would mean one of them was reused."""
        a = Patient.objects.create(email="ada@example.com")
        b = Patient.objects.create(email="ada@example.com")
        assert raw_column(a.pk, "email") != raw_column(b.pk, "email")

    def test_update_rewrites_the_envelope(self):
        p = Patient.objects.create(email="ada@example.com")
        first = raw_column(p.pk, "email")
        p.email = "ada@example.com"
        p.save()
        assert raw_column(p.pk, "email") != first

    def test_non_text_inner_type_round_trips_as_its_own_type(self):
        p = Patient.objects.create(email="a@b.com", age=41)
        got = Patient.objects.get(pk=p.pk)
        assert got.age == 41 and isinstance(got.age, int)

    def test_null_stays_null(self):
        """A NULL column is not encrypted: the row genuinely has no value, and
        an envelope would claim it has one."""
        p = Patient.objects.create(email="a@b.com", note=None)
        assert raw_column(p.pk, "note") is None
        assert Patient.objects.get(pk=p.pk).note is None


class TestIndexSibling:
    def test_index_column_is_populated_on_insert(self):
        p = Patient.objects.create(email="ada@example.com")
        idx = raw_column(p.pk, "email_bidx")
        assert idx is not None
        # truncate_bits=15 -> ceil(15/8) = 2 bytes (spec §7.11).
        assert len(idx) == 2

    def test_the_index_is_deterministic_where_the_ciphertext_is_not(self):
        a = Patient.objects.create(email="ada@example.com")
        b = Patient.objects.create(email="ada@example.com")
        assert raw_column(a.pk, "email_bidx") == raw_column(b.pk, "email_bidx")
        assert raw_column(a.pk, "email") != raw_column(b.pk, "email")

    def test_the_index_folds_case_per_the_normalizer(self):
        """`nfc-casefold-v1` is why `iexact` is refused: the folding belongs to
        the normalizer, so the index already matches case variants."""
        a = Patient.objects.create(email="ada@example.com")
        b = Patient.objects.create(email="ADA@Example.COM")
        assert raw_column(a.pk, "email_bidx") == raw_column(b.pk, "email_bidx")


class TestRefusedPaths:
    @pytest.mark.parametrize("lookup", [
        "contains", "icontains", "startswith", "endswith", "iexact",
        "gt", "gte", "lt", "lte", "range", "regex", "search",
    ])
    def test_refused_lookups_raise_rather_than_return_nothing(self, lookup):
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.filter(**{f"email__{lookup}": "x"})
        assert lookup in str(e.value)

    def test_expression_rhs_is_refused(self):
        """`get_db_prep_save` short-circuits on expressions, so the value
        would reach the database unencrypted (docs/12 §6)."""
        from django.db.models import F

        Patient.objects.create(email="a@b.com", note="x")
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.update(note=F("email"))
        assert "bulk_update" in str(e.value)


class TestSerialization:
    def test_dumpdata_emits_ciphertext_not_plaintext(self):
        """Without `value_to_string`, serialization reaches for the Python
        value and writes plaintext into a fixture file."""
        Patient.objects.create(email="ada@example.com")
        out = serializers.serialize("json", Patient.objects.all())
        assert "ada@example.com" not in out
        import json

        blob = base64.b64decode(json.loads(out)[0]["fields"]["email"])
        assert blob[0] == 0x01 and blob[1:3] == b"\xff\x01"


class TestBulkPaths:
    def test_bulk_create_encrypts_and_indexes(self):
        Patient.objects.bulk_create([
            Patient(email="a@example.com"), Patient(email="b@example.com")])
        for p in Patient.objects.all():
            assert raw_column(p.pk, "email")[0] == 0x01
            assert raw_column(p.pk, "email_bidx") is not None

    def test_bulk_update_encrypts(self):
        """Routes through Case/When with Value(...), which reaches
        `get_db_prep_save` (`docs/04` §1, verified)."""
        p = Patient.objects.create(email="a@example.com", note="before")
        p.note = "after"
        Patient.objects.bulk_update([p], ["note"])
        assert Patient.objects.get(pk=p.pk).note == "after"
        assert b"after" not in raw_column(p.pk, "note")


class TestReadFailures:
    def test_a_tampered_envelope_raises_rather_than_returning_garbage(self):
        p = Patient.objects.create(email="ada@example.com")
        blob = bytearray(raw_column(p.pk, "email"))
        blob[-1] ^= 0x01  # flip a bit in the commitment
        with connection.cursor() as cur:
            cur.execute(
                f"UPDATE {connection.ops.quote_name(Patient._meta.db_table)} "
                "SET email = %s WHERE id = %s", [bytes(blob), p.pk])
        with pytest.raises(core_errors.FieldsealError):
            Patient.objects.get(pk=p.pk)


class TestEqualityGoesThroughTheIndexSibling:
    """L2 shipped (docs/12 §3.2, decision C). What still refuses, and why.

    The behaviour of the served paths lives in `test_l2.py`; what is pinned
    here is the one equality surface that stays refused, because it is the
    one a reader is most likely to assume works.
    """

    def test_exact_on_the_encrypted_column_is_served(self):
        row = Patient.objects.create(email="ada@example.com")
        assert Patient.objects.filter(email="ada@example.com").count() == 1
        assert Patient.objects.get(email="ada@example.com").pk == row.pk

    def test_in_on_the_encrypted_column_is_served(self):
        Patient.objects.create(email="ada@example.com")
        assert Patient.objects.filter(email__in=["ada@example.com"]).count() == 1

    def test_exact_on_the_index_column_refuses_naming_the_collision_rule(self):
        """The sibling column is still refused, and deliberately so.

        Matching it directly is the L2(a) "explicit index property" surface,
        and it cannot re-verify: `get_lookup` on the sibling has no access to
        the queryset that would do it, so serving it would return collisions
        under a spelling that looks precise. The verified path is
        `filter(email=...)`; the unverified one is `.candidates()`, which at
        least says what it is.
        """
        Patient.objects.create(email="ada@example.com")
        with pytest.raises(FieldsealNotSupported) as e:
            Patient.objects.filter(email_bidx="ada@example.com").count()
        msg = str(e.value)
        assert "§7.4" in msg and "§7.5" in msg
        assert "backfill" in msg

class TestBackendDivergence:
    """`bulk_update` builds a different expression tree per backend.

    PostgreSQL sets `requires_casted_case_in_updates`, so each `Value` is
    wrapped in a `Cast`; SQLite does not. A refusal that only knew `Value`
    and `Case` passed here and failed on Postgres -- which is why `docs/12`
    §8 requires both backends in CI rather than treating one as
    representative.
    """

    def test_a_cast_wrapping_a_literal_is_accepted(self):
        from django.db.models import TextField, Value
        from django.db.models.functions import Cast

        field = Patient._meta.get_field("note")
        field._assert_literal_expression(
            Cast(Value("after"), output_field=TextField()))

    def test_a_cast_wrapping_a_column_reference_is_still_refused(self):
        from django.db.models import F, TextField
        from django.db.models.functions import Cast

        field = Patient._meta.get_field("note")
        with pytest.raises(FieldsealNotSupported):
            field._assert_literal_expression(
                Cast(F("email"), output_field=TextField()))

    def test_a_function_over_a_literal_is_refused(self):
        """`Upper(Value(...))` would compile `UPPER(%s)` over the ciphertext:
        the allow-list is closed, not a heuristic about literals."""
        from django.db.models import Value
        from django.db.models.functions import Upper

        field = Patient._meta.get_field("note")
        with pytest.raises(FieldsealNotSupported):
            field._assert_literal_expression(Upper(Value("x")))
