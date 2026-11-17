"""The index context's `suite_id` is the index's DECLARED suite (spec §7.2,
#213): required, registered, independent of the write suite and the allow-list,
reflected, and the only suite the index derivation reads.
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fieldseal import (  # noqa: E402
    FieldContext,
    Fieldseal,
    IndexDeclaration,
    index_registry_key,
    validate_index_declaration,
)
from fieldseal.errors import ConfigurationError, FieldsealWarning  # noqa: E402
from fieldseal.keyprovider import StaticKeyProvider  # noqa: E402

KEY_ID = bytes(range(16))
DEK = bytes(range(32))
INDEX_KEY = bytes(range(32, 64))
CTX = FieldContext(table_uuid=bytes(16), column_uuid=bytes(range(16)),
                   purpose="encrypt", tenant_id=b"t1")
IDX_CTX = CTX.for_index("email-eq")


def _decl(**kw) -> IndexDeclaration:
    d = dict(table_uuid=CTX.table_uuid, column_uuid=CTX.column_uuid,
             suite_id=0xFF01, index_id="email-eq", idf="hmac-sha512",
             normalize="nfc-casefold-v1", truncate_bits=64,
             projected_population=2 ** 65)
    d.update(kw)
    return IndexDeclaration(**d)


class SpyProvider(StaticKeyProvider):
    """Records every context the client hands the provider."""

    def __init__(self) -> None:
        super().__init__(KEY_ID, DEK, INDEX_KEY)
        self.seen: list[FieldContext] = []

    def encryption_key(self, ctx):
        self.seen.append(ctx)
        return super().encryption_key(ctx)


def _client(*decls: IndexDeclaration, provider=None) -> Fieldseal:
    # The client's write suite and allow-list are 0xFF01 only: 0xFF01 is the
    # one suite this build has an AEAD backend for.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FieldsealWarning)
        return Fieldseal(
            key_provider=provider or StaticKeyProvider(KEY_ID, DEK, INDEX_KEY),
            allowed_suites={0xFF01}, write_suite=0xFF01,
            indexes=decls, arm_provisional_suites=True)


class TestDeclaredSuiteIsRequiredAndRegistered:
    def test_the_member_has_no_default(self):
        with pytest.raises(TypeError):
            IndexDeclaration(  # type: ignore[call-arg]
                table_uuid=CTX.table_uuid, column_uuid=CTX.column_uuid,
                index_id="email-eq", idf="hmac-sha512",
                normalize="identity", truncate_bits=15,
                projected_population=65536)

    def test_a_declaration_naming_no_suite_is_refused(self):
        with pytest.raises(ConfigurationError, match="suite_id is required"):
            validate_index_declaration(_decl(suite_id=None))
        with pytest.raises(ConfigurationError):
            _client(_decl(suite_id=None))

    @pytest.mark.parametrize("bad", [0x0001, 0x0002, 0x0000, 0xFFFF, 0xFF03,
                                     True, "0xFF01", 65281.0])
    def test_an_unregistered_or_malformed_suite_is_refused(self, bad):
        with pytest.raises(ConfigurationError):
            validate_index_declaration(_decl(suite_id=bad))
        with pytest.raises(ConfigurationError):
            _client(_decl(suite_id=bad))


class TestDeclaredSuiteDrivesTheIndex:
    def test_ff02_is_accepted_on_a_ff01_only_client_and_changes_the_bytes(self):
        v = "alice@example.com"
        only02 = _client(_decl(suite_id=0xFF02))
        only01 = _client(_decl(suite_id=0xFF01))
        assert only02.write_suite == 0xFF01
        assert only02.allowed_suites == frozenset({0xFF01})
        got02 = only02.blind_index(v, IDX_CTX)
        got01 = only01.blind_index(v, IDX_CTX)
        assert len(got02) == len(got01) == 8
        assert got02 != got01
        # Deterministic under its own declared suite.
        assert got02 == _client(_decl(suite_id=0xFF02)).blind_index(v, IDX_CTX)

    @pytest.mark.parametrize("declared", [0xFF01, 0xFF02])
    def test_the_context_handed_to_key_derivation_carries_the_declared_suite(
            self, declared):
        spy = SpyProvider()
        fs = _client(_decl(suite_id=declared), provider=spy)
        fs.blind_index("alice@example.com", IDX_CTX)
        fs.unindexable_marker(IDX_CTX)
        assert len(spy.seen) == 2
        assert [c.suite_id for c in spy.seen] == [declared, declared]
        assert all(c.purpose == "index:email-eq" and c.row_id is None
                   for c in spy.seen)

    def test_the_write_suite_is_not_read_on_the_index_path(self):
        spy = SpyProvider()
        fs = _client(_decl(suite_id=0xFF02), provider=spy)
        assert fs.write_suite == 0xFF01
        fs.blind_index("x", IDX_CTX)
        assert spy.seen[0].suite_id == 0xFF02 != fs.write_suite


class TestReflection:
    def test_the_validated_declaration_reports_the_declared_suite(self):
        fs = _client(_decl(suite_id=0xFF02))
        v = fs.indexes[index_registry_key(
            CTX.table_uuid, CTX.column_uuid, "email-eq")]
        assert v.suite_id == 0xFF02

    def test_the_suite_participates_in_validated_equality(self):
        a = validate_index_declaration(_decl(suite_id=0xFF01))
        assert a == validate_index_declaration(_decl(suite_id=0xFF01))
        assert a != validate_index_declaration(_decl(suite_id=0xFF02))
