"""Behaviour the pinned suite does not reach.

Two cores can pass the same 42 vectors and still disagree on every one of
these, because nothing in `vectors/` exercises a read mode, a second key
version, a reserved format version, or a hostile length (docs/18 §3, and the
2026-08-22 review). Each test here pins one line of `run_vectors.PINNED_DECISIONS`
or one clause the specification already settles, so that the declaration in
the conformance report is a statement about code that is actually tested.
"""

from __future__ import annotations

import mmap
import os
import sys
import warnings
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
os.environ.setdefault("FIELDSEAL_TEST_MODE", "1")

from fieldseal import Fieldseal, FieldContext                      # noqa: E402
from fieldseal.envelope import (MAX_PLAINTEXT, MIN_ENVELOPE_LEN,   # noqa: E402
                                EnvelopeHeader, is_ciphertext,
                                serialize_header)
from fieldseal.errors import (CommitmentInvalid, ConfigurationError,  # noqa: E402
                              FieldsealError, FieldsealWarning,
                              InvalidArgument, KeyUnavailable,
                              LengthExceeded, ModeViolation, NotCiphertext,
                              SuiteNotAllowed, SuiteProvisional, TagInvalid,
                              UnknownFormatVersion)
from fieldseal.keyprovider import StaticKeyProvider                # noqa: E402
from fieldseal.testing import encrypt_with_materials               # noqa: E402

KEY_ID = bytes(range(16))
DEK = bytes(range(32))
INDEX_KEY = bytes(range(32, 64))
CTX = FieldContext(table_uuid=bytes(16), column_uuid=bytes(range(16)),
                   purpose="encrypt", tenant_id=b"t1")


def _client(read_mode: str = "strict", provider=None, **kw) -> Fieldseal:
    kw.setdefault("arm_provisional_suites", True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FieldsealWarning)
        return Fieldseal(
            key_provider=provider or StaticKeyProvider(KEY_ID, DEK, INDEX_KEY),
            allowed_suites={0xFF01}, write_suite=0xFF01, read_mode=read_mode,
            **kw)


class _VersionedProvider:
    """Several currently-valid DEK versions under one key_id, as a rotating
    production provider would have (spec §5.6). Preference order is the
    provider's; the core tries them in the order given."""

    def __init__(self, key_id: bytes, *deks: bytes) -> None:
        self.key_id, self.deks = key_id, list(deks)

    def encryption_key(self, ctx):
        return (INDEX_KEY if ctx.purpose != "encrypt" else self.deks[0],
                self.key_id)

    def decryption_keys(self, header: EnvelopeHeader):
        return self.deks if header.key_id == self.key_id else []


# -- spec §10.3: read modes on the decrypt path ---------------------------------

@pytest.mark.parametrize("junk", [b"", b"plain text", b"\x00" * 200,
                                  bytes([0x03]) + b"\xff\x01" + bytes(200)])
def test_strict_raises_not_ciphertext_on_non_envelope(junk):
    with pytest.raises(NotCiphertext):
        _client("strict").decrypt(junk, CTX)


@pytest.mark.parametrize("mode", ["permissive", "readonly"])
@pytest.mark.parametrize("junk", [b"", b"plain text", b"\x00" * 200])
def test_pass_through_modes_return_non_envelope_as_is(mode, junk):
    fs = _client(mode)
    assert fs.decrypt(junk, CTX) is junk
    assert fs.plaintext_reads == 1


@pytest.mark.parametrize("mode", ["permissive", "readonly"])
def test_pass_through_modes_still_decrypt_real_envelopes(mode):
    blob = _client().encrypt(b"secret", CTX)
    fs = _client(mode)
    assert fs.decrypt(blob, CTX) == b"secret"
    assert fs.plaintext_reads == 0


@pytest.mark.parametrize("mode", ["permissive", "readonly"])
def test_pass_through_modes_warn_at_construction(mode):
    """Spec §10.3: implementations MUST warn when the mode is active."""
    with pytest.warns(FieldsealWarning, match=mode):
        Fieldseal(key_provider=StaticKeyProvider(KEY_ID, DEK, INDEX_KEY),
                  allowed_suites={0xFF01}, write_suite=0xFF01, read_mode=mode)


def test_strict_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error", FieldsealWarning)
        Fieldseal(key_provider=StaticKeyProvider(KEY_ID, DEK, INDEX_KEY),
                  allowed_suites={0xFF01}, write_suite=0xFF01)


def test_rotate_in_permissive_encrypts_pass_through_plaintext():
    """Literal composition (docs/18 D-13; pinned_decisions.rotate-in-permissive):
    rotate of unmigrated plaintext in permissive mode is an encrypt."""
    fs = _client("permissive")
    out = fs.rotate(b"unmigrated", CTX)
    assert is_ciphertext(out) and fs.decrypt(out, CTX) == b"unmigrated"


def test_rotate_in_readonly_refuses_before_reading():
    """docs/09 §3.5: the mode gate runs before the decrypt, so even
    non-envelope input is refused rather than passed through."""
    with pytest.raises(ModeViolation):
        _client("readonly").rotate(b"anything", CTX)


# -- spec §3.4 / docs/09 §3.2: recognition precedes policy ----------------------

def _ff02_blob(length: int) -> bytes:
    return serialize_header(0xFF02, bytes(16), bytes(32)) + bytes(length - 51)


def test_registered_but_not_allowed_suite_is_suite_not_allowed():
    """The §3.4 decoupling case: recognition must succeed first."""
    blob = _ff02_blob(123)  # 0xFF02's fixed overhead: 51 + 24 + 16 + 32
    assert is_ciphertext(blob)
    for mode in ("strict", "permissive", "readonly"):
        with pytest.raises(SuiteNotAllowed):
            _client(mode).decrypt(blob, CTX)


def test_short_blob_under_a_disallowed_suite_is_not_ciphertext():
    """Per-suite minimum (docs/18 D-11): a 115-byte 0xFF02-tagged blob cannot
    be an envelope, so it is not ciphertext -- and that verdict comes before
    the allow-list is consulted, so it is NOT_CIPHERTEXT, never
    SUITE_NOT_ALLOWED."""
    blob = _ff02_blob(115)
    assert not is_ciphertext(blob)
    with pytest.raises(NotCiphertext):
        _client("strict").decrypt(blob, CTX)
    assert _client("permissive").decrypt(blob, CTX) is blob


def test_unregistered_suite_is_not_ciphertext_not_suite_not_allowed():
    """docs/08 §4.6: recognition, not authorization."""
    blob = serialize_header(0x00FF, bytes(16), bytes(32)) + bytes(100)
    assert not is_ciphertext(blob)
    with pytest.raises(NotCiphertext):
        _client("strict").decrypt(blob, CTX)
    assert _client("permissive").decrypt(blob, CTX) is blob


# -- docs/18 D-03: the reserved-known-future version set ------------------------

def _with_fmt_ver(v: int, length: int = 123) -> bytes:
    return bytes([v]) + b"\xff\x01" + bytes(length - 3)


@pytest.mark.parametrize("mode", ["strict", "permissive", "readonly"])
def test_reserved_future_version_raises_in_every_mode(mode):
    with pytest.raises(UnknownFormatVersion):
        _client(mode).decrypt(_with_fmt_ver(0x02), CTX)
    # ...but it is not *recognized* ciphertext (spec §3.4).
    assert not is_ciphertext(_with_fmt_ver(0x02))


def test_reserved_future_version_at_implausible_length_is_not_ciphertext():
    short = _with_fmt_ver(0x02, MIN_ENVELOPE_LEN - 1)
    with pytest.raises(NotCiphertext):
        _client("strict").decrypt(short, CTX)
    assert _client("permissive").decrypt(short, CTX) is short


@pytest.mark.parametrize("v", [0x00, 0x03, 0x7f, 0x80, 0xff])
def test_other_version_bytes_are_not_ciphertext(v):
    blob = _with_fmt_ver(v)
    with pytest.raises(NotCiphertext):
        _client("strict").decrypt(blob, CTX)
    assert _client("permissive").decrypt(blob, CTX) is blob
    assert not is_ciphertext(blob)


# -- spec §8: every currently-valid version is a candidate ----------------------

def test_no_candidate_is_key_unavailable():
    blob = _client().encrypt(b"secret", CTX)
    other = StaticKeyProvider(bytes(range(16, 32)), DEK, INDEX_KEY)
    with pytest.raises(KeyUnavailable) as e:
        _client(provider=other).decrypt(blob, CTX)
    assert KEY_ID.hex() in str(e.value)


def test_later_candidate_is_tried_after_an_earlier_commitment_fails():
    writer = _client(provider=_VersionedProvider(KEY_ID, DEK))
    blob = writer.encrypt(b"secret", CTX)
    rotated = _VersionedProvider(KEY_ID, bytes(32), b"\x01" * 32, DEK)
    assert _client(provider=rotated).decrypt(blob, CTX) == b"secret"


def test_no_candidate_commits_is_commitment_invalid():
    blob = _client().encrypt(b"secret", CTX)
    wrong = _VersionedProvider(KEY_ID, bytes(32), b"\x01" * 32)
    with pytest.raises(CommitmentInvalid):
        _client(provider=wrong).decrypt(blob, CTX)


# -- docs/09 §3.2 step 6-7: commitment, then open --------------------------------

def _flip(blob: bytes, index: int) -> bytes:
    b = bytearray(blob)
    b[index] ^= 0x01
    return bytes(b)


def test_ciphertext_or_tag_damage_after_a_verified_commitment_is_tag_invalid():
    blob = _client().encrypt(b"payload", CTX)
    n = len(blob)
    for i in (63, n - 32 - 16, n - 33):  # ciphertext, tag[0], tag[-1]
        with pytest.raises(TagInvalid):
            _client().decrypt(_flip(blob, i), CTX)


def test_commitment_damage_is_commitment_invalid():
    blob = _client().encrypt(b"payload", CTX)
    with pytest.raises(CommitmentInvalid):
        _client().decrypt(_flip(blob, len(blob) - 1), CTX)


def test_msg_seed_damage_is_commitment_invalid():
    """A different seed derives a different record key, whose commitment
    cannot match -- so this surfaces before the AEAD (docs/08 §4.6 lists the
    outcome as G5-dependent; this is the pin)."""
    blob = _client().encrypt(b"payload", CTX)
    with pytest.raises(CommitmentInvalid):
        _client().decrypt(_flip(blob, 30), CTX)


def test_wrong_context_is_commitment_invalid_never_aad_mismatch():
    """pinned_decisions.aad-mismatch: under §6.3 dual binding a wrong context
    is a wrong record key, indistinguishable from key confusion (G5)."""
    blob = _client().encrypt(b"payload", CTX)
    for other in (
        FieldContext(bytes(16), bytes(range(16)), tenant_id=b"t2"),
        FieldContext(bytes(16), bytes(range(16)), tenant_id=b"t1",
                     row_id=b"r"),
        FieldContext(bytes(16), bytes(16), tenant_id=b"t1"),
        FieldContext(bytes(16), bytes(range(16))),
    ):
        with pytest.raises(CommitmentInvalid):
            _client().decrypt(blob, other)


def test_decrypt_uses_the_header_suite_not_the_write_suite():
    """docs/09 §3.2 step 4: the context's suite_id comes from the parsed
    header. With one performable suite the observable consequence is that the
    header's suite must be allow-listed on its own merits."""
    blob = _client().encrypt(b"x", CTX)
    assert blob[1:3] == b"\xff\x01"
    assert _client().decrypt(blob, CTX) == b"x"


# -- spec §3.5 and the API boundary order (docs/18 D-04) -------------------------

def test_oversize_plaintext_is_refused_before_the_provider():
    class Loud:
        def encryption_key(self, ctx):
            raise AssertionError("provider consulted before the boundary")

        def decryption_keys(self, header):
            raise AssertionError("provider consulted before the boundary")

    fs = _client(provider=Loud())
    with pytest.raises(LengthExceeded):
        fs.encrypt(bytes(MAX_PLAINTEXT + 1), CTX)
    blob = mmap.mmap(-1, 111 + MAX_PLAINTEXT + 1)
    mv = memoryview(blob)
    try:
        blob[:51] = serialize_header(0xFF01, KEY_ID, bytes(32))
        with pytest.raises(LengthExceeded):
            fs.decrypt(mv, CTX)
    finally:
        mv.release()
        blob.close()


def test_exact_bound_is_accepted_by_the_boundary():
    """2^31 - 1 passes the check; whether the AEAD can take it is a platform
    question the spec exempts. Only the boundary is asserted here."""
    class Stop(Exception):
        pass

    class Halt:
        def encryption_key(self, ctx):
            raise Stop

    with pytest.raises(Stop):
        _client(provider=Halt()).encrypt(bytes(MAX_PLAINTEXT), CTX)


def test_boundary_order_mode_then_provisional_then_length_then_context():
    big = bytes(MAX_PLAINTEXT + 1)
    index_ctx = CTX.for_index("email-eq")
    with pytest.raises(ModeViolation):
        _client("readonly", arm_provisional_suites=False).encrypt(big, index_ctx)
    with pytest.raises(SuiteProvisional):
        _client("strict", arm_provisional_suites=False).encrypt(big, index_ctx)
    with pytest.raises(LengthExceeded):
        _client("strict").encrypt(big, index_ctx)
    with pytest.raises(InvalidArgument):
        _client("strict").encrypt(b"x", index_ctx)


def test_testing_seam_runs_the_same_boundary(monkeypatch):
    """docs/08 §6: the full production pipeline except the entropy draws --
    the gates included. A seam that skipped them would let a harness certify
    gates that do not work."""
    monkeypatch.delenv("FIELDSEAL_ARM_PROVISIONAL_SUITES", raising=False)
    seed, nonce = bytes(32), bytes(12)
    with pytest.raises(ModeViolation):
        encrypt_with_materials(_client("readonly"), b"x", CTX, seed, nonce)
    with pytest.raises(SuiteProvisional):
        encrypt_with_materials(_client(arm_provisional_suites=False), b"x",
                               CTX, seed, nonce)
    with pytest.raises(LengthExceeded):
        encrypt_with_materials(_client(), bytes(MAX_PLAINTEXT + 1), CTX,
                               seed, nonce)
    out = encrypt_with_materials(_client(), b"x", CTX, seed, nonce)
    assert _client().decrypt(out, CTX) == b"x"


# -- blind indexes: normalizers are portability surface (docs/09 §7) ------------

def test_bytes_in_equals_text_in_for_the_text_normalizer():
    fs = _client()
    kw = dict(index_id="email-eq", b_bits=15, idf="hmac-sha512")
    assert (fs.blind_index("Alice@Example.com", CTX, **kw)
            == fs.blind_index(b"Alice@Example.com", CTX, **kw)
            == fs.blind_index("alice@example.com", CTX, **kw))


def test_invalid_utf8_is_refused_not_folded():
    """Replacement characters would map distinct invalid inputs onto one index
    value (docs/18 D-10(d))."""
    with pytest.raises(InvalidArgument):
        _client().blind_index(b"\xff\xfe", CTX, index_id="email-eq",
                              b_bits=15, idf="hmac-sha512")


def test_identity_and_digits_only_normalizers():
    fs = _client()
    kw = dict(index_id="ssn-eq", b_bits=16, idf="hmac-sha512")
    assert (fs.blind_index("123-45-6789", CTX, normalizer="digits-only-v1", **kw)
            == fs.blind_index(b"123456789", CTX, normalizer="identity", **kw))
    # identity never decodes, so invalid UTF-8 is fine there.
    assert fs.blind_index(b"\xff\xfe", CTX, normalizer="identity", **kw)


def test_unknown_idf_or_normalizer_fails_closed():
    fs = _client()
    with pytest.raises(ConfigurationError):
        fs.blind_index("x", CTX, index_id="e", b_bits=8, idf="md5")
    with pytest.raises(ConfigurationError):
        fs.blind_index("x", CTX, index_id="e", b_bits=8, idf="hmac-sha512",
                       normalizer="nfc-casefold")  # the unversioned name
    with pytest.raises(ConfigurationError):
        fs.blind_index("x", CTX, index_id="e", b_bits=0, idf="hmac-sha512")


def test_index_derivation_never_sees_the_dek():
    class Strict:
        def encryption_key(self, ctx):
            assert ctx.purpose == "index:email-eq" and ctx.row_id is None
            return INDEX_KEY, KEY_ID

        def decryption_keys(self, header):
            return []

    fs = _client(provider=Strict())
    ctx = FieldContext(bytes(16), bytes(range(16)), tenant_id=b"t1",
                       row_id=b"row-7")
    assert fs.blind_index("a", ctx, index_id="email-eq", b_bits=8,
                          idf="hmac-sha512")


# -- totality (docs/08 §4.6 first row; docs/18 D-02) ------------------------------

_operands = st.binary(max_size=400).flatmap(
    lambda b: st.sampled_from([b, bytearray(b), memoryview(b)]))


@settings(max_examples=300, deadline=None)
@given(_operands)
def test_decrypt_is_total_over_bytes_like_operands(blob):
    fs = _client("strict")
    try:
        fs.decrypt(blob, CTX)
    except FieldsealError:
        pass
    assert is_ciphertext(blob) in (True, False)


@settings(max_examples=300, deadline=None)
@given(_operands)
def test_pass_through_is_total_and_identity_shaped(blob):
    out = _client("permissive").decrypt(blob, CTX)
    assert isinstance(out, bytes)
    if not is_ciphertext(blob):
        assert out == bytes(blob)


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview])
def test_every_prefix_of_a_valid_envelope_is_a_typed_error(wrap):
    blob = _client().encrypt(b"payload", CTX)
    fs = _client("strict")
    for cut in range(len(blob)):
        with pytest.raises(FieldsealError):
            fs.decrypt(wrap(blob[:cut]), CTX)
    assert fs.decrypt(wrap(blob), CTX) == b"payload"


@pytest.mark.parametrize("value", [None, 0, 1.5, "", "str", [], {}, object(),
                                   memoryview(bytearray(range(8))).cast("B"),
                                   memoryview(b"\x01\xff\x01" * 40)[::2]])
def test_is_ciphertext_is_total_over_non_bytes_too(value):
    assert is_ciphertext(value) in (True, False)
