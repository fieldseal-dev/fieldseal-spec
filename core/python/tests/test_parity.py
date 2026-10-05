"""Behaviour the pinned suite does not reach.

Two cores can pass the same 42 vectors and still disagree on every one of
these, because nothing in `vectors/` exercises a read mode, a second key
version, a reserved format version, or a hostile length (docs/18 §3, and the
2026-08-22 review). Each test here pins one line of `run_vectors.PINNED_DECISIONS`
or one clause the specification already settles, so that the declaration in
the conformance report is a statement about code that is actually tested.
"""

from __future__ import annotations

import array
import ctypes
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

from fieldseal import (  # noqa: E402
    CardinalityOverride,
    FieldContext,
    Fieldseal,
    IndexDeclaration,
    normalize,
)
from fieldseal.blindindex import NORMALIZERS  # noqa: E402
from fieldseal.envelope import (  # noqa: E402
    MAX_PLAINTEXT,
    MIN_ENVELOPE_LEN,
    EnvelopeHeader,
    is_ciphertext,
    recognize,
    serialize_header,
)
from fieldseal.errors import (  # noqa: E402
    CommitmentInvalid,
    ConfigurationError,
    FieldsealError,
    FieldsealWarning,
    InvalidArgument,
    KeyUnavailable,
    LengthExceeded,
    ModeViolation,
    NotCiphertext,
    SuiteNotAllowed,
    SuiteProvisional,
    TagInvalid,
    UnknownFormatVersion,
)
from fieldseal.keyprovider import StaticKeyProvider  # noqa: E402
from fieldseal.testing import encrypt_with_materials  # noqa: E402

KEY_ID = bytes(range(16))
DEK = bytes(range(32))
INDEX_KEY = bytes(range(32, 64))
CTX = FieldContext(table_uuid=bytes(16), column_uuid=bytes(range(16)),
                   purpose="encrypt", tenant_id=b"t1")


def _decl(index_id: str = "email-eq", normalize: str = "nfc-casefold-v1",
          truncate_bits: int = 15, **kw) -> IndexDeclaration:
    d = dict(table_uuid=CTX.table_uuid, column_uuid=CTX.column_uuid,
             index_id=index_id, idf="hmac-sha512", normalize=normalize,
             truncate_bits=truncate_bits,
             projected_population=2 ** (truncate_bits + 1))
    d.update(kw)
    return IndexDeclaration(**d)


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
@pytest.mark.parametrize("junk", [bytearray(b"plain text"),
                                  memoryview(b"plain text")])
def test_pass_through_modes_return_other_bytes_likes_as_bytes(mode, junk):
    fs = _client(mode)
    assert fs.decrypt(junk, CTX) == b"plain text"
    assert fs.plaintext_reads == 1


@pytest.mark.parametrize("mode", ["strict", "permissive", "readonly"])
@pytest.mark.parametrize("operand", ["plain text", 42, -3, 1.5, None])
def test_decrypt_refuses_an_operand_that_is_not_bytes_in_every_mode(
        mode, operand):
    """#251: the pass-through coerced its operand with `bytes()`, so a str
    raised `TypeError`, -3 raised `ValueError`, and 42 came back as 42 zero
    bytes -- an int the size of a phone number allocates gigabytes. The
    refusal is the same in every mode, as `rotate`'s domain is (below)."""
    fs = _client(mode)
    with pytest.raises(InvalidArgument, match=type(operand).__name__):
        fs.decrypt(operand, CTX)
    assert fs.plaintext_reads == 0


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


@pytest.mark.parametrize("mode", ["strict", "permissive"])
def test_rotate_refuses_non_envelope_input_in_every_mode(mode):
    """spec §11.1 (G15 part B): `rotate` is ciphertext-to-ciphertext, so its
    domain does not widen in `permissive`. The §10.3 pass-through is a read
    behaviour and the decrypt inside `rotate` is not a read.

    The point of the parametrisation is that both modes give the same answer:
    an operation whose domain depended on the read mode would be a portability
    hazard no vector could adjudicate."""
    with pytest.raises(NotCiphertext):
        _client(mode).rotate(b"unmigrated", CTX)


def test_rotate_of_reserved_version_is_unknown_format_version():
    """Recognition (spec §3.4) distinguishes a future-format envelope from
    unmigrated plaintext, and `rotate` inherits that: a v2 envelope is not
    plaintext and must not be reported as such."""
    blob = bytes([0x02]) + _ff02_blob(MIN_ENVELOPE_LEN)[1:]
    with pytest.raises(UnknownFormatVersion):
        _client("permissive").rotate(blob, CTX)


def test_rotate_in_readonly_refuses_before_reading():
    """docs/09 §3.5: the mode gate runs before the decrypt, so even
    non-envelope input is refused rather than passed through."""
    with pytest.raises(ModeViolation):
        _client("readonly").rotate(b"anything", CTX)


# -- #254: an operand that is not bytes, on every operation that takes one ------
#
# Spec §11.1 types every operand as bytes, and `blind_index`'s as text too
# (docs/10 §4). Before #254 one such operand got four answers across four
# operations: INVALID_ARGUMENT from `decrypt` (#251), NOT_CIPHERTEXT from
# `rotate`, a raw `TypeError` from `encrypt`, and from `blind_index` an index
# of `bytes(42)` -- 42 NUL bytes -- with no error at all.

NOT_BYTES = ["plain text", 42, -3, 1.5, None]
NOT_TEXT_OR_BYTES = [42, -3, 1.5, None, ["a"]]


class _Untouchable:
    """Every refusal below is at the API boundary, before key acquisition
    (spec §9), so no call may reach the provider."""

    def encryption_key(self, ctx):
        raise AssertionError("provider consulted before the boundary")

    def decryption_keys(self, header):
        raise AssertionError("provider consulted before the boundary")


@pytest.mark.parametrize("mode", ["strict", "permissive"])
@pytest.mark.parametrize("operand", NOT_BYTES)
def test_encrypt_refuses_an_operand_that_is_not_bytes(mode, operand):
    """Was a raw `TypeError` -- `len()` of an int, or the AEAD refusing a
    str -- which is not a `FieldsealError` and carries no code."""
    fs = _client(mode, provider=_Untouchable())
    with pytest.raises(InvalidArgument,
                       match=f"encrypt takes bytes, not {type(operand).__name__}"):
        fs.encrypt(operand, CTX)


@pytest.mark.parametrize("mode", ["strict", "permissive"])
@pytest.mark.parametrize("operand", NOT_BYTES)
def test_rotate_refuses_an_operand_that_is_not_bytes(mode, operand):
    """Was NOT_CIPHERTEXT, so after #251 one operand carried two codes in
    this core: INVALID_ARGUMENT from `decrypt`, NOT_CIPHERTEXT from
    `rotate`. A value that is not bytes is not "not an envelope"; it is not
    an operand."""
    fs = _client(mode, provider=_Untouchable())
    with pytest.raises(InvalidArgument,
                       match=f"rotate takes bytes, not {type(operand).__name__}"):
        fs.rotate(operand, CTX)


@pytest.mark.parametrize("op", ["encrypt", "rotate"])
@pytest.mark.parametrize("operand", NOT_BYTES)
def test_readonly_refuses_a_write_before_looking_at_the_operand(op, operand):
    """docs/09 §3.5: the mode gate runs first, so readonly's answer does not
    depend on the operand."""
    fs = _client("readonly", provider=_Untouchable())
    with pytest.raises(ModeViolation):
        getattr(fs, op)(operand, CTX)


@pytest.mark.parametrize("mode", ["strict", "permissive", "readonly"])
@pytest.mark.parametrize("operand", NOT_TEXT_OR_BYTES)
def test_blind_index_refuses_an_operand_that_is_neither_text_nor_bytes(
        mode, operand):
    """The serious row of #254: `blind_index(42)` returned the index of 42 NUL
    bytes, so an equality lookup computed from an int found nothing, or found
    the rows holding that many NULs. -3 raised a raw `ValueError`; 1.5 and
    None a raw `TypeError`."""
    fs = _client(mode, provider=_Untouchable(), indexes=[_decl()])
    with pytest.raises(InvalidArgument, match=(
            f"blind_index takes str or bytes, not {type(operand).__name__}")):
        fs.blind_index(operand, CTX.for_index("email-eq"))


def test_bucket_does_not_file_an_operand_that_is_neither_text_nor_bytes():
    """`on_unindexable="bucket"` catches the normalizer's INVALID_ARGUMENT and
    derives the column's reserved marker. An int is a caller's error, not a
    value the pin cannot define, so it must not land in the bucket."""
    fs = _client(indexes=[_decl(
        on_unindexable="bucket",
        unindexable_override=CardinalityOverride(
            reason="test", approved_by="tests", date="2026-10-05"))])
    ctx = CTX.for_index("email-eq")
    assert fs.blind_index("a\u0378b", ctx) == fs.unindexable_marker(ctx)
    with pytest.raises(InvalidArgument, match="not int"):
        fs.blind_index(42, ctx)


@pytest.mark.parametrize("normalizer", sorted(NORMALIZERS))
@pytest.mark.parametrize("operand", NOT_TEXT_OR_BYTES)
def test_normalize_refuses_an_operand_that_is_neither_text_nor_bytes(
        normalizer, operand):
    """The public `normalize` is the function `blind_index` uses, and an
    adapter re-verifies candidates with it (spec §7.5); it coerced with
    `bytes()` too."""
    with pytest.raises(InvalidArgument, match=type(operand).__name__):
        normalize(normalizer, operand)


def _released_view():
    mv = memoryview(b"secret")
    mv.release()
    return mv


# Bytes-typed and refused. The AEAD refused the first three with a raw
# `TypeError` or `BufferError` after the provider had been consulted, `len()`
# undercounts the 2-D one, and a normalizer indexed the wide one's
# machine-endian bytes with no error. The last two worked on `dev` where the
# operation could read them (the strided one too, in `decrypt`'s pass-through
# and `blind_index`); they are refused because the rule is the format, not the
# operation's tolerance, and `.cast("B")` or `bytes(...)` is the way through.
UNUSABLE_VIEWS = {
    "wide-items": lambda: memoryview(array.array("I", [1, 2, 3])),
    "signed-bytes": lambda: memoryview(b"secret").cast("b"),
    "strided": lambda: memoryview(b"s_e_c_r_e_t")[::2],
    "two-dimensional": lambda: memoryview(b"secret").cast("B", [2, 3]),
    "ctypes-ubyte": lambda: memoryview((ctypes.c_ubyte * 6)(*b"secret")),
    "char": lambda: memoryview(b"secret").cast("c"),
}


@pytest.mark.parametrize("mode", ["strict", "permissive"])
@pytest.mark.parametrize("op", ["encrypt", "decrypt", "rotate"])
@pytest.mark.parametrize("view", sorted(UNUSABLE_VIEWS))
def test_a_memoryview_the_operation_cannot_use_is_refused(mode, op, view):
    fs = _client(mode, provider=_Untouchable())
    with pytest.raises(InvalidArgument, match=(
            f"{op} takes bytes, not a memoryview that is not a "
            "one-dimensional, contiguous view of format 'B'")):
        getattr(fs, op)(UNUSABLE_VIEWS[view](), CTX)
    assert fs.plaintext_reads == 0


@pytest.mark.parametrize("view", sorted(UNUSABLE_VIEWS))
def test_blind_index_refuses_a_memoryview_it_cannot_use(view):
    fs = _client(provider=_Untouchable(), indexes=[_decl()])
    with pytest.raises(InvalidArgument,
                       match="blind_index takes str or bytes, not a memoryview"):
        fs.blind_index(UNUSABLE_VIEWS[view](), CTX.for_index("email-eq"))


@pytest.mark.parametrize("op", ["encrypt", "decrypt", "rotate", "blind_index"])
def test_a_released_view_is_refused_and_named_as_released(op):
    """A released view was one-dimensional, contiguous and of format 'B'; the
    shape message would send its caller looking for the wrong fix."""
    fs = _client("permissive", provider=_Untouchable(), indexes=[_decl()])
    ctx = CTX.for_index("email-eq") if op == "blind_index" else CTX
    with pytest.raises(InvalidArgument, match="not a released memoryview$"):
        getattr(fs, op)(_released_view(), ctx)
    assert fs.plaintext_reads == 0


@pytest.mark.parametrize("view", sorted(UNUSABLE_VIEWS))
def test_a_refused_view_is_accepted_once_cast_or_copied(view):
    """The way through for a caller whose view is refused: `.cast("B")` where
    the view allows it, `bytes(...)` always."""
    mv = UNUSABLE_VIEWS[view]()
    fs = _client(indexes=[_decl()])
    blob = fs.encrypt(bytes(mv), CTX)
    assert fs.decrypt(blob, CTX) == bytes(mv)
    if mv.c_contiguous and mv.ndim == 1:
        assert fs.decrypt(fs.encrypt(mv.cast("B"), CTX), CTX) == bytes(mv)


class _HasDunderBytes:
    def __bytes__(self):
        return b"secret"


def _mmap_of_secret():
    m = mmap.mmap(-1, 6)
    m[:] = b"secret"
    return m


# Accepted on `dev` before #254 by `encrypt` (the first two) and `blind_index`
# (all three), and refused by `decrypt` since #251. A caller holding one wraps
# it: `memoryview(...)` over any of the first two is accepted.
NO_LONGER_ACCEPTED = {
    "array": lambda: array.array("B", b"secret"),
    "mmap": _mmap_of_secret,
    "__bytes__": _HasDunderBytes,
}


@pytest.mark.parametrize("op", ["encrypt", "decrypt", "rotate", "blind_index"])
@pytest.mark.parametrize("kind", sorted(NO_LONGER_ACCEPTED))
def test_other_buffer_types_are_refused_and_a_memoryview_over_them_is_not(
        op, kind):
    fs = _client(indexes=[_decl()])
    ctx = CTX.for_index("email-eq") if op == "blind_index" else CTX
    with pytest.raises(InvalidArgument, match="takes"):
        getattr(fs, op)(NO_LONGER_ACCEPTED[kind](), ctx)
    if kind == "__bytes__":
        return
    if op == "blind_index":
        assert (fs.blind_index(memoryview(NO_LONGER_ACCEPTED[kind]()), ctx)
                == fs.blind_index(b"secret", ctx))
    elif op == "encrypt":
        blob = fs.encrypt(memoryview(NO_LONGER_ACCEPTED[kind]()), CTX)
        assert fs.decrypt(blob, CTX) == b"secret"


@pytest.mark.parametrize("wrap", [bytearray, memoryview])
def test_encrypt_and_rotate_still_take_any_bytes_like(wrap):
    fs = _client()
    blob = fs.encrypt(wrap(b"secret"), CTX)
    assert fs.decrypt(blob, CTX) == b"secret"
    assert fs.decrypt(fs.rotate(wrap(blob), CTX), CTX) == b"secret"


@pytest.mark.parametrize("wrap", [bytearray, memoryview])
def test_blind_index_still_takes_any_bytes_like(wrap):
    fs = _client(indexes=[_decl()])
    ctx = CTX.for_index("email-eq")
    assert (fs.blind_index(wrap(b"Ada@Example.COM"), ctx)
            == fs.blind_index("Ada@Example.COM", ctx))


@pytest.mark.parametrize("mode", ["strict", "permissive", "readonly"])
@pytest.mark.parametrize("operand", NOT_BYTES + [b"", b"plain text",
                                                 _released_view()])
def test_client_is_ciphertext_stays_total(mode, operand):
    """Spec §3.4: the predicate is total, and the backfill asks it about
    exactly these values on a partially migrated column. It answers False,
    never raises, in every mode. A released view raised `ValueError` until
    #256's review round 2: recognition caught only `TypeError`."""
    assert _client(mode).is_ciphertext(operand) is False


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
    with pytest.raises(InvalidArgument, match="purpose"):
        _client("strict").encrypt(b"x", index_ctx)


@pytest.mark.parametrize("op", ["encrypt", "rotate"])
def test_boundary_order_puts_the_operand_after_the_configuration(op):
    """#254: an operand that is not bytes is refused after the two refusals
    that follow from configuration and before anything that reads the
    operand's length or its context."""
    index_ctx = CTX.for_index("email-eq")
    call = lambda fs: getattr(fs, op)(42, index_ctx)  # noqa: E731
    with pytest.raises(ModeViolation):
        call(_client("readonly", arm_provisional_suites=False))
    with pytest.raises(SuiteProvisional):
        call(_client("strict", arm_provisional_suites=False))
    with pytest.raises(InvalidArgument, match=f"{op} takes bytes"):
        call(_client("strict"))


def test_rotate_checks_the_context_before_recognition():
    """`rotate` runs the same boundary as `encrypt`, so a non-envelope
    operand under an index context is the context's refusal, not
    NOT_CIPHERTEXT. Not new in #254; pinned because the boundary now takes
    the operand."""
    with pytest.raises(InvalidArgument, match="purpose"):
        _client().rotate(b"x", CTX.for_index("email-eq"))
    with pytest.raises(NotCiphertext):
        _client().rotate(b"x", CTX)


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
    with pytest.raises(InvalidArgument, match="encrypt takes bytes, not int"):
        encrypt_with_materials(_client(), 42, CTX, seed, nonce)
    out = encrypt_with_materials(_client(), b"x", CTX, seed, nonce)
    assert _client().decrypt(out, CTX) == b"x"


# -- blind indexes: normalizers are portability surface (docs/09 §7) ------------

def test_bytes_in_equals_text_in_for_the_text_normalizer():
    fs = _client(indexes=[_decl()])
    ctx = CTX.for_index("email-eq")
    assert (fs.blind_index("Alice@Example.com", ctx)
            == fs.blind_index(b"Alice@Example.com", ctx)
            == fs.blind_index("alice@example.com", ctx))


def test_blind_index_drops_the_callers_row_id():
    """Spec §7.2: one value has one index key across rows. The client drops
    row_id before key acquisition as well as inside the derivation; the
    derivation's drop masks a missing client drop in the output, so the
    provider's view is what observes it (#191 review)."""
    seen = []

    class _Recording(StaticKeyProvider):
        def encryption_key(self, ctx):
            seen.append(ctx)
            return super().encryption_key(ctx)

    fs = _client(provider=_Recording(KEY_ID, DEK, INDEX_KEY), indexes=[_decl()])
    rowless = CTX.for_index("email-eq")
    with_row = FieldContext(table_uuid=rowless.table_uuid,
                            column_uuid=rowless.column_uuid,
                            purpose=rowless.purpose,
                            tenant_id=rowless.tenant_id, row_id=b"row-42")
    assert (fs.blind_index("alice@example.com", with_row)
            == fs.blind_index("alice@example.com", rowless))
    assert seen and all(c.row_id is None for c in seen)


def test_invalid_utf8_is_refused_not_folded():
    """Replacement characters would map distinct invalid inputs onto one index
    value (docs/18 D-10(d))."""
    fs = _client(indexes=[_decl()])
    with pytest.raises(InvalidArgument):
        fs.blind_index(b"\xff\xfe", CTX.for_index("email-eq"))


def test_identity_and_digits_only_normalizers():
    """`digits-only-v1` strips to exactly what `identity` would see for the
    same digits. Asserted on the normalizers themselves: two declarations on
    one column need distinct index-ids, and the index key is derived from the
    index-id (spec §7.2), so the same preimage under two declarations no
    longer produces the same index value -- by design."""
    assert (NORMALIZERS["digits-only-v1"]("123-45-6789")
            == NORMALIZERS["identity"](b"123456789") == b"123456789")
    fs = _client(indexes=[_decl("ssn-digits", "digits-only-v1", 16),
                          _decl("ssn-raw", "identity", 16)])
    assert fs.blind_index("123-45-6789", CTX.for_index("ssn-digits"))
    # identity never decodes, so invalid UTF-8 is fine there.
    assert fs.blind_index(b"\xff\xfe", CTX.for_index("ssn-raw"))


def test_unknown_idf_or_normalizer_fails_closed():
    """docs/09 §3.3 step 2: refused where the index is declared, so a column
    the spec cannot express never reaches a key derivation."""
    with pytest.raises(ConfigurationError):
        _client(indexes=[_decl(idf="md5")])
    with pytest.raises(ConfigurationError):
        # the unversioned name
        _client(indexes=[_decl(normalize="nfc-casefold")])
    with pytest.raises(ConfigurationError):
        _client(indexes=[_decl(truncate_bits=0)])


def test_index_derivation_never_sees_the_dek():
    class Strict:
        def encryption_key(self, ctx):
            assert ctx.purpose == "index:email-eq" and ctx.row_id is None
            return INDEX_KEY, KEY_ID

        def decryption_keys(self, header):
            return []

    fs = _client(provider=Strict(), indexes=[_decl()])
    ctx = FieldContext(bytes(16), bytes(range(16)), tenant_id=b"t1",
                       row_id=b"row-7")
    assert fs.blind_index("a", ctx.for_index("email-eq"))


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
                                   memoryview(b"\x01\xff\x01" * 40)[::2],
                                   _released_view()])
def test_is_ciphertext_is_total_over_non_bytes_too(value):
    assert is_ciphertext(value) in (True, False)


def test_recognition_is_total_over_a_released_view():
    """`recognize` states it is total, and `is_ciphertext` inherits that; a
    released view raised `ValueError` from both until #256's review round 2."""
    assert recognize(_released_view()) is None
