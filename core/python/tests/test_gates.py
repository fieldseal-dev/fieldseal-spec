"""Negative tests for the gates and the totality claims.

Every assertion here is something the specification says MUST hold and that a
positive vector cannot demonstrate: a gate is only proven by the operation it
refuses.
"""

from __future__ import annotations

import os
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from fieldseal import FieldContext, Fieldseal  # noqa: E402
from fieldseal.envelope import is_ciphertext  # noqa: E402
from fieldseal.errors import (  # noqa: E402
    CommitmentInvalid,
    ConfigurationError,
    FieldsealError,
    FieldsealWarning,
    InvalidArgument,
    ModeViolation,
    SuiteProvisional,
)
from fieldseal.keyprovider import StaticKeyProvider  # noqa: E402

KEY_ID = bytes(range(16))
DEK = bytes(range(32))
INDEX_KEY = bytes(range(32, 64))
CTX = FieldContext(table_uuid=bytes(16), column_uuid=bytes(range(16)),
                   purpose="encrypt", tenant_id=b"t1")


def _client(**kw) -> Fieldseal:
    kw.setdefault("arm_provisional_suites", True)
    with warnings.catch_warnings():
        # The §10.3 warning is asserted in test_parity.py; here it is noise.
        warnings.simplefilter("ignore", FieldsealWarning)
        return Fieldseal(key_provider=StaticKeyProvider(KEY_ID, DEK, INDEX_KEY),
                         allowed_suites={0xFF01}, write_suite=0xFF01, **kw)


# -- spec §4.8, the provisional gate ------------------------------------------

def test_unarmed_client_refuses_to_encrypt(monkeypatch):
    monkeypatch.delenv("FIELDSEAL_ARM_PROVISIONAL_SUITES", raising=False)
    fs = _client(arm_provisional_suites=False)
    with pytest.raises(SuiteProvisional) as e:
        fs.encrypt(b"secret", CTX)
    # The message must name the suite and the mechanism: an operator meeting
    # this needs to know both that the construction is unreviewed and exactly
    # what acknowledging it entails (spec §9).
    assert "0xff01" in str(e.value).lower()
    assert "FIELDSEAL_ARM_PROVISIONAL_SUITES" in str(e.value)


def test_unarmed_client_still_decrypts(monkeypatch):
    """Spec §4.8: decrypt is deliberately ungated. Making recovery harder than
    writing would be exactly the wrong incentive."""
    monkeypatch.delenv("FIELDSEAL_ARM_PROVISIONAL_SUITES", raising=False)
    blob = _client().encrypt(b"secret", CTX)
    assert _client(arm_provisional_suites=False).decrypt(blob, CTX) \
        == b"secret"


def test_env_var_arms_the_gate(monkeypatch):
    monkeypatch.setenv("FIELDSEAL_ARM_PROVISIONAL_SUITES", "1")
    assert _client(arm_provisional_suites=False).encrypt(b"x", CTX)


def test_rotate_is_a_write_for_the_gate(monkeypatch):
    monkeypatch.delenv("FIELDSEAL_ARM_PROVISIONAL_SUITES", raising=False)
    blob = _client().encrypt(b"secret", CTX)
    with pytest.raises(SuiteProvisional):
        _client(arm_provisional_suites=False).rotate(blob, CTX)


# -- spec §10.3, read modes (G6) ----------------------------------------------

def test_readonly_refuses_writes():
    with pytest.raises(ModeViolation) as e:
        _client(read_mode="readonly").encrypt(b"x", CTX)
    assert "readonly" in str(e.value)


def test_readonly_permits_blind_index():
    """An index computed for a WHERE clause is not a write (spec §10.3)."""
    fs = _client(read_mode="readonly")
    assert fs.blind_index("alice@example.com", CTX, index_id="email-eq",
                          b_bits=15, idf="hmac-sha512")


# -- spec §3.1/§4.4, no caller-supplied randomness ----------------------------

def test_encrypt_accepts_no_seed_or_nonce():
    """The production API must expose no way in, in any form -- not a keyword,
    not a config field (vectors/README.md)."""
    import inspect
    params = set(inspect.signature(Fieldseal.encrypt).parameters)
    assert not params & {"msg_seed", "nonce", "seed", "iv"}


def test_fresh_materials_every_call():
    fs = _client()
    a, b = fs.encrypt(b"same", CTX), fs.encrypt(b"same", CTX)
    assert a != b, "identical plaintext must not produce identical envelopes"
    assert a[19:51] != b[19:51], "msg_seed must be fresh on every write"


def test_importing_fieldseal_does_not_import_testing():
    """A clean interpreter, because this test module has already imported the
    world; checking sys.modules in-process would prove nothing."""
    code = ("import fieldseal, sys; "
            "sys.exit(1 if 'fieldseal.testing' in sys.modules else 0)")
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    assert subprocess.run([sys.executable, "-c", code], env=env).returncode == 0


def test_testing_namespace_is_inert_unless_armed():
    code = ("import fieldseal.testing as t\n"
            "try:\n"
            "    t.encrypt_with_materials(None, b'', None, b'', b'')\n"
            "except Exception as e:\n"
            "    raise SystemExit(0 if 'FIELDSEAL_TEST_MODE' in str(e) else 2)\n"
            "raise SystemExit(3)\n")
    env = {k: v for k, v in os.environ.items() if k != "FIELDSEAL_TEST_MODE"}
    env["PYTHONPATH"] = str(SRC)
    assert subprocess.run([sys.executable, "-c", code], env=env).returncode == 0


# -- spec §3.4, is_ciphertext is total ----------------------------------------

@pytest.mark.parametrize("value", [
    None, 0, "", "not bytes", b"", b"\x00", b"\x01" * 50, bytearray(b"\x01"),
    memoryview(b"\x01\xff\x01"),
])
def test_is_ciphertext_never_raises(value):
    assert is_ciphertext(value) in (True, False)


def test_truncated_envelope_always_raises_a_typed_error():
    """Every prefix of a valid envelope must produce a FieldsealError, never an
    IndexError and never a silently short slice."""
    blob = _client().encrypt(b"payload", CTX)
    fs = _client()
    for cut in range(len(blob)):
        with pytest.raises(FieldsealError):
            fs.decrypt(blob[:cut], CTX)


def test_bit_flip_is_detected():
    blob = bytearray(_client().encrypt(b"payload", CTX))
    blob[60] ^= 0x01
    with pytest.raises(FieldsealError):
        _client().decrypt(bytes(blob), CTX)


def test_wrong_context_fails_before_the_aead():
    """Under dual-layer binding a wrong context derives a wrong record key, so
    it surfaces at the commitment check rather than as a tag failure. This is
    the ambiguity gap G5 is about; the test pins current behavior so a change
    to it is visible."""
    blob = _client().encrypt(b"payload", CTX)
    other = FieldContext(table_uuid=bytes(16), column_uuid=bytes(range(16)),
                         purpose="encrypt", tenant_id=b"t2")
    with pytest.raises(CommitmentInvalid):
        _client().decrypt(blob, other)


# -- configuration ------------------------------------------------------------

def test_index_key_must_not_equal_dek():
    """Spec §5.2: the tenant index key is a sibling of the DEK, never it."""
    with pytest.raises(ConfigurationError):
        StaticKeyProvider(KEY_ID, DEK, DEK)


def test_write_suite_must_be_allowed():
    with pytest.raises(ConfigurationError):
        Fieldseal(key_provider=StaticKeyProvider(KEY_ID, DEK, INDEX_KEY),
                  allowed_suites={0xFF02}, write_suite=0xFF01)


def test_purpose_grammar_is_enforced():
    for bad in ["Encrypt", "index:", "index:UPPER", "index:" + "a" * 33, "x"]:
        with pytest.raises(ConfigurationError):
            FieldContext(table_uuid=bytes(16), column_uuid=bytes(16),
                         purpose=bad)


def test_index_purpose_never_gets_the_dek():
    """Spec §8: purpose routing is a provider obligation, not a convention."""
    p = StaticKeyProvider(KEY_ID, DEK, INDEX_KEY)
    material, key_id = p.encryption_key(
        CTX.for_index("email-eq").with_suite(0xFF01))
    assert material == INDEX_KEY and material != DEK
    assert p.encryption_key(CTX.with_suite(0xFF01)) == (DEK, KEY_ID)


# -- review findings, 2026-08-22 ----------------------------------------------

def test_registered_but_unperformable_suite_is_refused_at_construction():
    """Registered != performable. 0xFF02 is in the registry (spec §4.2) and has
    no backend in this build. Before this was caught, the client constructed
    happily and then raised a bare KeyError from inside encrypt -- and
    is_ciphertext() returned True for such an envelope, so an adapter would
    route it straight to decrypt to find out."""
    with pytest.raises(ConfigurationError) as e:
        Fieldseal(key_provider=StaticKeyProvider(KEY_ID, DEK, INDEX_KEY),
                  allowed_suites={0xFF02}, write_suite=0xFF02)
    assert "no backend" in str(e.value)


def test_unperformable_suite_refused_even_when_only_readable():
    """Allowing it for reads is no safer: without a backend the envelope cannot
    be opened either."""
    with pytest.raises(ConfigurationError):
        Fieldseal(key_provider=StaticKeyProvider(KEY_ID, DEK, INDEX_KEY),
                  allowed_suites={0xFF01, 0xFF02}, write_suite=0xFF01)


def test_backend_lookup_never_raises_an_untyped_error():
    """Defensive: the constructor should make this unreachable, but a KeyError
    escaping the core would break the contract that every failure is typed."""
    from fieldseal.api import _backend
    from fieldseal.errors import SuiteNotAllowed
    with pytest.raises(SuiteNotAllowed):
        _backend(0x0001)


# -- docs/09 §7.1 / §7.2, the index boundary ----------------------------------

# U+0378 is unassigned in every Unicode version so far, so it stands in for
# "a character the pin does not define" without waiting for 18.0.
UNPINNED = "a͸b"
OTHER_UNPINNED = "z͸z"
IDX_KW = dict(index_id="email-eq", b_bits=15, idf="hmac-sha512",
              normalizer="nfc-casefold-v1")


def test_blind_index_takes_text_and_bytes_alike():
    """docs/09 §7.1: an index API must accept text, and widening the type
    must not fork the function."""
    fs = _client()
    for s in ("alice@example.com", "ALICE@example.com", "grüße", ""):
        assert fs.blind_index(s, CTX, **IDX_KW) == \
            fs.blind_index(s.encode("utf-8"), CTX, **IDX_KW)


def test_lone_surrogate_is_refused_distinguishably():
    """The false match the text path exists to close. Both are refused, and
    the messages name different code points -- an identical diagnosis would
    leave the two values indistinguishable, which is the property the refusal
    denies them."""
    fs = _client()
    msgs = []
    for s in ("a\ud800b", "a\udc00b"):
        with pytest.raises(InvalidArgument) as e:
            fs.blind_index(s, CTX, **IDX_KW)
        msgs.append(str(e.value))
    assert "D800" in msgs[0] and "DC00" in msgs[1]
    assert msgs[0] != msgs[1]


def test_on_unindexable_refuse_is_the_default():
    fs = _client()
    with pytest.raises(InvalidArgument):
        fs.blind_index(UNPINNED, CTX, **IDX_KW)


def test_on_unindexable_bucket_keeps_the_row_findable():
    """docs/09 §7.2: `bucket` derives a reserved marker rather than storing no
    index -- an absent index is the silent missing row spec §10.2 forbids."""
    fs = _client()
    marker = fs.unindexable_marker(CTX, index_id="email-eq", b_bits=15,
                                   idf="hmac-sha512")
    got = fs.blind_index(UNPINNED, CTX, on_unindexable="bucket", **IDX_KW)
    assert got == marker
    assert len(marker) == 2          # ceil(15/8)
    assert marker != b"\x00\x00"     # derived, not a constant


def test_bucket_is_one_collision_class_that_lookup_reaches_naturally():
    """The same value normalizes the same way in both directions, so a query
    for an unindexable value derives the marker and matches those rows; §7.5
    re-verification narrows the candidates. An indexable value never lands
    there."""
    fs = _client()
    a = fs.blind_index(UNPINNED, CTX, on_unindexable="bucket", **IDX_KW)
    b = fs.blind_index(OTHER_UNPINNED, CTX, on_unindexable="bucket", **IDX_KW)
    normal = fs.blind_index("alice@example.com", CTX,
                            on_unindexable="bucket", **IDX_KW)
    assert a == b
    assert normal != a


def test_bucket_is_refused_where_it_could_never_fire():
    """`identity` consults no Unicode table and never refuses, so a bucket for
    it would misrepresent the column as protected."""
    fs = _client()
    with pytest.raises(ConfigurationError) as e:
        fs.blind_index("x", CTX, index_id="email-eq", b_bits=15,
                       idf="hmac-sha512", normalizer="identity",
                       on_unindexable="bucket")
    assert "never refuses" in str(e.value)


def test_unknown_on_unindexable_is_a_configuration_error():
    fs = _client()
    with pytest.raises(ConfigurationError):
        fs.blind_index("x", CTX, on_unindexable="skip", **IDX_KW)
