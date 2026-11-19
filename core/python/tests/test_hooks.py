"""The client's `on_warning` and `metrics` hooks (docs/09 §2, docs/10 §4, #223).

Spec §10.3 (read-mode warning, plaintext-read metric) and §8 (the
`StaticKeyProvider` warning outside test configuration) are the clauses these
pin; the error counts are keyed on spec §9's codes.
"""

from __future__ import annotations

import os
import sys
import warnings
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from fieldseal import FieldContext, Fieldseal, NullMetrics  # noqa: E402
from fieldseal.envelope import MIN_ENVELOPE_LEN  # noqa: E402
from fieldseal.errors import (  # noqa: E402
    ConfigurationError,
    FieldsealError,
    FieldsealWarning,
    InvalidArgument,
    KeyUnavailable,
    MetricsHookWarning,
    ReadModeWarning,
    StaticKeyProviderWarning,
)
from fieldseal.keyprovider import StaticKeyProvider  # noqa: E402

KEY_ID = bytes(range(16))
DEK = bytes(range(32))
INDEX_KEY = bytes(range(32, 64))
CTX = FieldContext(table_uuid=bytes(16), column_uuid=bytes(range(16)),
                   purpose="encrypt", tenant_id=b"t1")


def _provider() -> StaticKeyProvider:
    return StaticKeyProvider(KEY_ID, DEK, INDEX_KEY)


def _client(read_mode: str = "strict", **kw) -> Fieldseal:
    """Built in test mode, so only the read-mode warning can fire."""
    kw.setdefault("arm_provisional_suites", True)
    kw.setdefault("key_provider", _provider())
    return Fieldseal(allowed_suites={0xFF01}, write_suite=0xFF01,
                     read_mode=read_mode, **kw)


@pytest.fixture(autouse=True)
def _test_mode(monkeypatch):
    monkeypatch.setenv("FIELDSEAL_TEST_MODE", "1")


class Rec(NullMetrics):
    def __init__(self) -> None:
        self.reads = 0
        self.errors: list[str] = []

    def plaintext_read(self) -> None:
        self.reads += 1

    def decrypt_error(self, code: str) -> None:
        self.errors.append(code)


# -- on_warning: read mode (spec §10.3) ---------------------------------------

@pytest.mark.parametrize("mode", ["permissive", "readonly"])
def test_read_mode_warning_goes_through_on_warning(mode):
    got: list[FieldsealWarning] = []
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # nothing may reach warnings.warn
        _client(mode, on_warning=got.append)
    assert len(got) == 1
    assert isinstance(got[0], ReadModeWarning)
    assert got[0].kind == "READ_MODE_PASS_THROUGH"
    assert mode in str(got[0])


@pytest.mark.parametrize("mode", ["permissive", "readonly"])
def test_read_mode_warning_default_is_warnings_warn(mode):
    with pytest.warns(FieldsealWarning, match=mode) as rec:
        _client(mode)
    assert len(rec) == 1
    assert rec[0].filename == __file__  # attributed to the caller


def test_strict_emits_no_warning_at_all():
    got: list[FieldsealWarning] = []
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _client("strict", on_warning=got.append)
        _client("strict")
    assert got == []


def test_on_warning_that_raises_escalates_construction():
    class Boom(Exception):
        pass

    def hard(w: FieldsealWarning) -> None:
        raise Boom(w.kind)

    with pytest.raises(Boom):
        _client("permissive", on_warning=hard)


def test_on_warning_must_be_callable():
    with pytest.raises(ConfigurationError):
        _client(on_warning="log")  # type: ignore[arg-type]


# -- on_warning: StaticKeyProvider outside test mode (spec §8) -----------------

def test_static_provider_outside_test_mode_warns_through_on_warning(
        monkeypatch):
    monkeypatch.delenv("FIELDSEAL_TEST_MODE")
    got: list[FieldsealWarning] = []
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _client(on_warning=got.append)
    assert [type(w) for w in got] == [StaticKeyProviderWarning]
    assert got[0].kind == "STATIC_KEY_PROVIDER"


def test_static_provider_outside_test_mode_default_is_warnings_warn(
        monkeypatch):
    monkeypatch.delenv("FIELDSEAL_TEST_MODE")
    with pytest.warns(StaticKeyProviderWarning, match="StaticKeyProvider"):
        _client()


@pytest.mark.parametrize("value", ["0", "", "true"])
def test_only_exactly_1_is_test_mode(monkeypatch, value):
    # docs/08 §6 arms on "=1", and so does this.
    monkeypatch.setenv("FIELDSEAL_TEST_MODE", value)
    with pytest.warns(StaticKeyProviderWarning):
        _client()


def test_static_provider_in_test_mode_does_not_warn():
    got: list[FieldsealWarning] = []
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _client(on_warning=got.append)
        _client()
    assert got == []


def test_both_warnings_are_delivered_when_both_apply(monkeypatch):
    monkeypatch.delenv("FIELDSEAL_TEST_MODE")
    got: list[FieldsealWarning] = []
    _client("permissive", on_warning=got.append)
    assert [type(w) for w in got] == [ReadModeWarning,
                                      StaticKeyProviderWarning]


def test_on_warning_that_raises_escalates_the_static_warning(monkeypatch):
    monkeypatch.delenv("FIELDSEAL_TEST_MODE")

    def hard(w: FieldsealWarning) -> None:
        raise RuntimeError("refused")

    with pytest.raises(RuntimeError, match="refused"):
        _client(on_warning=hard)


def test_a_non_static_provider_never_gets_the_static_warning(monkeypatch):
    monkeypatch.delenv("FIELDSEAL_TEST_MODE")

    class Other:
        def encryption_key(self, ctx):
            return DEK, KEY_ID

        def decryption_keys(self, header):
            return [DEK]

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _client(key_provider=Other())


def test_no_warning_carries_key_material_or_plaintext(monkeypatch):
    monkeypatch.delenv("FIELDSEAL_TEST_MODE")
    got: list[FieldsealWarning] = []
    fs = _client("permissive", on_warning=got.append)
    fs.decrypt(b"patient-secret-123", CTX)
    assert len(got) == 2
    secrets = [DEK, INDEX_KEY, KEY_ID, b"patient-secret-123"]
    for w in got:
        text = str(w).encode()
        for s in secrets:
            assert s not in text
            assert s.hex().encode() not in text
        assert repr(DEK) not in str(w)


# -- metrics: plaintext_reads (spec §10.3) -------------------------------------

@pytest.mark.parametrize("mode", ["permissive", "readonly"])
def test_plaintext_read_metric_tracks_the_counter(mode):
    m = Rec()
    fs = _client(mode, metrics=m, on_warning=lambda w: None)
    for i in range(3):
        fs.decrypt(b"plain %d" % i, CTX)
    assert fs.plaintext_reads == 3
    assert m.reads == fs.plaintext_reads
    assert m.errors == []


def test_envelope_reads_are_not_plaintext_reads():
    m = Rec()
    fs = _client("permissive", metrics=m, on_warning=lambda w: None)
    fs.decrypt(fs.encrypt(b"x", CTX), CTX)
    assert fs.plaintext_reads == 0 and m.reads == 0


def test_strict_counts_no_plaintext_read_but_an_error():
    m = Rec()
    fs = _client("strict", metrics=m)
    with pytest.raises(FieldsealError):
        fs.decrypt(b"not an envelope", CTX)
    assert fs.plaintext_reads == 0 and m.reads == 0
    assert m.errors == ["NOT_CIPHERTEXT"]


# -- metrics: decrypt_errors by code (spec §9) ---------------------------------

def _flip(blob: bytes, index: int) -> bytes:
    b = bytearray(blob)
    b[index] ^= 0x01
    return bytes(b)


def _ff02_blob(length: int) -> bytes:
    return b"\x01\xff\x02" + bytes(length - 3)


def test_decrypt_errors_by_code():
    m = Rec()
    fs = _client(metrics=m)
    good = fs.encrypt(b"payload", CTX)

    cases = [
        ("NOT_CIPHERTEXT", b"plain text, no header"),
        ("UNKNOWN_FORMAT_VERSION", bytes([0x02]) + b"\xff\x01"
         + bytes(MIN_ENVELOPE_LEN)),
        ("SUITE_NOT_ALLOWED", _ff02_blob(123)),
        ("TAG_INVALID", _flip(good, 63)),
        ("COMMITMENT_INVALID", _flip(good, len(good) - 1)),
    ]
    for code, blob in cases:
        before = list(m.errors)
        with pytest.raises(FieldsealError) as ei:
            fs.decrypt(blob, CTX)
        assert ei.value.code == code
        assert m.errors == before + [code]
    assert fs.decrypt(good, CTX) == b"payload"  # success counts nothing
    assert len(m.errors) == len(cases)


def test_a_provider_raised_error_is_counted_by_its_code():
    class Dark:
        def encryption_key(self, ctx):
            return DEK, KEY_ID

        def decryption_keys(self, header):
            return []

    m = Rec()
    good = _client().encrypt(b"x", CTX)
    with pytest.raises(KeyUnavailable):
        _client(key_provider=Dark(), metrics=m).decrypt(good, CTX)
    assert m.errors == ["KEY_UNAVAILABLE"]


def test_argument_errors_are_not_decrypt_errors():
    # INVALID_ARGUMENT is implementation-local (docs/09 §9), a caller fault.
    m = Rec()
    fs = _client(metrics=m)
    with pytest.raises(InvalidArgument):
        fs.decrypt(42, CTX)  # type: ignore[arg-type]
    assert m.errors == []


def test_rotate_counts_the_decrypt_it_performs_and_nothing_else():
    m = Rec()
    fs = _client(metrics=m)
    good = fs.encrypt(b"x", CTX)
    with pytest.raises(FieldsealError):
        fs.rotate(_flip(good, 63), CTX)  # inner decrypt fails
    assert m.errors == ["TAG_INVALID"]
    with pytest.raises(FieldsealError):
        fs.rotate(b"plaintext", CTX)  # refused before any decrypt
    assert m.errors == ["TAG_INVALID"]


# -- metrics: shape ------------------------------------------------------------

def test_a_hook_with_one_method_is_enough():
    class OnlyErrors:
        def __init__(self):
            self.codes = []

        def decrypt_error(self, code):
            self.codes.append(code)

    m = OnlyErrors()
    fs = _client("permissive", metrics=m, on_warning=lambda w: None)
    fs.decrypt(b"plain", CTX)  # no plaintext_read method: not called
    assert fs.plaintext_reads == 1 and m.codes == []
    strict = _client(metrics=m)
    with pytest.raises(FieldsealError):
        strict.decrypt(b"plain", CTX)
    assert m.codes == ["NOT_CIPHERTEXT"]


@pytest.mark.parametrize("bad", [object(), type("X", (), {
    "plaintext_read": 1})()])
def test_a_metrics_object_with_no_usable_method_is_refused(bad):
    with pytest.raises(ConfigurationError):
        _client(metrics=bad)


def test_the_metrics_hook_gets_a_code_string_and_nothing_else():
    seen: list[tuple] = []

    class Spy(NullMetrics):
        def decrypt_error(self, *a, **k):
            seen.append((a, k))

    fs = _client(metrics=Spy())
    with pytest.raises(FieldsealError):
        fs.decrypt(b"secret-plaintext-in-the-wrong-place", CTX)
    assert seen == [(("NOT_CIPHERTEXT",), {})]


# -- metrics: a hook that raises ----------------------------------------------

class Raising(NullMetrics):
    def plaintext_read(self) -> None:
        raise RuntimeError("secret-from-hook")

    def decrypt_error(self, code: str) -> None:
        raise RuntimeError("secret-from-hook")


def test_a_failing_hook_does_not_change_a_successful_read():
    fs = _client("permissive", metrics=Raising(), on_warning=lambda w: None)
    with pytest.warns(FieldsealWarning, match="RuntimeError") as rec:
        assert fs.decrypt(b"plain", CTX) == b"plain"
    assert fs.plaintext_reads == 1  # the counter is the client's, not the hook's
    assert "secret-from-hook" not in str(rec[0].message)


def test_a_failing_hook_does_not_replace_the_spec_error():
    fs = _client(metrics=Raising())
    with pytest.warns(FieldsealWarning, match="RuntimeError"):
        with pytest.raises(FieldsealError) as ei:
            fs.decrypt(b"plain", CTX)
    assert ei.value.code == "NOT_CIPHERTEXT"


def test_a_failing_hook_is_not_routed_through_on_warning():
    got: list[FieldsealWarning] = []
    fs = _client(metrics=Raising(), on_warning=got.append)
    with pytest.warns(FieldsealWarning):
        with pytest.raises(FieldsealError):
            fs.decrypt(b"plain", CTX)
    assert got == []


def test_keyboard_interrupt_from_a_hook_passes_through():
    class Ctrl(NullMetrics):
        def decrypt_error(self, code: str) -> None:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _client(metrics=Ctrl()).decrypt(b"plain", CTX)


def test_default_construction_adds_no_metrics_cost_or_warning():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        fs = _client()
        with pytest.raises(FieldsealError):
            fs.decrypt(b"plain", CTX)
    assert os.environ["FIELDSEAL_TEST_MODE"] == "1"


# -- round 1 review ------------------------------------------------------------

def test_length_exceeded_is_counted():
    # spec §3.5, decrypt side: an envelope implying a plaintext over 2**31-1.
    from fieldseal.envelope import MAX_PLAINTEXT

    ok = _client().encrypt(b"x", CTX)
    overhead = len(ok) - 1

    class Big(bytes):
        """A bytes whose len() lies, so no 2 GiB buffer is allocated."""

        def __len__(self) -> int:
            return MAX_PLAINTEXT + 1 + overhead

    m = Rec()
    fs = _client(metrics=m)
    blob = Big(ok)
    with pytest.raises(FieldsealError) as ei:
        fs.decrypt(blob, CTX)
    assert ei.value.code == "LENGTH_EXCEEDED"
    assert m.errors == ["LENGTH_EXCEEDED"]


def test_a_provider_that_raises_key_unavailable_is_counted():
    class Raises:
        def encryption_key(self, ctx):
            return DEK, KEY_ID

        def decryption_keys(self, header):
            raise KeyUnavailable("directory down")

    good = _client().encrypt(b"x", CTX)
    m = Rec()
    with pytest.raises(KeyUnavailable):
        _client(key_provider=Raises(), metrics=m).decrypt(good, CTX)
    assert m.errors == ["KEY_UNAVAILABLE"]


def test_a_class_as_metrics_is_refused():
    with pytest.raises(ConfigurationError, match="instance"):
        _client(metrics=Rec)  # type: ignore[arg-type]


@pytest.mark.parametrize("attr", ["plaintext_read", "decrypt_error"])
def test_wrong_signatures_are_refused_at_construction(attr):
    class Bad:
        def plaintext_read(self, n):  # takes an argument it is never given
            pass

        def decrypt_error(self):  # cannot take the code
            pass

    class Only:
        pass

    setattr(Only, attr, getattr(Bad, attr))
    with pytest.raises(ConfigurationError, match=attr):
        _client(metrics=Only())


def test_a_metrics_object_whose_attribute_access_raises_is_refused():
    class Hostile:
        def __getattr__(self, name):
            raise RuntimeError("secret-from-getattr")

    with pytest.raises(ConfigurationError) as ei:
        _client(metrics=Hostile())
    assert "secret-from-getattr" not in str(ei.value)


def test_a_hook_failure_under_error_filter_does_not_replace_the_outcome():
    fs = _client("permissive", metrics=Raising(), on_warning=lambda w: None)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert fs.decrypt(b"plain", CTX) == b"plain"  # value wins
        strict = _client(metrics=Raising())
        with pytest.raises(FieldsealError) as ei:
            strict.decrypt(b"plain", CTX)
        assert ei.value.code == "NOT_CIPHERTEXT"  # the spec's code wins


def test_hook_failure_has_its_own_warning_class():
    fs = _client(metrics=Raising())
    with pytest.warns(MetricsHookWarning) as rec:
        with pytest.raises(FieldsealError):
            fs.decrypt(b"plain", CTX)
    assert rec[0].message.kind == "METRICS_HOOK_FAILED"
    assert not isinstance(rec[0].message, (ReadModeWarning,
                                           StaticKeyProviderWarning))


def test_filtering_the_read_mode_warning_does_not_hide_a_hook_failure():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ReadModeWarning)
        warnings.simplefilter("ignore", StaticKeyProviderWarning)
        fs = _client("permissive", metrics=Raising())  # warning is hidden
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        warnings.simplefilter("ignore", ReadModeWarning)
        fs.decrypt(b"plain", CTX)
    assert [type(w.message) for w in rec] == [MetricsHookWarning]


def test_the_static_warning_names_real_routes_not_the_test_mode_variable(
        monkeypatch):
    monkeypatch.delenv("FIELDSEAL_TEST_MODE")
    got: list[FieldsealWarning] = []
    _client(on_warning=got.append)
    text = str(got[0])
    assert "EnvelopeKeyProvider" in text
    assert "DerivedKeyProvider" not in text  # not ported to this core
    assert "FIELDSEAL_TEST_MODE" not in text
    assert "on_warning" in text and "StaticKeyProviderWarning" in text


def test_rotate_refusals_before_its_decrypt_are_not_counted():
    # Reserved-version input is refused by recognition inside rotate, before
    # the inner decrypt; the same bytes through decrypt are counted.
    v2 = bytes([0x02]) + b"\xff\x01" + bytes(MIN_ENVELOPE_LEN)
    m = Rec()
    fs = _client(metrics=m)
    with pytest.raises(FieldsealError) as ei:
        fs.rotate(v2, CTX)
    assert ei.value.code == "UNKNOWN_FORMAT_VERSION"
    assert m.errors == []
    with pytest.raises(FieldsealError):
        fs.decrypt(v2, CTX)
    assert m.errors == ["UNKNOWN_FORMAT_VERSION"]
