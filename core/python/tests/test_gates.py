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
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from fieldseal import (  # noqa: E402
    Argon2Params,
    CardinalityOverride,
    FieldContext,
    Fieldseal,
    IndexDeclaration,
    index_registry_key,
    validate_index_declaration,
)
from fieldseal.blindindex import (  # noqa: E402
    ARGON2_MIN_M_KIB,
    ARGON2_MIN_T,
)
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
IDX_CTX = CTX.for_index("email-eq")

OVERRIDE = CardinalityOverride(reason="test", approved_by="tests",
                               date="2026-08-25")


def _decl(**kw) -> IndexDeclaration:
    """A declaration on CTX's column, inside the §7.4 band for b=15."""
    d = dict(table_uuid=CTX.table_uuid, column_uuid=CTX.column_uuid,
             index_id="email-eq", idf="hmac-sha512",
             normalize="nfc-casefold-v1", truncate_bits=15,
             projected_population=65536)
    d.update(kw)
    return IndexDeclaration(**d)


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
    fs = _client(read_mode="readonly", indexes=[_decl()])
    assert fs.blind_index("alice@example.com", IDX_CTX)


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


def test_blind_index_takes_text_and_bytes_alike():
    """docs/09 §7.1: an index API must accept text, and widening the type
    must not fork the function."""
    fs = _client(indexes=[_decl()])
    for s in ("alice@example.com", "ALICE@example.com", "grüße", ""):
        assert fs.blind_index(s, IDX_CTX) == \
            fs.blind_index(s.encode("utf-8"), IDX_CTX)


def test_lone_surrogate_is_refused_distinguishably():
    """The false match the text path exists to close. Both are refused, and
    the messages name different code points -- an identical diagnosis would
    leave the two values indistinguishable, which is the property the refusal
    denies them."""
    fs = _client(indexes=[_decl()])
    msgs = []
    for s in ("a\ud800b", "a\udc00b"):
        with pytest.raises(InvalidArgument) as e:
            fs.blind_index(s, IDX_CTX)
        msgs.append(str(e.value))
    assert "D800" in msgs[0] and "DC00" in msgs[1]
    assert msgs[0] != msgs[1]


def test_first_unassigned_is_on_the_package_root():
    """docs/09 §7.1 requires cores to export the assigned-code-point check
    "for adapters that hold the text earlier and can give a better-sited
    error". It lived in `fieldseal.unicode` and never reached this root, so
    the MUST had no public surface at all (G22, #88). `UNICODE_VERSION` is
    exported with it: an adapter rendering "not assigned in Unicode 17.0.0"
    needs the version the check was made against, and a constant of its own
    is how two copies drift apart."""
    import fieldseal

    assert "first_unassigned" in fieldseal.__all__
    assert "UNICODE_VERSION" in fieldseal.__all__
    assert fieldseal.first_unassigned("plain ascii") is None


def test_first_unassigned_reports_the_position_in_code_points():
    """The half the export existed without.

    Before G22 the check returned the code point alone, so an adapter could
    name the character and not where it was -- and `docs/12` §10.2 requires
    both, because "somewhere in this field" is not something a person can act
    on. The Prisma adapter recovered the offset by regex over the core's error
    message, which never matched on the `nfc-casefold-v1` path that
    `on_unindexable` actually governs, so the shipped message named the
    character and silently dropped the position.

    **The unit is code points, not UTF-16 units**, and the astral cases are
    here because that is the only place the two differ. The TypeScript core
    returns the same numbers for the same strings; that agreement is a
    cross-core property no vector can express (an unpaired surrogate has no
    UTF-8 encoding, so `blind-index/` cannot key one), which is why it is
    asserted here and in `tests/unicode.test.ts` rather than in the suite."""
    from fieldseal import first_unassigned

    assert first_unassigned("\u0378") == (0x378, 0)
    assert first_unassigned("a\ud800b") == (0xD800, 1)
    assert first_unassigned("a\udc00b") == (0xDC00, 1)
    # One astral character ahead of the fault: code-point index 1, UTF-16
    # index 2. A core that counted UTF-16 units would say 2 here.
    assert first_unassigned("\U0001F510\u0378") == (0x378, 1)
    assert first_unassigned("\U0001F510\U0001F510\ufdd0") == (0xFDD0, 2)
    # Named access, so a message reads `stray.code_point` rather than `[0]`.
    stray = first_unassigned("\U0001F510\u0378")
    assert stray is not None
    assert (stray.code_point, stray.offset) == (0x378, 1)


def test_identity_normalizer_refuses_lone_surrogates_as_invalid_argument():
    """The same refusal on the byte-transparent path, and typed the same way.

    `identity` reaches the encoder rather than the Unicode tables, so the
    failure arrives as a `UnicodeEncodeError` unless the normalizer converts
    it. Untyped, it would escape the §9 taxonomy and diverge from the
    TypeScript core, which raises INVALID_ARGUMENT here.
    """
    fs = _client(indexes=[_decl(normalize="identity")])
    for s in ("a\ud800b", "a\udc00b"):
        with pytest.raises(InvalidArgument):
            fs.blind_index(s, IDX_CTX)


def test_on_unindexable_refuse_is_the_default():
    fs = _client(indexes=[_decl()])
    with pytest.raises(InvalidArgument):
        fs.blind_index(UNPINNED, IDX_CTX)


def test_on_unindexable_bucket_keeps_the_row_findable():
    """docs/09 §7.2: `bucket` derives a reserved marker rather than storing no
    index -- an absent index is the silent missing row spec §10.2 forbids."""
    fs = _client(indexes=[_decl(on_unindexable="bucket",
                                unindexable_override=OVERRIDE)])
    marker = fs.unindexable_marker(IDX_CTX)
    got = fs.blind_index(UNPINNED, IDX_CTX)
    assert got == marker
    assert len(marker) == 2          # ceil(15/8)
    assert marker != b"\x00\x00"     # derived, not a constant


def test_bucket_is_one_collision_class_that_lookup_reaches_naturally():
    """The same value normalizes the same way in both directions, so a query
    for an unindexable value derives the marker and matches those rows; §7.5
    re-verification narrows the candidates. An indexable value never lands
    there."""
    fs = _client(indexes=[_decl(on_unindexable="bucket",
                                unindexable_override=OVERRIDE)])
    a = fs.blind_index(UNPINNED, IDX_CTX)
    b = fs.blind_index(OTHER_UNPINNED, IDX_CTX)
    normal = fs.blind_index("alice@example.com", IDX_CTX)
    assert a == b
    assert normal != a


def test_bucket_is_refused_where_it_could_never_fire():
    """`identity` consults no Unicode table and never refuses, so a bucket for
    it would misrepresent the column as protected."""
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(normalize="identity", on_unindexable="bucket",
                               unindexable_override=OVERRIDE)])
    assert "never refuses" in str(e.value)


def test_unknown_on_unindexable_is_a_configuration_error():
    with pytest.raises(ConfigurationError):
        _client(indexes=[_decl(on_unindexable="skip")])


# -- docs/09 §7.2, the bucket ceremony ----------------------------------------

def test_bucket_requires_a_recorded_override():
    """Relaxing a default-deny rule is a reviewed, recorded act -- the same
    ceremony §7.6 requires for the cardinality gate, so that `bucket` cannot
    become a setting copied between columns. Without it the column is a
    configuration error, not a quiet default."""
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(on_unindexable="bucket")])
    assert "unindexable_override" in str(e.value)


@pytest.mark.parametrize("bad", [
    CardinalityOverride(reason="", approved_by="a", date="2026-08-25"),
    CardinalityOverride(reason="r", approved_by="", date="2026-08-25"),
    CardinalityOverride(reason="r", approved_by="a", date=""),
])
def test_bucket_override_must_be_complete(bad):
    """A present-but-empty field records nothing, so it is not an approval."""
    with pytest.raises(ConfigurationError):
        _client(indexes=[_decl(on_unindexable="bucket",
                               unindexable_override=bad)])


# -- spec §7.3, the Argon2id cost is a minimum, not a constant (#62) ----------

def test_argon2_cost_defaults_to_the_spec_minimum():
    """Absent parameters mean the §7.3 minima, resolved at validation so no
    derivation path carries a default of its own."""
    v = validate_index_declaration(_decl(idf="argon2id"))
    assert v.argon2 == Argon2Params(time_cost=ARGON2_MIN_T,
                                    memory_kib=ARGON2_MIN_M_KIB)
    assert validate_index_declaration(_decl()).argon2 is None


@pytest.mark.parametrize("params,field", [
    (Argon2Params(time_cost=ARGON2_MIN_T - 1, memory_kib=ARGON2_MIN_M_KIB),
     "time_cost"),
    (Argon2Params(time_cost=ARGON2_MIN_T, memory_kib=ARGON2_MIN_M_KIB - 1),
     "memory_kib"),
    (Argon2Params(time_cost=True, memory_kib=ARGON2_MIN_M_KIB), "time_cost"),
    (Argon2Params(time_cost=3.5, memory_kib=ARGON2_MIN_M_KIB), "time_cost"),
    (Argon2Params(time_cost=ARGON2_MIN_T, memory_kib=32768.0), "memory_kib"),
])
def test_argon2_cost_below_the_minimum_is_refused(params, field):
    """§7.3 states t and m as minima. Below either one the index is weaker
    than the specification allows, and it is refused where a column is
    declared rather than where a value is indexed -- a weakened index that
    reached one write is already in the database."""
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(idf="argon2id", argon2=params)])
    assert field in str(e.value)
    assert "§7.3" in str(e.value)


def test_argon2_params_of_the_wrong_type_are_a_configuration_error():
    """A mapping with the right keys is the plausible mistake. Reading its
    attributes would raise `AttributeError`, which is untyped and outside the
    taxonomy docs/09 §9 permits; the TypeScript core refuses the same shape as
    a configuration error by finding no integer where it needs one."""
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(idf="argon2id",
                               argon2={"time_cost": 4, "memory_kib": 32768})])
    assert "Argon2Params" in str(e.value)


def test_argon2_params_are_refused_on_an_hmac_index():
    """HMAC-SHA-512 has no cost parameters, so accepting them would record a
    configuration nothing reads -- an operator would believe a column was
    hardened that was not."""
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(argon2=Argon2Params())])
    assert "hmac-sha512" in str(e.value)


def test_a_raised_argon2_cost_reaches_the_derivation():
    """The point of the field (#62): a deployment that raises the cost gets
    index values derived at the raised cost, and a core that read the cost
    from a module constant would silently return the minimum's instead --
    same column, two index values, and a cross-implementation lookup that
    finds nothing.

    This asserts that the declared parameters are what the primitive is
    invoked with. It asserts nothing about whether that primitive matches
    another core's -- that is a vector obligation, and since 2026-08-31 the
    vectors carry it: `blind-index/argon2id.json` is pinned into the suite and
    both cores derive its values at the cost each vector declares -- including
    `raised-cost-t4-b15` and `unindexable-marker-t4-b15`, added in the #108
    review round, which are the vectors that assert cross-core agreement at a
    *raised* cost: the one configuration under which a core, or a harness,
    that quietly used the minima is told apart from one that did not.
    """
    pytest.importorskip("argon2.low_level",
                        reason="the argon2 extra is not installed")
    minimum = _client(indexes=[_decl(idf="argon2id")])
    explicit = _client(indexes=[_decl(idf="argon2id", argon2=Argon2Params())])
    raised = _client(indexes=[_decl(
        idf="argon2id",
        argon2=Argon2Params(time_cost=ARGON2_MIN_T + 1))])
    at_min = minimum.blind_index("alice@example.com", IDX_CTX)
    assert explicit.blind_index("alice@example.com", IDX_CTX) == at_min
    assert raised.blind_index("alice@example.com", IDX_CTX) != at_min


# -- spec §7.4 band and §7.6 cardinality gate ---------------------------------

def test_truncation_outside_the_7_4_band_is_refused():
    """Spec §7.4: 2 <= P*2^-b < sqrt(P). Too few bits floods every query with
    candidates; too many make the index a near-unique fingerprint of the
    value, which is the correlation §7.4 exists to bound."""
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(truncate_bits=4)])       # P*2^-b = 4096, > sqrt
    assert "§7.4" in str(e.value)
    with pytest.raises(ConfigurationError):
        _client(indexes=[_decl(truncate_bits=40)])      # P*2^-b far below 2


def test_low_cardinality_is_refused_by_default():
    """Spec §7.6 is default-deny: a column with few distinct values leaks its
    distribution to anyone who can read the index."""
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(projected_population=256, truncate_bits=5)])
    assert "§7.6" in str(e.value)


def test_low_cardinality_passes_with_a_recorded_override():
    fs = _client(indexes=[_decl(projected_population=256, truncate_bits=5,
                                cardinality_override=OVERRIDE)])
    assert fs.blind_index("alice@example.com", IDX_CTX)


def test_declared_skew_is_gated_like_low_cardinality():
    """Spec §7.6: a large but heavily skewed column leaks the same way."""
    with pytest.raises(ConfigurationError):
        _client(indexes=[_decl(skewed=True)])
    assert _client(indexes=[_decl(skewed=True,
                                  cardinality_override=OVERRIDE)])


# -- docs/09 §7, declarations are resolved, not described at the call ---------

def test_undeclared_index_is_a_configuration_error():
    """Spec §7.8: an index the client was never told about cannot be derived
    on demand -- that would be a column whose gates nobody ran."""
    fs = _client(indexes=[_decl()])
    with pytest.raises(ConfigurationError) as e:
        fs.blind_index("x", CTX.for_index("never-declared"))
    assert "declared at construction" in str(e.value)


def test_blind_index_requires_an_index_purpose():
    fs = _client(indexes=[_decl()])
    with pytest.raises(InvalidArgument) as e:
        fs.blind_index("x", CTX)
    assert "for_index" in str(e.value)


def test_duplicate_declarations_are_refused():
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(), _decl()])
    assert "duplicate" in str(e.value)


def test_unknown_idf_or_normalizer_is_refused_at_declaration():
    """Fails closed at construction (docs/09 §3.3 step 2), naming the field
    that is actually wrong rather than a downstream symptom."""
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(idf="md5")])
    assert "idf" in str(e.value)
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(normalize="nope")])
    assert "normalizer" in str(e.value)


def test_index_id_grammar_is_checked_at_declaration():
    with pytest.raises(ConfigurationError) as e:
        _client(indexes=[_decl(index_id="Email_EQ")])
    assert "§6.1" in str(e.value)


# -- docs/09 §2 configuration reflection (G18) --------------------------------

def test_client_reflects_its_validated_configuration():
    """docs/09 §2: what construction validated must be readable back.

    Everything asserted here decides stored bytes, query results or read
    behaviour. The key provider and the cache are deliberately absent from the
    surface, which is what the last assertion pins.
    """
    fs = _client(indexes=[_decl()])
    assert fs.read_mode == "strict"
    assert fs.write_suite == 0xFF01
    assert fs.allowed_suites == frozenset({0xFF01})
    assert fs.provisional_armed is True
    # The allow-list is the other collection on this surface, and the decrypt
    # path consults it. `frozenset` carries no mutating methods, so this
    # binding needs no copy where TypeScript's `ReadonlySet` -- a type, not a
    # runtime guarantee -- does. Pinned so the type cannot quietly become a
    # `set`.
    assert isinstance(fs.allowed_suites, frozenset)
    assert not hasattr(fs.allowed_suites, "add")
    # The carve-out is the point of stating the rule as a principle: a
    # reflected handle to the object holding key material is a larger surface
    # than any consumer of this needs.
    assert not hasattr(fs, "key_provider")


def test_index_registry_is_readable_and_resolved():
    """Validated, not as-declared.

    `argon2` absent in the declaration comes back filled in from the §7.3
    minima, and `on_unindexable` comes back as its `refuse` default. Comparing
    as-declared inputs would let two declarations that agree textually and
    differ operationally register as a match -- the failure #62 was.
    """
    fs = _client(indexes=[_decl(idf="argon2id")])
    key = index_registry_key(CTX.table_uuid, CTX.column_uuid, "email-eq")
    assert set(fs.indexes) == {key}
    v = fs.indexes[key]
    assert v.idf == "argon2id"
    assert v.argon2 == Argon2Params(time_cost=ARGON2_MIN_T,
                                    memory_kib=ARGON2_MIN_M_KIB)
    assert v.on_unindexable == "refuse"
    assert v.truncate_bits == 15
    # The public validation entry point resolves a declaration to exactly what
    # the client holds, which is what makes an exact-match check writable from
    # outside the core at all.
    assert validate_index_declaration(_decl(idf="argon2id")) == v


def test_reflected_registry_cannot_mutate_the_client():
    """docs/09 §2 makes the client immutable after construction, and an
    accessor handing out the live registry would make that untrue for anyone
    who asked for it."""
    fs = _client(indexes=[_decl()])
    view = fs.indexes
    key = next(iter(view))
    with pytest.raises(TypeError):
        view["injected"] = view[key]  # type: ignore[index]
    # `mappingproxy` has no mutating methods at all, which is a stronger
    # guarantee than refusing them.
    assert not hasattr(view, "clear")
    assert not hasattr(view, "pop")
    assert len(fs.indexes) == 1
    # The declarations themselves are frozen, so a caller holding one cannot
    # rewrite the truncation length of a live index either.
    with pytest.raises(FrozenInstanceError):
        view[key].truncate_bits = 32  # type: ignore[misc]


def test_reflection_is_empty_rather_than_absent_with_no_indexes():
    """An adapter comparing registries must be able to tell "no indexes
    declared" from "this core cannot say", and only one of those is a state."""
    fs = _client()
    assert dict(fs.indexes) == {}


# -- docs/09 §7: the normalizer set is public (G19) ---------------------------

def test_normalize_is_public_and_the_set_is_closed():
    """§7.5 re-verification compares *normalized* values, and that comparison
    happens in the adapter -- so the one implementation has to be reachable.

    An adapter that reimplemented `nfc-casefold-v1` would be reimplementing
    portability surface: the identifier IS the definition (docs/09 §7), and
    two implementations disagreeing on it is a silent lookup miss, not an
    error.
    """
    from fieldseal import NORMALIZER_IDS, normalize

    assert set(NORMALIZER_IDS) == {"identity", "nfc-casefold-v1",
                                   "digits-only-v1"}
    assert normalize("identity", b"Ada") == b"Ada"
    assert normalize("nfc-casefold-v1", "Ada@Example.COM") == b"ada@example.com"
    assert normalize("digits-only-v1", "555-0100") == b"5550100"


def test_normalize_agrees_with_what_blind_index_derives():
    """The public helper must be the same function the index path uses, or
    an adapter verifying with it would disagree with the column it queried."""
    from fieldseal import normalize

    fs = _client(indexes=[_decl()])
    a = fs.blind_index("Ada@Example.COM", IDX_CTX)
    b = fs.blind_index(normalize("nfc-casefold-v1", "Ada@Example.COM"), IDX_CTX)
    assert a == b


def test_an_unknown_normalizer_is_refused():
    from fieldseal import normalize

    with pytest.raises(ConfigurationError) as e:
        normalize("nfc-casefold-v2", "x")
    assert "closed" in str(e.value)
