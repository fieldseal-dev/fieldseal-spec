"""Blind index derivation (spec §7.2, §7.3), normalizers (docs/09 §7) and
truncation."""

from __future__ import annotations

import hmac
import math
import re
from collections.abc import Callable
from dataclasses import dataclass

from . import unicode
from .errors import ConfigurationError, InvalidArgument
from .kdf import hkdf_sha512

# Spec §7.3's Argon2id invocation. `version`, `p`, `output_len` and the salt
# derivation MUST NOT vary; `t` and `m` are stated there as *minima* a
# deployment MAY raise, so they are named as minima here and are the only two
# a declaration carries (see `Argon2Params`).
ARGON2_SALT_INFO = b"fieldseal-argon2-salt-v1"
ARGON2_SALT_LEN = 16
ARGON2_MIN_T = 3
ARGON2_MIN_M_KIB = 32768
ARGON2_PARALLELISM = 1
ARGON2_OUTPUT_LEN = 64
ARGON2_VERSION = 0x13


@dataclass(frozen=True, slots=True)
class Argon2Params:
    """The two Argon2id cost parameters spec §7.3 lets a deployment raise.

    Everything else in that invocation -- version, parallelism, output length,
    the salt derivation -- is fixed, and is deliberately absent here: a
    parameter with no legal second value is a constant, and giving it a field
    would invite an implementation to vary it.

    Raising either parameter derives different index values for the same
    plaintext, so a raised pair is a *new index* under spec §7.8, not a
    reconfiguration of an existing one.
    """
    time_cost: int = ARGON2_MIN_T
    memory_kib: int = ARGON2_MIN_M_KIB


def truncate(raw: bytes, b_bits: int) -> bytes:
    """Spec §7.2, bit-exact: leading ceil(b/8) bytes, trailing
    8*ceil(b/8) - b bits of the final byte zeroed, MSB-first numbering."""
    if b_bits <= 0:
        raise ValueError("b must be positive")
    n = (b_bits + 7) // 8
    if n > len(raw):
        raise ValueError(f"cannot truncate {len(raw)} bytes to {b_bits} bits")
    out = bytearray(raw[:n])
    spare = 8 * n - b_bits
    if spare:
        out[-1] &= (0xFF << spare) & 0xFF
    return bytes(out)


# -- normalizers (docs/09 §7: a closed, versioned set; portability surface) ---

def _as_text(value: str | bytes) -> str:
    """A text normalizer over bytes decodes them as UTF-8, strictly. Decoding
    with replacement characters would map distinct invalid inputs onto one
    index value, so invalid UTF-8 is refused instead (docs/18 D-10(d))."""
    if isinstance(value, str):
        return value
    try:
        return bytes(value).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InvalidArgument(
            "value is not valid UTF-8; a text normalizer cannot index it "
            "(use the `identity` normalizer for opaque bytes)") from exc


def _as_bytes(value: str | bytes) -> bytes:
    """Text becomes its UTF-8 encoding, strictly.

    Python's `str.encode` already refuses an unpaired surrogate rather than
    substituting for it -- substitution would map U+D800 and U+DC00 onto one
    index value and reintroduce the collision docs/09 §7.1 closes. What it
    raises is a `UnicodeEncodeError`, which is outside the §9 taxonomy and
    which `blind_index` would not recognise as the refusal `on_unindexable`
    acts on. Re-raise it as the typed error, so both cores refuse the same
    input with the same error code.
    """
    if not isinstance(value, str):
        return bytes(value)
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InvalidArgument(
            f"value contains an unpaired surrogate at position {exc.start}; "
            "it has no UTF-8 encoding and cannot be indexed") from exc


def normalize_identity(value: str | bytes) -> bytes:
    """`identity` -- bytes unchanged; text is its UTF-8 encoding."""
    return _as_bytes(value)


def normalize_nfc_casefold(value: str | bytes) -> bytes:
    """`nfc-casefold-v1` (docs/09 §7): NFC, full case folding, NFC again,
    then UTF-8 -- all at the pinned Unicode version, from vendored tables.

    The second NFC is what makes this a caseless-matching function rather
    than merely a deterministic one. Folding a precomposed character can
    yield a decomposed sequence, so without it the same letter in two cases
    lands on two index values: U+0390 folds to U+03B9 U+0308 U+0301, while
    its uppercase spelling U+03AA U+0301 folds to U+03CA U+0301. Those are
    canonically equivalent and would be one lookup to a user, and two
    different blind indexes to the database. Re-normalizing collapses them.

    This is not Unicode's canonical caseless match, which is
    NFD(toCasefold(NFD(X))) and outputs NFD; this outputs NFC, which is
    shorter as a stored value.

    Input containing a code point unassigned in the pinned version is
    refused: its normalization is not yet fixed, so a core built against a
    later UCD would index it differently. Refusing is visible; disagreeing
    is not.
    """
    text = _as_text(value)
    stray = unicode.first_unassigned(text)
    if stray is not None:
        raise InvalidArgument(
            f"value contains U+{stray.code_point:04X}, which is not "
            f"assigned in Unicode {unicode.UNICODE_VERSION}; "
            "`nfc-casefold-v1` is pinned to that version and cannot index a "
            "character it does not define")
    folded = unicode.casefold_full(unicode.nfc(text))
    return unicode.nfc(folded).encode("utf-8")


_NON_DIGIT = re.compile(rb"[^0-9]")


def normalize_digits_only(value: str | bytes) -> bytes:
    """`digits-only-v1` -- strip every byte that is not an ASCII digit
    (docs/09 §7; phone/SSN-like values). Defined on bytes, so it needs no
    decoding and consults no Unicode table.

    It is still not total over `str`: text has to be encoded before the
    stripping can happen, and a string holding an unpaired surrogate has no
    UTF-8 encoding at all. That refusal comes from the encoder, not from a
    pinned-version question, which is why this normalizer stays outside
    `REFUSING_NORMALIZERS` -- `on_unindexable` exists for values the pin
    cannot define, not for values that cannot be encoded."""
    return _NON_DIGIT.sub(b"", _as_bytes(value))


NORMALIZERS: dict[str, Callable[[str | bytes], bytes]] = {
    "identity": normalize_identity,
    "nfc-casefold-v1": normalize_nfc_casefold,
    "digits-only-v1": normalize_digits_only,
}

NORMALIZER_IDS = tuple(sorted(NORMALIZERS))


def normalize(normalizer_id: str, value: str | bytes) -> bytes:
    """Apply one of the closed set of normalizers by id (docs/09 §7).

    Public because §7.5 re-verification compares *normalized* values (G19),
    and that comparison happens in the adapter. An adapter that reimplemented
    `nfc-casefold-v1` would be reimplementing portability surface -- the
    identifier IS the definition, and two implementations disagreeing on it
    is a silent lookup miss rather than an error. So the core hands out the
    one implementation instead of leaving callers to write a second.
    """
    fn = NORMALIZERS.get(normalizer_id)
    if fn is None:
        raise ConfigurationError(
            f"unknown normalizer {normalizer_id!r}; the set is closed and "
            f"versioned: {sorted(NORMALIZERS)} (docs/09 §7)")
    return fn(value)


# Normalizers that can refuse an otherwise-storable value (docs/09 §7.2).
# Only these make `on_unindexable` meaningful: `identity` and `digits-only-v1`
# consult no Unicode table and have nothing to refuse.
REFUSING_NORMALIZERS = frozenset({"nfc-casefold-v1"})

# docs/09 §7.2. The leading 0xFF can never appear in UTF-8, so no input
# `nfc-casefold-v1` accepts can normalize to this preimage -- the marker
# cannot collide with a real value by construction rather than by luck.
UNINDEXABLE_PREIMAGE = b"\xff" + b"fieldseal-unindexable-v1"


# -- the index declaration (docs/09 §7) --------------------------------------

@dataclass(frozen=True, slots=True)
class CardinalityOverride:
    """The recorded act that relaxes a default-deny gate (spec §7.6)."""
    reason: str
    approved_by: str
    date: str


@dataclass(frozen=True, slots=True)
class IndexDeclaration:
    """docs/09 §7: an index is declared to the client at construction, not
    described at each call.

    That is not an ergonomic preference. The §7.4 truncation band and the
    §7.6 cardinality gate are properties of a *column* -- they ask how many
    distinct values it will hold -- and a per-call parameter has no column to
    ask about. Declaring the index once gives those gates somewhere to run,
    and gives them one place to fail: a column whose configuration the spec
    refuses never reaches a key derivation.
    """
    table_uuid: bytes
    column_uuid: bytes
    idf: str
    normalize: str
    truncate_bits: int
    #: Projected number of DISTINCT values (spec §7.4), >= 16; >= 2^10 unless
    #: overridden (§7.6).
    projected_population: int
    index_id: str = "exact"
    #: Argon2id cost for this column, for `idf="argon2id"` only. Absent means
    #: the spec §7.3 minima. It is per-column and not a module constant
    #: because §7.3 states the cost as a minimum a deployment MAY raise: a
    #: core that could not express a raised value would derive under the
    #: minimum instead -- silently, and only until a core that could express
    #: it wrote the same column.
    argon2: Argon2Params | None = None
    cardinality_override: CardinalityOverride | None = None
    #: Declares the column as heavily skewed (spec §7.6); gated like low
    #: cardinality.
    skewed: bool = False
    #: What happens to a value the normalizer refuses -- one containing a code
    #: point the pinned Unicode version does not define (docs/09 §7.2).
    #: `refuse` (default) propagates the `InvalidArgument`, so an adapter
    #: deriving an index on write fails the write. `bucket` returns this
    #: column's reserved marker instead, keeping the row findable: the same
    #: marker is derived on lookup, and spec §7.5 re-verification narrows the
    #: candidates. Storing *no* index is not an option -- that is the silent
    #: missing row spec §10.2 forbids.
    on_unindexable: str = "refuse"
    #: Required when `on_unindexable` is `bucket`; same shape §7.6 requires.
    unindexable_override: CardinalityOverride | None = None


@dataclass(frozen=True, slots=True)
class ValidatedIndex:
    key: str
    index_id: str
    idf: str
    #: Resolved, never absent for `argon2id` (the minima are filled in at
    #: validation, so no derivation path has to know a default); always
    #: `None` for `hmac-sha512`, which has no cost parameters.
    argon2: Argon2Params | None
    normalize: str
    truncate_bits: int
    projected_population: int
    overridden: bool
    on_unindexable: str


CARDINALITY_GATE = 1 << 10

# Both IDFs produce 64 bytes, so that is the ceiling on a truncation length.
_RAW_BITS = ARGON2_OUTPUT_LEN * 8

_INDEX_ID_RE = re.compile(r"\A[a-z0-9-]{1,32}\Z")


def index_registry_key(table_uuid: bytes, column_uuid: bytes,
                       index_id: str) -> str:
    return f"{table_uuid.hex()}/{column_uuid.hex()}/{index_id}"


def _int(v: object) -> bool:
    """`bool` is an `int` in Python and is never a count here."""
    return isinstance(v, int) and not isinstance(v, bool)


def _recorded(o: CardinalityOverride | None) -> bool:
    return (isinstance(o, CardinalityOverride) and bool(o.reason)
            and bool(o.approved_by) and bool(o.date))


def validate_index_declaration(d: IndexDeclaration) -> ValidatedIndex:
    """Construction-time validation (docs/09 §2, §7).

    Everything here is a `ConfigurationError`: configuration validation sits
    outside the §9 taxonomy (docs/08 §4.3), and a declaration that fails must
    never reach a key derivation.
    """
    if len(d.table_uuid) != 16:
        raise ConfigurationError(
            "index declaration: table_uuid must be 16 bytes")
    if len(d.column_uuid) != 16:
        raise ConfigurationError(
            "index declaration: column_uuid must be 16 bytes")
    index_id = d.index_id
    if not isinstance(index_id, str) or not _INDEX_ID_RE.match(index_id):
        # Spec §6.1: refused when the index is declared, never at call time.
        raise ConfigurationError(
            f"index declaration: index-id {index_id!r} violates the spec "
            "§6.1 grammar [a-z0-9-]{1,32}")
    if d.idf not in IDFS:
        raise ConfigurationError(
            f"index declaration {index_id}: unknown idf {d.idf!r}; must be "
            f"one of {sorted(IDFS)} (spec §7.3)")
    # Spec §7.3: t and m are minima. Resolving them here rather than at
    # derivation time is what keeps a raised cost a property of the column --
    # and refusing a value below the minimum at construction keeps a weakened
    # index from ever being written.
    argon2 = d.argon2
    if d.idf == "argon2id":
        if argon2 is None:
            argon2 = Argon2Params()
        if not isinstance(argon2, Argon2Params):
            # A mapping with the right keys is the plausible mistake, and
            # reading its attributes would raise `AttributeError` -- untyped,
            # and outside the taxonomy docs/09 §9 permits. The TypeScript core
            # reaches the same refusal by finding no integer where it needs
            # one, so both cores refuse a malformed declaration as a
            # configuration error rather than as a crash.
            raise ConfigurationError(
                f"index declaration {index_id}: argon2 must be an "
                f"Argon2Params, not {type(argon2).__name__} (spec §7.3)")
        if not _int(argon2.time_cost) or argon2.time_cost < ARGON2_MIN_T:
            raise ConfigurationError(
                f"index declaration {index_id}: argon2 time_cost must be an "
                f"integer >= {ARGON2_MIN_T} (spec §7.3)")
        if not _int(argon2.memory_kib) or argon2.memory_kib < ARGON2_MIN_M_KIB:
            raise ConfigurationError(
                f"index declaration {index_id}: argon2 memory_kib must be an "
                f"integer >= {ARGON2_MIN_M_KIB} (spec §7.3)")
    elif argon2 is not None:
        # Accepting them silently would record a cost that nothing reads.
        raise ConfigurationError(
            f"index declaration {index_id}: argon2 parameters given for an "
            f"{d.idf} index; only argon2id takes them (spec §7.3)")
    if d.normalize not in NORMALIZERS:
        raise ConfigurationError(
            f"index declaration {index_id}: unknown normalizer "
            f"{d.normalize!r}; must be one of the shipped normalizers "
            f"{sorted(NORMALIZERS)} (docs/09 §7). A custom normalizer is a "
            "portability break")
    p = d.projected_population
    if not _int(p) or p < 16:
        raise ConfigurationError(
            f"index declaration {index_id}: projected_population must be an "
            "integer >= 16 (spec §7.4)")
    b = d.truncate_bits
    if not _int(b) or b < 1 or b > _RAW_BITS:
        raise ConfigurationError(
            f"index declaration {index_id}: truncate_bits must be an integer "
            f"in 1..{_RAW_BITS}")
    # Spec §7.4: 2 <= P x 2^(-b) < sqrt(P). A declared b outside the band is a
    # spec violation the core can see at construction, so it is refused here
    # rather than silently accepted.
    collisions = p / 2 ** b
    if not (collisions >= 2 and collisions < math.sqrt(p)):
        raise ConfigurationError(
            f"index declaration {index_id}: truncate_bits={b} is outside the "
            f"spec §7.4 band for P={p} (need 2 <= P*2^-b < sqrt(P); got "
            f"{collisions:.3f})")
    # Spec §7.6 default-deny gate.
    gated = p < CARDINALITY_GATE or d.skewed
    overridden = False
    if gated:
        if not _recorded(d.cardinality_override):
            raise ConfigurationError(
                f"index declaration {index_id}: refused by the spec §7.6 "
                f"cardinality gate (P={p}"
                f"{', declared skewed' if d.skewed else ''}); an explicit "
                "cardinality_override {reason, approved_by, date} is required")
        overridden = True
    # docs/09 §7.2. Relaxing a default-deny rule on a column is a reviewed,
    # recorded act -- deliberately the same ceremony §7.6 requires above, so
    # that `bucket` cannot become a setting copied between columns.
    if d.on_unindexable not in ("refuse", "bucket"):
        raise ConfigurationError(
            f"index declaration {index_id}: on_unindexable must be 'refuse' "
            f"or 'bucket', not {d.on_unindexable!r}")
    if d.on_unindexable == "bucket":
        if d.normalize not in REFUSING_NORMALIZERS:
            # The setting could never take effect, and accepting it silently
            # would misrepresent the column as protected.
            raise ConfigurationError(
                f"index declaration {index_id}: on_unindexable='bucket' is "
                f"meaningless for normalizer {d.normalize!r}, which never "
                f"refuses a value; only {sorted(REFUSING_NORMALIZERS)} can")
        if not _recorded(d.unindexable_override):
            raise ConfigurationError(
                f"index declaration {index_id}: on_unindexable='bucket' "
                "stores unindexable rows under a reserved marker that is "
                "distinguishable by frequency (docs/09 §7.2); an explicit "
                "unindexable_override {reason, approved_by, date} is required")
    return ValidatedIndex(
        key=index_registry_key(d.table_uuid, d.column_uuid, index_id),
        index_id=index_id,
        idf=d.idf,
        argon2=argon2,
        normalize=d.normalize,
        truncate_bits=b,
        projected_population=p,
        overridden=overridden,
        on_unindexable=d.on_unindexable,
    )


# -- IDFs (spec §7.3) ---------------------------------------------------------

def idf_hmac_sha512(index_key: bytes, normalized: bytes) -> bytes:
    return hmac.new(index_key, normalized, "sha512").digest()


def argon2_salt(index_key: bytes) -> bytes:
    return hkdf_sha512(ikm=index_key, salt=b"", info=ARGON2_SALT_INFO,
                       length=ARGON2_SALT_LEN)


def idf_argon2id(index_key: bytes, normalized: bytes,
                 params: Argon2Params | None = None) -> bytes:
    """Spec §7.3, at `params` (the minima when absent).

    Externally checked, and pinned since suite 0.6.0-provisional. This
    docstring read UNVALIDATED while `blind-index/argon2id.json` was held out
    of the suite, on the ground that the primitive had never been checked
    against an outside known-answer source. That ground is gone twice over:
    the generator verifies argon2-cffi against libsodium's seven published
    `crypto_pwhash` answers on every run (`tools/vector-gen`
    `kat_argon2id.py`), and the TypeScript core reproduces this family's
    expected values through `node:crypto`, a backend that shares no code with
    this one.

    The original limitation still stands and is worth keeping straight: RFC
    9106 §5.3's own vector sets a nonzero secret `K` and associated data `X`,
    both forbidden by §7.3 and unsuppliable from Python. libsodium cannot
    supply them either, which is precisely why its answers are the right
    external source for the empty-`K`/`X` case §7.3 actually uses.
    """
    from argon2.low_level import Type, hash_secret_raw

    cost = params if params is not None else Argon2Params()
    # The salt is key material and this binding cannot erase it. Spec §7.3
    # forbids Argon2's K and X, so keying "rests entirely on the salt"
    # (docs/02 line 546): these 16 bytes carry the full strength of the
    # column's index key, and anyone holding them can mount the same offline
    # dictionary attack on the column's stored indexes as the holder of the
    # key. The TypeScript core zeroes its salt (`idf`/`idfAsync`, PR #111
    # review); this one cannot, because argon2-cffi accepts only immutable
    # `bytes` for `salt=` -- `bytearray` and `memoryview` are both rejected
    # with TypeError (verified against argon2-cffi 25.1.0; pinned by
    # tests/test_blindindex_salt.py, which fails if that ever changes so
    # this decision gets revisited rather than forgotten).
    #
    # Nothing is gained by deriving into a `bytearray` and converting at the
    # call: the `bytes` copy handed to the primitive is the exposure, and it
    # is unwipeable either way. Recorded rather than fixed, in the same terms
    # as record_key (docs/10 §5) -- and the salt is passed inline here
    # precisely so no longer-lived reference to it exists.
    #
    # `secret=` here is argon2-cffi's name for the PASSWORD. It is *not*
    # RFC 9106's secret value K, which §7.3 forbids and which this API cannot
    # supply anyway. Passing index_key here would be silently wrong.
    return hash_secret_raw(
        secret=normalized,
        salt=argon2_salt(index_key),
        time_cost=cost.time_cost,
        memory_cost=cost.memory_kib,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_OUTPUT_LEN,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


def idf(which: str, index_key: bytes, normalized: bytes,
        argon2: Argon2Params | None = None) -> bytes:
    """`IDF(index_key, normalized)` per spec §7.3, for either IDF.

    Dispatch is a function rather than a table of callables because the two
    IDFs do not take the same arguments: Argon2id carries a per-column cost
    and HMAC-SHA-512 has none. A table typed to the narrower signature is what
    made a raised cost inexpressible here while the TypeScript core accepted
    it -- the two cores agreeing on every shipped vector, which pins the
    minima, and diverging the first time an operator raised the cost on one
    of them (issue #62).
    """
    if which == "hmac-sha512":
        return idf_hmac_sha512(index_key, normalized)
    if which == "argon2id":
        return idf_argon2id(index_key, normalized, argon2)
    # Unreachable through a validated declaration; raised rather than
    # returning a default, so a new IDF cannot silently derive under an old
    # one (docs/09 §3.3 step 2, fail closed).
    raise ConfigurationError(
        f"unknown idf {which!r}; must be one of {sorted(IDFS)} (spec §7.3)")


#: The IDF identifiers spec §7.3 defines. A frozen set, not a dispatch table:
#: see `idf` above.
IDFS: frozenset[str] = frozenset({"argon2id", "hmac-sha512"})
