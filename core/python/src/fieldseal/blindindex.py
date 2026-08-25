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

ARGON2_SALT_INFO = b"fieldseal-argon2-salt-v1"
ARGON2_SALT_LEN = 16
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 32768
ARGON2_PARALLELISM = 1
ARGON2_OUTPUT_LEN = 64
ARGON2_VERSION = 0x13


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
            f"value contains U+{stray:04X}, which is not assigned in Unicode "
            f"{unicode.UNICODE_VERSION}; `nfc-casefold-v1` is pinned to that "
            "version and cannot index a character it does not define")
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
    if d.normalize not in NORMALIZERS:
        raise ConfigurationError(
            f"index declaration {index_id}: unknown normalizer "
            f"{d.normalize!r}; must be one of the shipped normalizers "
            f"{sorted(NORMALIZERS)} (docs/09 §7). A custom normalizer is a "
            "portability break")
    p = d.projected_population
    if not isinstance(p, int) or isinstance(p, bool) or p < 16:
        raise ConfigurationError(
            f"index declaration {index_id}: projected_population must be an "
            "integer >= 16 (spec §7.4)")
    b = d.truncate_bits
    if not isinstance(b, int) or isinstance(b, bool) or b < 1 or b > _RAW_BITS:
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


def idf_argon2id(index_key: bytes, normalized: bytes) -> bytes:
    """Spec §7.3.

    UNVALIDATED. The `blind-index/argon2id.json` vector family is held out of
    the pinned suite because this primitive has never been checked against an
    external known-answer source -- RFC 9106 §5.3's vector needs a nonzero
    secret and associated data, both of which §7.3 forbids and Python cannot
    supply. Passing the project's own vectors here would prove only that two
    implementations copied one unverified assumption.
    """
    from argon2.low_level import Type, hash_secret_raw

    # `secret=` here is argon2-cffi's name for the PASSWORD. It is *not*
    # RFC 9106's secret value K, which §7.3 forbids and which this API cannot
    # supply anyway. Passing index_key here would be silently wrong.
    return hash_secret_raw(
        secret=normalized,
        salt=argon2_salt(index_key),
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_OUTPUT_LEN,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


IDFS: dict[str, Callable[[bytes, bytes], bytes]] = {
    "argon2id": idf_argon2id,
    "hmac-sha512": idf_hmac_sha512,
}
