"""The Fieldseal client (spec §11.1, docs/10 §4).

Every value-path operation here is strictly synchronous and performs no I/O.
That is not a style preference: Django field types, SQLAlchemy type
processors, TypeORM transformers and the rest cannot await in the value path,
and a core that required them to would be unusable in the place it is meant to
be used. The one exception is `warm`, the §11.2 prefetch and the only
coroutine on the client (docs/10 §4): all KMS/network I/O lives there, off
the value path.

The decrypt path follows docs/09 §3.2 step for step. Spec §9 leaves the
precedence among its error codes open (gap G5) and obliges a Gate 0a
implementation to pin one and declare it in its conformance report; this
module is the pin, and `tests/run_vectors.py` carries the declaration. Where
the spec is silent on an observable choice, the comment says so and names the
docs/18 entry that records it.
"""

from __future__ import annotations

import os
import secrets
import warnings
from collections.abc import Iterable, Mapping
from types import MappingProxyType

from cryptography.hazmat.primitives import constant_time

from .aead.gcm import GcmBackend
from .blindindex import (
    NORMALIZERS,
    UNINDEXABLE_PREIMAGE,
    IndexDeclaration,
    ValidatedIndex,
    idf,
    index_registry_key,
    truncate,
    validate_index_declaration,
)
from .context import FieldContext, aad
from .envelope import (
    FMT_VER,
    MAX_PLAINTEXT,
    EnvelopeHeader,
    implied_plaintext_len,
    is_ciphertext,
    recognize,
    serialize_header,
    split,
)
from .errors import (
    CommitmentInvalid,
    ConfigurationError,
    FieldsealWarning,
    InvalidArgument,
    KeyUnavailable,
    LengthExceeded,
    ModeViolation,
    NotCiphertext,
    SuiteNotAllowed,
    SuiteProvisional,
)
from .kdf import commitment, index_key, record_key
from .keyprovider import KeyProvider
from .registry import SUITES, Suite, is_provisional

# Spec §4.8 constrains the arming mechanism's shape but does not name it
# (docs/18 D-14). The name uses §4.8's own verb -- the section speaks of
# "arming" throughout -- and is plural like `allowed_suites`. The TypeScript
# core reads the same variable, so an operator running both cores meets one
# name; until the spec names it, the conformance report declares it
# (`pinned_decisions.provisional-arming`).
PROVISIONAL_ENV = "FIELDSEAL_ARM_PROVISIONAL_SUITES"

READ_MODES = ("strict", "permissive", "readonly")

# Registered != performable. The registry (spec §4.2) is the format's list of
# suites; this is the list this *build* can actually execute. Suite 0xFF02
# needs an XChaCha20-Poly1305 backend that is not written -- gap G7 leaves it
# without a citable normative definition -- so it is registered and absent
# here on purpose.
_BACKENDS = {0xFF01: GcmBackend()}


def _backend(suite_id: int) -> GcmBackend:
    try:
        return _BACKENDS[suite_id]
    except KeyError:
        # Defensive: the constructor refuses unperformable suites, so reaching
        # this means the registry and _BACKENDS drifted apart. Raise the typed
        # error anyway -- a KeyError escaping the core would break the contract
        # that every failure is a FieldsealError.
        raise SuiteNotAllowed(
            f"suite {suite_id:#06x} is registered but this build has no "
            "backend for it") from None


class Fieldseal:
    def __init__(self, *, key_provider: KeyProvider, allowed_suites: set[int],
                 write_suite: int, read_mode: str = "strict",
                 indexes: Iterable[IndexDeclaration] = (),
                 arm_provisional_suites: bool = False) -> None:
        if write_suite not in allowed_suites:
            raise ConfigurationError("write_suite must be in allowed_suites")
        for sid in set(allowed_suites) | {write_suite}:
            if sid not in SUITES:
                raise ConfigurationError(f"unregistered suite {sid:#06x}")
            # Refused at construction rather than at the first call. A client
            # that cannot perform a suite it claims to allow would otherwise
            # pass is_ciphertext() on such an envelope and then fail inside
            # decrypt, which is the worst place to discover it (docs/18 D-12).
            if sid not in _BACKENDS:
                raise ConfigurationError(
                    f"suite {sid:#06x} ({SUITES[sid].name}) is registered but "
                    "this build has no backend for it (gap G7); install the "
                    "extra that provides it or remove it from allowed_suites")
        if read_mode not in READ_MODES:
            raise ConfigurationError(f"unknown read_mode {read_mode!r}")

        self._provider = key_provider
        self._allowed = frozenset(allowed_suites)
        self._write_suite = write_suite
        self._read_mode = read_mode
        # docs/09 §7: indexes are declared here, so the §7.4 band and the §7.6
        # cardinality gate run once, on the column, before any key derivation.
        self._indexes: dict[str, ValidatedIndex] = {}
        for decl in indexes:
            v = validate_index_declaration(decl)
            if v.key in self._indexes:
                raise ConfigurationError(
                    f"duplicate index declaration {v.key}")
            self._indexes[v.key] = v
        # Spec §4.8: arming is an affirmative out-of-band act. It is a separate
        # constructor argument or an environment variable, deliberately not a
        # member of the configuration carrying allowed_suites/write_suite, so
        # that it cannot be inherited by copying a config file.
        self._provisional_armed = bool(
            arm_provisional_suites
            or os.environ.get(PROVISIONAL_ENV) == "1")
        # Spec §10.3: the pass-through modes MUST warn while active and SHOULD
        # count plaintext reads. The counter is the metric; embedders can
        # export it however they export anything else.
        self.plaintext_reads = 0
        if read_mode != "strict":
            warnings.warn(
                f"Fieldseal read_mode={read_mode!r}: non-envelope input is "
                "returned as plaintext (spec §10.3). This is a migration "
                "setting, not a steady state.", FieldsealWarning, stacklevel=2)

    # -- configuration reflection (docs/09 §2, G18) ------------------------
    #
    # Read-only views of what construction validated. The rule is stated as a
    # principle in docs/09 §2: everything that decides stored bytes, query
    # results or read behaviour is reportable; the key provider and the cache
    # are not, because a reflected handle to the object holding key material
    # is a larger surface than any consumer needs.
    #
    # `indexes` is the load-bearing one. Without it a check like the Django
    # adapter's E006 -- does a hand-supplied client's registry match what the
    # models declare -- can only be written against `_indexes`, and one
    # written against another package's internals fails silently the first
    # time they move.

    @property
    def read_mode(self) -> str:
        return self._read_mode

    @property
    def write_suite(self) -> int:
        return self._write_suite

    @property
    def allowed_suites(self) -> frozenset[int]:
        return self._allowed

    @property
    def provisional_armed(self) -> bool:
        """Whether spec §4.8 provisional writing was armed for this client."""
        return self._provisional_armed

    @property
    def indexes(self) -> Mapping[str, ValidatedIndex]:
        """The validated index registry, keyed by `index_registry_key`.

        Validated, not as-declared: `argon2` carries the §7.3 minima filled
        in, `index_id` its "exact" default, `on_unindexable` its `refuse`
        default. Comparing as-declared inputs would let two declarations that
        agree textually and differ operationally register as a match, which is
        the failure #62 was: one core read the Argon2 cost from a module
        constant, the other took it per column, and they agreed on every
        shipped vector.

        A `MappingProxyType`, not the dict: docs/09 §2 makes the client
        immutable after construction, and an accessor handing out the live
        registry would make that untrue for anyone who asked for it.
        """
        return MappingProxyType(self._indexes)

    # -- gates ------------------------------------------------------------
    def _write_boundary(self, plaintext: bytes, ctx: FieldContext) -> Suite:
        """Every refusal spec §9 places "at the API boundary, before key
        acquisition", in one order: MODE_VIOLATION, then SUITE_PROVISIONAL,
        then LENGTH_EXCEEDED, then the operand's context. Refusals that follow
        from configuration come before any look at the operand; the spec does
        not rank the three (docs/18 D-04), so the report declares this order
        (`pinned_decisions.api-boundary-order`)."""
        if self._read_mode == "readonly":
            raise ModeViolation(
                f"operation not permitted: mode is {self._read_mode!r} and "
                "this operation produces ciphertext")
        if is_provisional(self._write_suite) and not self._provisional_armed:
            raise SuiteProvisional(
                f"write suite {self._write_suite:#06x} is provisional "
                "(spec §4.8) and its constructions have not been "
                f"independently reviewed; set {PROVISIONAL_ENV}=1 or pass "
                "arm_provisional_suites=True to proceed anyway")
        if len(plaintext) > MAX_PLAINTEXT:
            raise LengthExceeded(f"plaintext exceeds the §3.5 bound "
                                 f"({len(plaintext)} > {MAX_PLAINTEXT})")
        if ctx.purpose != "encrypt":
            raise InvalidArgument(
                f"encrypt requires purpose 'encrypt', got {ctx.purpose!r}; "
                "an index context never reaches the DEK (spec §5.3, §8)")
        return SUITES[self._write_suite]

    # -- operations -------------------------------------------------------
    def encrypt(self, plaintext: bytes, ctx: FieldContext) -> bytes:
        suite = self._write_boundary(plaintext, ctx)
        # Fresh on EVERY encryption, including UPDATEs (spec §3.1, §4.4).
        # Never derived from row identity, never a counter, never persisted.
        # These two draws are the only thing `fieldseal.testing` replaces.
        msg_seed = secrets.token_bytes(32)
        nonce = secrets.token_bytes(suite.nonce_len)
        return self._encrypt_with(suite, plaintext, ctx, msg_seed, nonce)

    def _encrypt_with(self, suite: Suite, plaintext: bytes, ctx: FieldContext,
                      msg_seed: bytes, nonce: bytes) -> bytes:
        """docs/09 §3.1 steps 3-13: everything after the boundary and the
        entropy draws. Private; the production surface exposes no way to
        reach it with caller-chosen materials."""
        bound = ctx.with_suite(suite.suite_id)
        tenant_dek, key_id = self._provider.encryption_key(bound)
        rk = record_key(tenant_dek, key_id, msg_seed, bound, suite.key_len)
        a = aad(FMT_VER, key_id, msg_seed, bound)
        ct, tag = _backend(suite.suite_id).seal(rk, nonce, plaintext, a)
        return (serialize_header(suite.suite_id, key_id, msg_seed)
                + nonce + ct + tag + commitment(rk))

    def decrypt(self, blob: bytes, ctx: FieldContext) -> bytes:
        # 1. Every read mode may decrypt (spec §10.3).
        # 2. Recognition (spec §3.4), before policy: an unregistered suite or
        #    an implausible length is "not one of ours", never SUITE_NOT_ALLOWED.
        #    A reserved future fmt_ver raises UNKNOWN_FORMAT_VERSION here, in
        #    every mode (envelope.recognize).
        header = recognize(blob)
        if header is None:
            if self._read_mode == "strict":
                raise NotCiphertext("input is not a recognizable envelope")
            # permissive / readonly: returned as-is (spec §10.3, G6).
            self.plaintext_reads += 1
            return blob if isinstance(blob, bytes) else bytes(blob)
        suite = SUITES[header.suite_id]
        # 2b. Spec §3.5, decrypt side: a function of the byte count alone,
        #    refused before any allocation and -- pinned here, the spec leaves
        #    it free -- before the allow-list is consulted.
        if implied_plaintext_len(blob, suite) > MAX_PLAINTEXT:
            raise LengthExceeded(
                "envelope implies a plaintext over the §3.5 bound")
        # 3. Authorization, after recognition (spec §3.4 decoupling).
        if header.suite_id not in self._allowed:
            raise SuiteNotAllowed(
                f"suite {header.suite_id:#06x} not on the decrypt allow-list")
        # 4. The suite comes from the PARSED HEADER, not from the write suite:
        #    a client whose write suite differs must still read older
        #    envelopes during mixed-suite reads and rotation.
        bound = ctx.with_suite(header.suite_id)
        # 5. All currently-valid versions, preference-ordered (spec §8).
        candidates = list(self._provider.decryption_keys(header))
        if not candidates:
            raise KeyUnavailable(
                f"key_id {header.key_id.hex()} not resolvable")
        nonce, ct, tag, commit = split(blob, suite)
        backend = _backend(suite.suite_id)
        # 6. Per candidate: derive, verify the commitment constant-time BEFORE
        #    the AEAD open (spec §4.6), open only a committed key. An open
        #    that fails after its commitment verified has a proven key and
        #    context, so what remains is ciphertext or tag damage: TAG_INVALID.
        for tenant_dek in candidates:
            rk = record_key(tenant_dek, header.key_id, header.msg_seed, bound,
                            suite.key_len)
            if constant_time.bytes_eq(commit, commitment(rk)):
                a = aad(header.fmt_ver, header.key_id, header.msg_seed, bound)
                return backend.open(rk, nonce, ct, tag, a)
        # 7. No candidate committed. Under dual-layer binding (spec §6.3) a
        #    wrong context derives a wrong record key, so a context mismatch
        #    surfaces here and is indistinguishable from key confusion -- the
        #    gap G5 is about. AAD_MISMATCH is therefore never raised on this
        #    path (`pinned_decisions.aad-mismatch`); the message says so
        #    rather than claiming to know which it was.
        raise CommitmentInvalid(
            "key commitment check failed for every candidate key: wrong key, "
            "wrong context, or a partitioning-oracle attempt")

    def _declaration(self, ctx: FieldContext) -> ValidatedIndex:
        """Resolve the index this context names (docs/09 §7, spec §7.8).

        The index-id travels in `ctx.purpose`, not in a keyword argument:
        `purpose` is already the field that distinguishes one index on a
        column from another (spec §6.1), and it is what the key derivation
        reads. Taking it from anywhere else would let a caller derive under
        one index-id while the declaration checked belonged to another.
        """
        index_id = ctx.index_id
        if index_id is None:
            raise InvalidArgument(
                "blind_index requires ctx.purpose = 'index:<index-id>' "
                "(spec §7.2); call ctx.for_index(...) first")
        try:
            return self._indexes[
                index_registry_key(ctx.table_uuid, ctx.column_uuid, index_id)]
        except KeyError:
            raise ConfigurationError(
                f"no blind index {index_id!r} is declared for this "
                "table/column; indexes are declared at construction "
                "(spec §7.8)") from None

    def blind_index(self, value: str | bytes, ctx: FieldContext) -> bytes:
        """Derive the blind index for `value` (spec §7.2, §7.3).

        Every parameter of the index -- IDF, normalizer, truncation length,
        `on_unindexable` -- comes from the declaration made at construction,
        never from this call. That is what lets the §7.4 band and the §7.6
        cardinality gate be enforced at all: they are questions about a
        column, and they are answered once, before any value is indexed.

        Takes `str` as well as `bytes`, and `str` is the preferred form:
        docs/09 §7.1 requires an index API to accept text, because the
        encoding step can destroy the difference between two values before
        the core is ever entered. Every other operation on this client takes
        bytes; normalization is a text operation and encryption is not.
        """
        # An index computed for a WHERE clause is not a write, so readonly
        # permits it (spec §10.3, per G6) and the provisional gate does not
        # apply either -- no ciphertext is produced.
        decl = self._declaration(ctx)
        try:
            normalized = NORMALIZERS[decl.normalize](value)
        except InvalidArgument:
            # docs/09 §7.2: a value the normalizer refuses either fails here
            # or lands in the column's reserved bucket. Storing no index at
            # all is not on the menu -- that is the silent missing row spec
            # §10.2 forbids, and it is why `bucket` derives a marker rather
            # than returning nothing.
            if decl.on_unindexable != "bucket":
                raise
            normalized = UNINDEXABLE_PREIMAGE
        return self._derive_index(decl, normalized, ctx)

    def unindexable_marker(self, ctx: FieldContext) -> bytes:
        """This column's reserved index value for unindexable rows
        (docs/09 §7.2), so an adapter can name the bucket without holding a
        value that lands in it -- for a migration sweep, or to count how many
        rows are in it before relaxing a column.

        Derived under the column's own index key rather than being a fixed
        constant: a constant would announce which rows hold a character the
        pin does not define to anyone who can read the column without any
        key at all.
        """
        # The reserved preimage is not valid UTF-8 by construction, so it
        # bypasses normalization rather than being passed through it.
        return self._derive_index(self._declaration(ctx),
                                  UNINDEXABLE_PREIMAGE, ctx)

    def _derive_index(self, decl: ValidatedIndex, normalized: bytes,
                      ctx: FieldContext) -> bytes:
        # Spec §7.2: the index context is the field's with purpose retargeted
        # and row_id dropped; spec §8: a provider handed that purpose returns
        # the tenant INDEX key, never the DEK.
        bound = ctx.for_index(decl.index_id).with_suite(self._write_suite)
        tenant_index_key, _ = self._provider.encryption_key(bound)
        ik = index_key(tenant_index_key, bound, decl.index_id)
        # Every IDF parameter comes from the declaration, the Argon2id cost
        # included (spec §7.3 states t and m as minima a deployment may raise).
        raw = idf(decl.idf, ik, normalized, decl.argon2)
        return truncate(raw, decl.truncate_bits)

    def rotate(self, blob: bytes, ctx: FieldContext) -> bytes:
        """Re-encrypt under a fresh seed and nonce. Produces ciphertext, so it
        is a write for both the mode gate and the provisional gate, checked
        before anything inspects the operand (spec §10.3, §4.8).

        `rotate` is ciphertext-to-ciphertext in every mode (spec §11.1).
        The §10.3 pass-through is a *read* behavior -- its column is
        "non-envelope input on read" -- and the decrypt inside `rotate` is
        not a read whose result reaches the application. Composing the two
        literally would make `rotate` encrypt unmigrated plaintext in
        `permissive` and raise on the same bytes in `strict`, so the
        operation's domain would depend on a mode setting that has nothing to
        do with rotation; two cores could then disagree with no vector able
        to say which was right.

        A reserved future version byte still raises `UNKNOWN_FORMAT_VERSION`
        rather than `NOT_CIPHERTEXT`: recognition (spec §3.4) runs first and
        distinguishes the two, and a v2 envelope is emphatically not
        unmigrated plaintext.
        """
        self._write_boundary(b"", ctx)
        if recognize(blob) is None:
            raise NotCiphertext(
                "rotate requires an envelope; this input is not one "
                "(use encrypt() to migrate unencrypted values)")
        return self.encrypt(self.decrypt(blob, ctx), ctx)

    def is_ciphertext(self, blob: object) -> bool:
        return is_ciphertext(blob)

    async def warm(self, contexts: Iterable[FieldContext]) -> None:
        """Spec §11.2 prefetch -- the only coroutine on the client (docs/10
        §4). Delegates to the provider when it offers `warm`; a provider
        without one makes this a no-op, so warming is never required for
        correctness. All KMS/network I/O lives here; the value path stays
        sync-only (spec §11.1)."""
        w = getattr(self._provider, "warm", None)
        if w is not None:
            await w(contexts)


__all__ = ["Fieldseal", "EnvelopeHeader", "PROVISIONAL_ENV", "READ_MODES"]
