"""The Fieldseal client (spec §11.1, docs/10 §4).

Every operation here is strictly synchronous and performs no I/O. That is not a
style preference: Django field types, SQLAlchemy type processors, TypeORM
transformers and the rest cannot await in the value path, and a core that
required them to would be unusable in the place it is meant to be used.

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
from collections.abc import Iterable

from cryptography.hazmat.primitives import constant_time

from .aead.gcm import GcmBackend
from .blindindex import IDFS, NORMALIZERS, truncate
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

    def blind_index(self, value: str | bytes, ctx: FieldContext, *,
                    index_id: str, b_bits: int, idf: str = "argon2id",
                    normalizer: str = "nfc-casefold-v1") -> bytes:
        # An index computed for a WHERE clause is not a write, so readonly
        # permits it (spec §10.3, per G6) and the provisional gate does not
        # apply either -- no ciphertext is produced.
        # Declaration checks fail closed (docs/09 §3.3 step 2): an unknown
        # IDF or normalizer is a configuration error, never a default.
        try:
            derive = IDFS[idf]
        except KeyError:
            raise ConfigurationError(f"unknown idf {idf!r}") from None
        try:
            normalize = NORMALIZERS[normalizer]
        except KeyError:
            raise ConfigurationError(
                f"unknown normalizer {normalizer!r}") from None
        if not isinstance(b_bits, int) or b_bits <= 0:
            raise ConfigurationError("b_bits must be a positive integer")
        # Spec §7.2: the index context is the field's with purpose retargeted
        # and row_id dropped; spec §8: a provider handed that purpose returns
        # the tenant INDEX key, never the DEK.
        bound = ctx.for_index(index_id).with_suite(self._write_suite)
        tenant_index_key, _ = self._provider.encryption_key(bound)
        ik = index_key(tenant_index_key, bound, index_id)
        return truncate(derive(ik, normalize(value)), b_bits)

    def rotate(self, blob: bytes, ctx: FieldContext) -> bytes:
        """Re-encrypt under a fresh seed and nonce. Produces ciphertext, so it
        is a write for both the mode gate and the provisional gate, checked
        before the decrypt runs (docs/09 §3.5).

        Literal composition, decrypt then encrypt: in `permissive` mode the
        decrypt of non-envelope input passes through, so rotate *encrypts*
        unmigrated plaintext. Whether that is intended is docs/18 D-13; the
        report declares it (`pinned_decisions.rotate-in-permissive`)."""
        self._write_boundary(b"", ctx)
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
