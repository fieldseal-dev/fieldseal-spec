"""The Fieldseal client (spec §11.1, docs/10 §4).

Every operation here is strictly synchronous and performs no I/O. That is not a
style preference: Django field types, SQLAlchemy type processors, TypeORM
transformers and the rest cannot await in the value path, and a core that
required them to would be unusable in the place it is meant to be used.
"""

from __future__ import annotations

import os
import secrets

from cryptography.hazmat.primitives import constant_time

from .aead.gcm import GcmBackend
from .blindindex import (idf_argon2id, idf_hmac_sha512, normalize_nfc_casefold,
                         truncate)
from .context import FieldContext, aad
from .envelope import (FMT_VER, MAX_PLAINTEXT, is_ciphertext, parse_header,
                       serialize_header, split)
from .errors import (CommitmentInvalid, ConfigurationError, KeyUnavailable,
                     LengthExceeded, ModeViolation, SuiteNotAllowed,
                     SuiteProvisional)
from .kdf import commitment, index_key, record_key
from .registry import SUITES, is_provisional

PROVISIONAL_ENV = "FIELDSEAL_ALLOW_PROVISIONAL_SUITE"

_BACKENDS = {0xFF01: GcmBackend()}


class Fieldseal:
    def __init__(self, *, key_provider, allowed_suites: set[int],
                 write_suite: int, read_mode: str = "strict",
                 acknowledge_provisional_suite: bool = False) -> None:
        if write_suite not in allowed_suites:
            raise ConfigurationError("write_suite must be in allowed_suites")
        for sid in set(allowed_suites) | {write_suite}:
            if sid not in SUITES:
                raise ConfigurationError(f"unregistered suite {sid:#06x}")
        if read_mode not in {"strict", "permissive", "readonly"}:
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
            acknowledge_provisional_suite
            or os.environ.get(PROVISIONAL_ENV) == "1")

    # -- gates ------------------------------------------------------------
    def _check_can_write(self) -> None:
        """Both gates are raised at the API boundary, before key acquisition
        and before any cryptographic processing (spec §9, §4.8)."""
        if self._read_mode == "readonly":
            raise ModeViolation(
                f"operation not permitted: mode is {self._read_mode!r} and "
                "this operation produces ciphertext")
        if is_provisional(self._write_suite) and not self._provisional_armed:
            raise SuiteProvisional(
                f"write suite {self._write_suite:#06x} is provisional "
                "(spec §4.8) and its constructions have not been "
                f"independently reviewed; set {PROVISIONAL_ENV}=1 or pass "
                "acknowledge_provisional_suite=True to proceed anyway")

    def _suite_for_read(self, suite_id: int):
        if suite_id not in self._allowed:
            raise SuiteNotAllowed(
                f"suite {suite_id:#06x} not on the decrypt allow-list")
        suite = SUITES.get(suite_id)
        if suite is None:
            raise SuiteNotAllowed(f"suite {suite_id:#06x} not registered")
        return suite

    # -- operations -------------------------------------------------------
    def encrypt(self, plaintext: bytes, ctx: FieldContext) -> bytes:
        self._check_can_write()
        if len(plaintext) > MAX_PLAINTEXT:
            raise LengthExceeded(f"plaintext exceeds the §3.5 bound "
                                 f"({len(plaintext)} > {MAX_PLAINTEXT})")
        suite = SUITES[self._write_suite]
        bound = ctx.with_suite(self._write_suite)

        # Fresh on EVERY encryption, including UPDATEs (spec §3.1, §4.4).
        # Never derived from row identity, never a counter, never persisted.
        msg_seed = secrets.token_bytes(32)
        nonce = secrets.token_bytes(suite.nonce_len)
        key_id, tenant_dek = self._provider.dek_for(bound)
        return self._assemble(suite, bound, tenant_dek, key_id, msg_seed,
                              nonce, plaintext)

    def _assemble(self, suite, bound, tenant_dek, key_id, msg_seed, nonce,
                  plaintext) -> bytes:
        rk = record_key(tenant_dek, key_id, msg_seed, bound, suite.key_len)
        a = aad(FMT_VER, key_id, msg_seed, bound)
        ct, tag = _BACKENDS[suite.suite_id].seal(rk, nonce, plaintext, a)
        return (serialize_header(suite.suite_id, key_id, msg_seed)
                + nonce + ct + tag + commitment(rk))

    def decrypt(self, blob: bytes, ctx: FieldContext) -> bytes:
        header = parse_header(blob)
        suite = self._suite_for_read(header.suite_id)
        nonce, ct, tag, commit = split(blob, suite)

        # The suite comes from the PARSED HEADER, not from the write suite: a
        # client whose write suite differs must still read older envelopes
        # during mixed-suite reads and rotation (docs/09 §3.2 step 4).
        bound = ctx.with_suite(header.suite_id)
        try:
            tenant_dek = self._provider.dek_for_key_id(header.key_id, bound)
        except KeyError as exc:
            raise KeyUnavailable(
                f"key_id {header.key_id.hex()} not resolvable") from exc

        rk = record_key(tenant_dek, header.key_id, header.msg_seed, bound,
                        suite.key_len)
        # Commitment is verified constant-time BEFORE the AEAD open (spec
        # §4.6). Under dual-layer binding a wrong context derives a wrong
        # record key, so a context mismatch usually surfaces here rather than
        # as a tag failure -- which is exactly the ambiguity gap G5 is about,
        # and why the message below does not claim to know which it was.
        if not constant_time.bytes_eq(commit, commitment(rk)):
            raise CommitmentInvalid(
                "key commitment check failed: wrong key, wrong context, or a "
                "partitioning-oracle attempt")
        a = aad(header.fmt_ver, header.key_id, header.msg_seed, bound)
        return _BACKENDS[suite.suite_id].open(rk, nonce, ct, tag, a)

    def blind_index(self, value: str | bytes, ctx: FieldContext, *,
                    index_id: str, b_bits: int, idf: str = "argon2id",
                    normalizer: str = "nfc-casefold") -> bytes:
        # An index computed for a WHERE clause is not a write, so readonly
        # permits it (spec §10.3, per G6) and the provisional gate does not
        # apply either -- no ciphertext is produced.
        bound = ctx.with_suite(self._write_suite)
        if normalizer != "nfc-casefold":
            raise ConfigurationError(f"unknown normalizer {normalizer!r}")
        normalized = (normalize_nfc_casefold(value)
                      if isinstance(value, str) else value)
        tenant_index_key = self._provider.index_key_material(bound)
        ik = index_key(tenant_index_key, bound, index_id)
        raw = (idf_hmac_sha512(ik, normalized) if idf == "hmac-sha512"
               else idf_argon2id(ik, normalized))
        return truncate(raw, b_bits)

    def rotate(self, blob: bytes, ctx: FieldContext) -> bytes:
        """Re-encrypt under a fresh seed and nonce. Produces ciphertext, so it
        is a write for both the mode gate and the provisional gate."""
        self._check_can_write()
        return self.encrypt(self.decrypt(blob, ctx), ctx)

    def is_ciphertext(self, blob: object) -> bool:
        return is_ciphertext(blob)
