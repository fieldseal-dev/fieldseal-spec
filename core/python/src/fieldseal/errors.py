"""The error taxonomy of spec §9.

Spec §9 requires these to stay distinguishable: an implementation that collapses
them into one "decryption failed" is non-conformant, because an operator cannot
tell a migration bug from tampering without them. `.code` is the string the
vector suite and the conformance report use (docs/09 §9).

Two codes here are implementation-local and outside §9, as docs/09 §9 permits:
`CONFIGURATION_ERROR` for construction-time failures, and `INVALID_ARGUMENT`
for an operand refused at the API boundary before any cryptographic work
(an index purpose handed to `encrypt`, invalid UTF-8 handed to a text
normalizer). Neither ever reaches the vectors.
"""

from __future__ import annotations


class FieldsealError(Exception):
    code: str = "FIELDSEAL_ERROR"

    def __str__(self) -> str:  # pragma: no cover - trivial
        base = super().__str__()
        return f"[{self.code}] {base}" if base else f"[{self.code}]"


class FieldsealWarning(UserWarning):
    """Spec §10.3: `permissive` and `readonly` MUST warn while active."""


class UnknownFormatVersion(FieldsealError):
    code = "UNKNOWN_FORMAT_VERSION"


class SuiteNotAllowed(FieldsealError):
    code = "SUITE_NOT_ALLOWED"


class KeyUnavailable(FieldsealError):
    code = "KEY_UNAVAILABLE"


class AadMismatch(FieldsealError):
    code = "AAD_MISMATCH"


class TagInvalid(FieldsealError):
    code = "TAG_INVALID"


class CommitmentInvalid(FieldsealError):
    code = "COMMITMENT_INVALID"


class NotCiphertext(FieldsealError):
    code = "NOT_CIPHERTEXT"


class ModeViolation(FieldsealError):
    code = "MODE_VIOLATION"


class LengthExceeded(FieldsealError):
    code = "LENGTH_EXCEEDED"


class SuiteProvisional(FieldsealError):
    """Spec §4.8. Raised at the API boundary before key acquisition."""

    code = "SUITE_PROVISIONAL"


class ConfigurationError(FieldsealError):
    code = "CONFIGURATION_ERROR"


class InvalidArgument(FieldsealError):
    """Implementation-local (docs/09 §9): an operand refused at the API
    boundary. Not a §9 code; never the outcome of a vector."""

    code = "INVALID_ARGUMENT"
