package dev.fieldseal.core.errors;

/**
 * The base of the spec §9 error taxonomy (docs/09 §9; docs/27 §4): one final subclass per code,
 * each returning its exact code string from {@link #code()}.
 *
 * <p>Sealed, so the taxonomy is closed: the ten spec §9 codes, plus {@code INVALID_ARGUMENT}
 * (docs/09 §7.1) and the implementation-local {@code CONFIGURATION_ERROR} (docs/09 §9). A caller
 * can switch over it exhaustively, and no one can add a code by subclassing.
 *
 * <p>Unchecked because the value path cannot declare checked exceptions: an ORM converter such
 * as Hibernate's {@code AttributeConverter} (the WS-N adapter this core exists for) has no
 * {@code throws} clause to carry one.
 *
 * <p>No message may include plaintext, key material or a derived key (spec §9).
 */
public abstract sealed class FieldsealError extends RuntimeException
        permits UnknownFormatVersionError, SuiteNotAllowedError, KeyUnavailableError,
                AadMismatchError, TagInvalidError, CommitmentInvalidError, NotCiphertextError,
                ModeViolationError, LengthExceededError, SuiteProvisionalError,
                InvalidArgumentError, ConfigurationError {

    private static final long serialVersionUID = 1L;

    protected FieldsealError(String message) {
        super(message);
    }

    /** For a code that wraps another failure, such as a key provider's own exception. */
    protected FieldsealError(String message, Throwable cause) {
        super(message, cause);
    }

    /** The exact code string, such as {@code "TAG_INVALID"}. */
    public abstract String code();
}
