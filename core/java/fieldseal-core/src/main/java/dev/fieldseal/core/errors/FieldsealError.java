package dev.fieldseal.core.errors;

/**
 * The base of the spec §9 error taxonomy (docs/09 §9; docs/27 §4). One subclass per code
 * arrives at S3, each returning its exact §9 string from {@link #code()}.
 *
 * <p>Unchecked because the value path cannot declare checked exceptions: an ORM converter such
 * as Hibernate's {@code AttributeConverter} (the WS-N adapter this core exists for) has no
 * {@code throws} clause to carry one.
 */
public abstract class FieldsealError extends RuntimeException {

    private static final long serialVersionUID = 1L;

    protected FieldsealError(String message) {
        super(message);
    }

    /** The exact spec §9 code string, such as {@code "TAG_INVALID"}. */
    public abstract String code();
}
