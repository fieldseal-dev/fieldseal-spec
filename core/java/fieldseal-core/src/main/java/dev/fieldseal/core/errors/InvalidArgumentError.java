package dev.fieldseal.core.errors;

/**
 * An operand refused at the API boundary (docs/09 §7.1; docs/27 §4): for example malformed
 * UTF-8 handed to {@code blindIndex(byte[])}, or a null operand. Not a spec §9 code; the
 * {@code blind-index/} {@code refuse} vectors pin its string.
 */
public final class InvalidArgumentError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    public InvalidArgumentError(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "INVALID_ARGUMENT";
    }
}
