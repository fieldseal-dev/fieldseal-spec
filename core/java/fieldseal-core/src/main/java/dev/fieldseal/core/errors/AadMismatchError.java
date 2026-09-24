package dev.fieldseal.core.errors;

/**
 * spec §9: the context does not match. Under dual binding (spec §6.3) a context mismatch fails
 * the commitment first, so on suite {@code 0xFF01} this code is not reachable from decrypt
 * (spec §4.6; G5). It exists because §9 requires the taxonomy to distinguish it.
 */
public final class AadMismatchError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    public AadMismatchError(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "AAD_MISMATCH";
    }
}
