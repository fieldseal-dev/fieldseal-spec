package dev.fieldseal.core.errors;

/**
 * spec §9: the operation is not permitted in the configured read mode, which today means
 * {@code encrypt} or {@code rotate} on a {@code readonly} client (spec §10.3). Raised at the API
 * boundary. Spec §9 requires the message to name both the rejected operation and the active mode,
 * so the constructor takes both and builds it.
 */
public final class ModeViolationError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    /** @param operation such as {@code "encrypt"}; @param mode such as {@code "readonly"} */
    public ModeViolationError(String operation, String mode) {
        super(operation + " is not permitted in " + mode + " mode: " + mode
                + " refuses the operations that produce ciphertext for storage (spec §10.3)");
    }

    @Override
    public String code() {
        return "MODE_VIOLATION";
    }
}
