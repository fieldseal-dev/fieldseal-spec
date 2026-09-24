package dev.fieldseal.core.errors;

/**
 * spec §9: the input is not a recognizable envelope (spec §3.4). {@code decrypt} raises it in
 * {@code strict} only; {@code rotate} raises it in every mode (spec §10.3, §11.1).
 */
public final class NotCiphertextError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    public NotCiphertextError(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "NOT_CIPHERTEXT";
    }
}
