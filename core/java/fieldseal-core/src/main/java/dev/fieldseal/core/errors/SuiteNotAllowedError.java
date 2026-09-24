package dev.fieldseal.core.errors;

/**
 * spec §9: the envelope's {@code suite_id} is registered but not on the decrypt allow-list
 * (spec §4.3). Raised after recognition, never instead of it (spec §3.4).
 */
public final class SuiteNotAllowedError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    public SuiteNotAllowedError(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "SUITE_NOT_ALLOWED";
    }
}
