package dev.fieldseal.core.errors;

/**
 * spec §9: no candidate key's commitment matched (spec §4.6).
 */
public final class CommitmentInvalidError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    public CommitmentInvalidError(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "COMMITMENT_INVALID";
    }
}
