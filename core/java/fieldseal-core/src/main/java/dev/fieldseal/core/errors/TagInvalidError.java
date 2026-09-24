package dev.fieldseal.core.errors;

/**
 * spec §9: authentication failed after the commitment verified. {@code AEADBadTagException}
 * maps here, and only after the commitment (docs/09 §3.2 step 6; docs/27 §4).
 */
public final class TagInvalidError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    public TagInvalidError(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "TAG_INVALID";
    }
}
