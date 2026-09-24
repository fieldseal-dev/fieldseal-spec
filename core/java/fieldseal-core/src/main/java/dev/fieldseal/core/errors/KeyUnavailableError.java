package dev.fieldseal.core.errors;

/**
 * spec §9: the {@code key_id} is not resolvable. Also what a key provider's own exception
 * becomes (docs/27 §4).
 */
public final class KeyUnavailableError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    public KeyUnavailableError(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "KEY_UNAVAILABLE";
    }
}
