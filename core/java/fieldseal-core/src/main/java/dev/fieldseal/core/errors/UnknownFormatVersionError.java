package dev.fieldseal.core.errors;

/**
 * spec §9: {@code fmt_ver} is the reserved {@code 0x02} at a plausible length (spec §3.1, §3.4).
 * Raised in every read mode (spec §9, §10.3).
 */
public final class UnknownFormatVersionError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    public UnknownFormatVersionError(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "UNKNOWN_FORMAT_VERSION";
    }
}
