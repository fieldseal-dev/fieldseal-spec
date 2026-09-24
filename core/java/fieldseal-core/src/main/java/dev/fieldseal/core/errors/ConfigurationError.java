package dev.fieldseal.core.errors;

/**
 * A client configuration refused at construction (docs/09 §9). Implementation-local: spec §9
 * defines no such code, because construction never reaches the crypto path or the vectors.
 */
public final class ConfigurationError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    public ConfigurationError(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "CONFIGURATION_ERROR";
    }
}
