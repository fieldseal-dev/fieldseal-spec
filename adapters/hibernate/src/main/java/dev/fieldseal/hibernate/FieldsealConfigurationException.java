package dev.fieldseal.hibernate;

/**
 * A mapping or setting this adapter refuses when the session factory is built (docs/29 §5), or a
 * runtime context that cannot be assembled, such as a tenant-bound column with no tenant on the
 * session. A startup refusal's message starts with the check's id.
 */
public final class FieldsealConfigurationException extends FieldsealHibernateException {
    private static final long serialVersionUID = 1L;

    FieldsealConfigurationException(String message) {
        super(message);
    }

    FieldsealConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
