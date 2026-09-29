package dev.fieldseal.hibernate;

/** The base of this adapter's own exceptions. The core's §9 errors pass through unwrapped. */
public abstract sealed class FieldsealHibernateException extends RuntimeException
        permits FieldsealNotSupportedException, FieldsealConfigurationException,
                FieldsealUnindexableException {
    private static final long serialVersionUID = 1L;

    FieldsealHibernateException(String message) {
        super(message);
    }

    FieldsealHibernateException(String message, Throwable cause) {
        super(message, cause);
    }
}
