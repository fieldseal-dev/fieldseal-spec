package dev.fieldseal.hibernate;

/**
 * A path this adapter does not serve, refused rather than degraded (spec §10.2): a query shape
 * over an encrypted or index attribute, a plain value at an encrypted column's JDBC binding, or a
 * value spec §3.6's codec does not admit. Nothing about any envelope is wrong.
 */
public final class FieldsealNotSupportedException extends FieldsealHibernateException {
    private static final long serialVersionUID = 1L;

    FieldsealNotSupportedException(String message) {
        super(message);
    }
}
