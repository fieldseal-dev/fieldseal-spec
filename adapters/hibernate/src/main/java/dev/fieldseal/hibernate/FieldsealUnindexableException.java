package dev.fieldseal.hibernate;

/**
 * A value the index's normalizer refuses, on a column declared {@code onUnindexable = REFUSE}
 * (docs/09 §7.2, docs/29 §10). Carries the attribute, the offending code point and its position
 * in code points, so that an application can build docs/12 §10.2's message without parsing this
 * one.
 */
public final class FieldsealUnindexableException extends FieldsealHibernateException {
    private static final long serialVersionUID = 1L;

    private final String attribute;
    private final int codePoint;
    private final int offset;

    FieldsealUnindexableException(String attribute, int codePoint, int offset, String message,
            Throwable cause) {
        super(message, cause);
        this.attribute = attribute;
        this.codePoint = codePoint;
        this.offset = offset;
    }

    /** {@code Entity.attribute}. */
    public String attribute() {
        return attribute;
    }

    /** The code point the index refused, or -1 if none was located (malformed input). */
    public int codePoint() {
        return codePoint;
    }

    /** Its offset in code points, from 0, or -1 if none was located. */
    public int offset() {
        return offset;
    }
}
