package dev.fieldseal.hibernate;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.hibernate.annotations.Type;

/**
 * An encrypted attribute (docs/29 §2). A Hibernate {@link Type} meta-annotation: the attribute is
 * mapped by {@link EncryptedType}, and its Java type fixes its spec §3.6 logical type.
 *
 * <p>The value is encrypted by the adapter's event listener on write, never by the type, and a
 * plain value that reaches the column's JDBC binding is refused (docs/29 §2.1).
 */
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Type(EncryptedType.class)
public @interface Encrypted {
    /** The column UUID (spec §6.1), canonical 8-4-4-4-12 form, unique within the table. */
    String column();

    /**
     * Bind the session's tenant identifier into the context (L3, docs/29 §4). A tenant-bound
     * column with no tenant on the session fails closed on read and on write.
     */
    boolean tenantBound() default false;
}
