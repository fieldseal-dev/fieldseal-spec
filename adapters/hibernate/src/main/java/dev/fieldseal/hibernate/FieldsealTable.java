package dev.fieldseal.hibernate;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The entity's table surrogate (spec §6.1): a UUID literal in the source, never derived from the
 * entity or table name, so that a rename changes nothing (docs/29 §2). Required on every entity
 * with an {@link Encrypted} attribute (startup check FS-H001).
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface FieldsealTable {
    /** The table UUID, in the canonical 8-4-4-4-12 form. */
    String value();
}
