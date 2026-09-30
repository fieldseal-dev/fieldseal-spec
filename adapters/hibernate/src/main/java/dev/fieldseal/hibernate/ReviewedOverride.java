package dev.fieldseal.hibernate;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A reviewed, recorded relaxation of a default-deny rule on one column: spec §7.6's cardinality
 * gate, or docs/09 §7.2's {@code refuse}. All three members empty means no override. The core
 * validates the rest, and logs the override when the client is built.
 */
@Target({})
@Retention(RetentionPolicy.RUNTIME)
public @interface ReviewedOverride {
    /** Why the rule does not fit this column. */
    String reason() default "";

    /** Who reviewed it. */
    String approvedBy() default "";

    /** When, as an ISO-8601 date ({@code 2026-09-29}). */
    String date() default "";
}
