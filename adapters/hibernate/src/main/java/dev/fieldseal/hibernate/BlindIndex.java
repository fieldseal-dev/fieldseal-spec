package dev.fieldseal.hibernate;

import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.core.IndexDeclaration.OnUnindexable;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A blind-index sibling of an {@link Encrypted} attribute (docs/29 §2, spec §7). The annotated
 * attribute is a {@code byte[]} holding spec §7.11's raw index bytes, which the adapter's
 * listener writes from the same rendered bytes it encrypts. It is queried only through {@link
 * FieldsealQueries}, which re-verifies what the index returns (spec §7.5).
 *
 * <p>The members are docs/09 §7's {@code IndexDeclaration}. The core validates them when the
 * adapter builds the client (startup check FS-H003).
 */
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface BlindIndex {
    /** The name of the encrypted attribute this indexes, on the same entity. */
    String source();

    /** The spec §6.1 {@code index-id}. */
    String id() default "exact";

    /** Spec §7.3: {@code ARGON2ID} for an enumerable domain, {@code HMAC_SHA512} for a high-entropy one. */
    Idf idf();

    /** The Argon2id time cost {@code t}; 0 means spec §7.3's minimum. */
    int argon2TimeCost() default 0;

    /** The Argon2id memory cost {@code m}, in KiB; 0 means spec §7.3's minimum. */
    int argon2MemoryKib() default 0;

    /** The normalizer, from docs/09 §7's closed set. */
    Normalizer normalize();

    /** {@code b}, within spec §7.4's band for {@link #projectedPopulation}. */
    int truncateBits();

    /** {@code P}, the projected number of distinct values (spec §7.4). */
    long projectedPopulation();

    /** Spec §7.6: the values are heavily skewed; gated as a small {@code P} is. */
    boolean skewed() default false;

    /** Required below spec §7.6's gate, or with {@link #skewed}. */
    ReviewedOverride cardinalityOverride() default @ReviewedOverride;

    /** docs/09 §7.2 and docs/29 §10. */
    OnUnindexable onUnindexable() default OnUnindexable.REFUSE;

    /** Required for {@link OnUnindexable#BUCKET}. */
    ReviewedOverride unindexableOverride() default @ReviewedOverride;
}
