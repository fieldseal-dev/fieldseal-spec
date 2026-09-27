package dev.fieldseal.core;

import dev.fieldseal.core.IndexDeclaration.Argon2Params;
import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.OnUnindexable;
import dev.fieldseal.core.IndexDeclaration.ReviewedOverride;
import dev.fieldseal.core.errors.ConfigurationError;
import dev.fieldseal.core.internal.blindindex.Idf.Params;
import dev.fieldseal.core.internal.context.Purpose;

/**
 * The checks an index declaration passes before any derivation uses it (docs/09 §2, §7, §12).
 * Every refusal is a {@link ConfigurationError} naming the rule, and the first one found is the
 * one reported.
 */
final class IndexValidation {

    /** spec §7.6: fewer projected distinct values than this needs a reviewed override. */
    static final long CARDINALITY_GATE = 1L << 10;

    /** spec §7.4: {@code P} MUST be at least 16. */
    static final long MIN_POPULATION = 16;

    /** spec §7.2: the IDF output is 64 bytes, so nothing longer can be kept. */
    static final int MAX_BITS = 512;

    static final String DEFAULT_INDEX_ID = "exact";

    private static final int MIN_T = dev.fieldseal.core.internal.blindindex.Idf.ARGON2_MIN_TIME_COST;
    private static final int MIN_M =
            dev.fieldseal.core.internal.blindindex.Idf.ARGON2_MIN_MEMORY_KIB;

    private IndexValidation() {}

    static ValidatedIndex validate(IndexDeclaration d) {
        if (d == null) {
            throw new ConfigurationError("an index declaration is null");
        }
        uuid("tableUuid", d.tableUuid());
        uuid("columnUuid", d.columnUuid());
        String id = d.indexId() == null ? DEFAULT_INDEX_ID : d.indexId();
        String where = "index '" + id + "'";
        if (!Purpose.isValidIndexId(id)) {
            // Not the id itself: it may hold any character, and it failed the grammar.
            throw new ConfigurationError("an index id is outside the spec §6.1 grammar"
                    + " [a-z0-9-]{1,32} (length " + id.length() + ")");
        }
        if (d.idf() == null) {
            throw new ConfigurationError(where + ": idf is required (spec §7.3)");
        }
        if (d.normalize() == null) {
            throw new ConfigurationError(where + ": normalize is required (spec §7.2)");
        }
        Argon2Params cost = argon2(where, d.idf(), d.argon2());
        band(where, d.truncateBits(), d.projectedPopulation());
        // spec §7.6's two halves: too few distinct values, or declared heavily skewed.
        if (d.projectedPopulation() < CARDINALITY_GATE || d.skewed()) {
            if (d.cardinalityOverride() == null) {
                throw new ConfigurationError(where + ": " + (d.skewed()
                        ? "a column declared heavily skewed"
                        : "a projected population of " + d.projectedPopulation()
                                + " distinct values, below 2^10,") + " is behind spec §7.6's"
                        + " default-deny gate; an index on it needs a"
                        + " cardinalityOverride {reason, approvedBy, date}");
            }
            override(where, "cardinalityOverride", d.cardinalityOverride());
        } else if (d.cardinalityOverride() != null) {
            override(where, "cardinalityOverride", d.cardinalityOverride());
        }
        OnUnindexable policy = d.onUnindexable() == null ? OnUnindexable.REFUSE
                : d.onUnindexable();
        if (policy == OnUnindexable.BUCKET) {
            if (!d.normalize().impl().canRefuseWellFormedText()) {
                throw new ConfigurationError(where + ": on_unindexable = bucket under "
                        + d.normalize().id() + " could never take effect: it refuses no"
                        + " well-formed text, and the one value it does refuse, text with a lone"
                        + " surrogate, cannot be stored at all (spec §3.6; docs/09 §7.2)");
            }
            if (d.unindexableOverride() == null) {
                throw new ConfigurationError(where + ": on_unindexable = bucket needs an"
                        + " unindexableOverride {reason, approvedBy, date} (docs/09 §7.2)");
            }
        }
        if (d.unindexableOverride() != null) {
            override(where, "unindexableOverride", d.unindexableOverride());
        }
        return new ValidatedIndex(d.tableUuid(), d.columnUuid(), id, d.idf(), cost,
                d.normalize(), d.truncateBits(), d.projectedPopulation(), d.skewed(),
                d.cardinalityOverride(), policy, d.unindexableOverride());
    }

    /** The internal IDF parameters for a validated index. */
    static Params params(ValidatedIndex v) {
        return v.idf() == Idf.HMAC_SHA512 ? new Params.HmacSha512()
                : new Params.Argon2id(v.argon2().timeCost(), v.argon2().memoryKib());
    }

    /**
     * docs/09 §7, §12: the cost comes from the declaration, defaults to the spec §7.3 minima, is
     * refused below either, and is refused outright on {@code hmac-sha512}.
     */
    private static Argon2Params argon2(String where, Idf idf, Argon2Params given) {
        if (idf == Idf.HMAC_SHA512) {
            if (given != null) {
                throw new ConfigurationError(where + ": hmac-sha512 has no cost parameters, so"
                        + " an argon2 cost on it is refused (docs/09 §7)");
            }
            return null;
        }
        if (given == null) {
            return new Argon2Params(MIN_T, MIN_M);
        }
        if (given.timeCost() < MIN_T || given.memoryKib() < MIN_M) {
            throw new ConfigurationError(where + ": Argon2id t = " + given.timeCost() + ", m = "
                    + given.memoryKib() + " KiB is below spec §7.3's minima (t = 3, m = 32768)");
        }
        String refusal = dev.fieldseal.core.internal.blindindex.Idf.argon2CostRefusal(
                given.timeCost(), given.memoryKib());
        if (refusal != null) {
            throw new ConfigurationError(where + ": " + refusal);
        }
        return given;
    }

    /**
     * spec §7.4: {@code P >= 16} and {@code 2 <= P * 2^-b < sqrt(P)}, which in integers is
     * {@code 2^(b+1) <= P < 2^(2b)}. Exact, with no floating point.
     */
    private static void band(String where, int b, long p) {
        if (p < MIN_POPULATION) {
            throw new ConfigurationError(where + ": projectedPopulation " + p
                    + " is below spec §7.4's minimum of 16 (it is required)");
        }
        if (b < 1 || b > MAX_BITS) {
            throw new ConfigurationError(where + ": truncateBits " + b + " is outside 1.."
                    + MAX_BITS + " (it is required; spec §7.2, §7.4)");
        }
        // P is a long, so P >= 2^(b+1) is impossible once b + 1 > 62.
        boolean enoughCollisions = b + 1 <= 62 && p >= 1L << (b + 1);
        boolean fewEnough = 2 * b > 62 || p < 1L << (2 * b);
        if (!enoughCollisions || !fewEnough) {
            throw new ConfigurationError(where + ": truncateBits " + b + " is outside spec §7.4's"
                    + " band for a projected population of " + p + ": it needs"
                    + " 2 <= P * 2^-b < sqrt(P), that is 2^(b+1) <= P < 2^(2b)");
        }
    }

    private static void override(String where, String name, ReviewedOverride o) {
        if (blank(o.reason()) || blank(o.approvedBy()) || o.date() == null) {
            throw new ConfigurationError(where + ": " + name + " needs a reason, an approver and"
                    + " a date: it is the recorded, reviewed act spec §7.6 requires");
        }
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private static void uuid(String name, byte[] v) {
        if (v == null || v.length != 16) {
            throw new ConfigurationError("an index declaration's " + name + " must be 16 bytes,"
                    + " got " + (v == null ? "null" : v.length));
        }
    }
}
