package dev.fieldseal.core;

import dev.fieldseal.core.errors.InvalidArgumentError;
import dev.fieldseal.core.internal.blindindex.Normalizers;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * One blind index, declared to the client at construction (docs/09 §7): a column's index is fixed
 * when the column is declared, not chosen per call, so that spec §7.4's truncation band and spec
 * §7.6's cardinality gate run once, where the column is declared, and a declaration that fails
 * never reaches a key derivation.
 *
 * <p>This is the declaration as supplied. {@link Fieldseal#validateIndexDeclaration} checks it and
 * fills in the defaults; {@link Fieldseal.Builder#indexes} does the same for every declaration
 * a client is built with. Nothing is checked here, so a declaration that is wrong is reported by
 * that validation with the reason, rather than by a constructor with none.
 *
 * <p>Immutable: the arrays are copied in and out.
 *
 * @param tableUuid 16 bytes: the column's table, as in its {@link FieldContext}
 * @param columnUuid 16 bytes: the column
 * @param indexId the spec §6.1 {@code index-id}, {@code [a-z0-9-]{1,32}}; null means {@code "exact"}
 * @param idf spec §7.3: {@link Idf#ARGON2ID} for an enumerable domain, {@link Idf#HMAC_SHA512}
 *     only for a high-entropy one
 * @param argon2 the Argon2id cost; null means spec §7.3's minima. Not allowed on {@code
 *     hmac-sha512}, which has no cost (docs/09 §7)
 * @param normalize the normalizer, from the closed set of docs/09 §7
 * @param truncateBits {@code b}, within spec §7.4's band for {@code projectedPopulation}
 * @param projectedPopulation {@code P}, the projected number of distinct values (spec §7.4)
 * @param skewed that the column's values are heavily skewed, one or a few values dominating:
 *     gated by spec §7.6 exactly as a small {@code P} is. Default false
 * @param cardinalityOverride required when {@code P} is below spec §7.6's gate of 2^10, or the
 *     column is declared {@code skewed}
 * @param onUnindexable docs/09 §7.2; null means {@link OnUnindexable#REFUSE}
 * @param unindexableOverride required for {@link OnUnindexable#BUCKET} (docs/09 §7.2)
 */
public record IndexDeclaration(byte[] tableUuid, byte[] columnUuid, String indexId, Idf idf,
        Argon2Params argon2, Normalizer normalize, int truncateBits, long projectedPopulation,
        boolean skewed, ReviewedOverride cardinalityOverride, OnUnindexable onUnindexable,
        ReviewedOverride unindexableOverride) {

    public IndexDeclaration {
        tableUuid = tableUuid == null ? null : tableUuid.clone();
        columnUuid = columnUuid == null ? null : columnUuid.clone();
    }

    /** A builder for the declaration of an index on {@code (tableUuid, columnUuid)}. */
    public static Builder builder(byte[] tableUuid, byte[] columnUuid) {
        return new Builder(tableUuid, columnUuid);
    }

    @Override
    public byte[] tableUuid() {
        return tableUuid == null ? null : tableUuid.clone();
    }

    @Override
    public byte[] columnUuid() {
        return columnUuid == null ? null : columnUuid.clone();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof IndexDeclaration d && Arrays.equals(tableUuid, d.tableUuid)
                && Arrays.equals(columnUuid, d.columnUuid)
                && java.util.Objects.equals(indexId, d.indexId) && idf == d.idf
                && java.util.Objects.equals(argon2, d.argon2) && normalize == d.normalize
                && truncateBits == d.truncateBits && projectedPopulation == d.projectedPopulation
                && skewed == d.skewed
                && java.util.Objects.equals(cardinalityOverride, d.cardinalityOverride)
                && onUnindexable == d.onUnindexable
                && java.util.Objects.equals(unindexableOverride, d.unindexableOverride);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(Arrays.hashCode(tableUuid), Arrays.hashCode(columnUuid),
                indexId, idf, argon2, normalize, truncateBits, projectedPopulation,
                skewed, cardinalityOverride, onUnindexable, unindexableOverride);
    }

    @Override
    public String toString() {
        HexFormat h = HexFormat.of();
        return "IndexDeclaration[table=" + (tableUuid == null ? null : h.formatHex(tableUuid))
                + ", column=" + (columnUuid == null ? null : h.formatHex(columnUuid))
                + ", indexId=" + indexId + ", idf=" + idf + ", argon2=" + argon2 + ", normalize="
                + normalize + ", truncateBits=" + truncateBits + ", projectedPopulation="
                + projectedPopulation + ", skewed=" + skewed + ", cardinalityOverride=" + cardinalityOverride
                + ", onUnindexable=" + onUnindexable + ", unindexableOverride="
                + unindexableOverride + "]";
    }

    /** spec §7.3's index derivation functions. */
    public enum Idf {
        ARGON2ID("argon2id"),
        HMAC_SHA512("hmac-sha512");

        private final String id;

        Idf(String id) {
            this.id = id;
        }

        /** The identifier the vectors and the other cores use. */
        public String id() {
            return id;
        }
    }

    /**
     * The closed, versioned normalizer set of docs/09 §7. Public so that spec §7.5's
     * re-verification compares under the index's own equality with the same code that derived
     * the index, rather than a reimplementation (docs/09 §7).
     */
    public enum Normalizer {
        /** Bytes unchanged; text as its UTF-8 encoding. */
        IDENTITY(Normalizers.Id.IDENTITY),
        /** docs/09 §7.1: {@code NFC(toCasefold(NFC(X)))} at Unicode {@value Fieldseal#UNICODE_VERSION}. */
        NFC_CASEFOLD_V1(Normalizers.Id.NFC_CASEFOLD_V1),
        /** docs/09 §7: the ASCII digits, on bytes. */
        DIGITS_ONLY_V1(Normalizers.Id.DIGITS_ONLY_V1);

        private final Normalizers.Id impl;

        Normalizer(Normalizers.Id impl) {
            this.impl = impl;
        }

        /** The identifier the vectors and the other cores use. */
        public String id() {
            return impl.wire();
        }

        /**
         * The normalized bytes of {@code value}.
         *
         * <p><b>For spec §7.5's re-verification</b>, compare a candidate with the queried value
         * on these bytes. Where this refuses a value, that side of the comparison falls back to
         * the value's raw plaintext bytes, so two refused values are equal only byte for byte
         * (spec §7.5, G19). That is how two different values in one {@code bucket} are told
         * apart.
         *
         * @throws InvalidArgumentError if this normalizer refuses the value: a code point not
         *     assigned in the pinned Unicode version, or a lone surrogate (docs/09 §7.1)
         */
        public byte[] normalize(String value) {
            if (value == null) {
                throw new InvalidArgumentError("the value to normalize is null");
            }
            return valueOrThrow(Normalizers.apply(impl, value));
        }

        /**
         * The normalized bytes of {@code value}. {@link #NFC_CASEFOLD_V1} decodes it as strict
         * UTF-8 first (docs/09 §7.1 clause 5). Re-verification compares as {@link
         * #normalize(String)} describes, falling back to {@code value} itself on a refusal.
         *
         * @throws InvalidArgumentError on malformed UTF-8, or as {@link #normalize(String)}
         */
        public byte[] normalize(byte[] value) {
            if (value == null) {
                throw new InvalidArgumentError("the value to normalize is null");
            }
            return valueOrThrow(Normalizers.apply(impl, value));
        }

        Normalizers.Id impl() {
            return impl;
        }

        private static byte[] valueOrThrow(Normalizers.Result r) {
            return switch (r) {
                case Normalizers.Result.Value v -> v.bytes();
                case Normalizers.Result.Refused f -> throw new InvalidArgumentError(f.reason());
            };
        }
    }

    /** docs/09 §7.2: what index derivation does with a value its normalizer refuses. */
    public enum OnUnindexable {
        /** Raise {@code INVALID_ARGUMENT}; an adapter deriving an index on write fails the write. */
        REFUSE("refuse"),
        /** Return this column's reserved marker instead, so the row is stored and findable. */
        BUCKET("bucket");

        private final String id;

        OnUnindexable(String id) {
            this.id = id;
        }

        public String id() {
            return id;
        }
    }

    /**
     * An Argon2id cost above spec §7.3's minima. Raising either value makes a different index
     * (spec §7.8), not a reconfiguration of an existing one.
     *
     * @param timeCost {@code t}, iterations; at least 3
     * @param memoryKib {@code m}, in KiB; at least 32768
     */
    public record Argon2Params(int timeCost, int memoryKib) {}

    /**
     * The reviewed, recorded act that relaxes a default-deny rule on one column: spec §7.6's
     * cardinality gate, or docs/09 §7.2's {@code refuse}. The client logs it, through its warning
     * hook, when it is built.
     *
     * @param reason why the rule does not fit this column
     * @param approvedBy who reviewed it
     * @param date when
     */
    public record ReviewedOverride(String reason, String approvedBy, LocalDate date) {}

    /** Builds an {@link IndexDeclaration}; {@link #build} checks nothing (see the class comment). */
    public static final class Builder {
        private final byte[] tableUuid;
        private final byte[] columnUuid;
        private String indexId;
        private Idf idf;
        private Argon2Params argon2;
        private Normalizer normalize;
        private int truncateBits;
        private long projectedPopulation;
        private boolean skewed;
        private ReviewedOverride cardinalityOverride;
        private OnUnindexable onUnindexable;
        private ReviewedOverride unindexableOverride;

        private Builder(byte[] tableUuid, byte[] columnUuid) {
            this.tableUuid = tableUuid;
            this.columnUuid = columnUuid;
        }

        /** Default {@code "exact"}. */
        public Builder indexId(String id) {
            this.indexId = id;
            return this;
        }

        /** Required. */
        public Builder idf(Idf idf) {
            this.idf = idf;
            return this;
        }

        /** Argon2id only; default spec §7.3's minima. */
        public Builder argon2(Argon2Params cost) {
            this.argon2 = cost;
            return this;
        }

        /** Required. */
        public Builder normalize(Normalizer n) {
            this.normalize = n;
            return this;
        }

        /** Required. */
        public Builder truncateBits(int b) {
            this.truncateBits = b;
            return this;
        }

        /** Required. */
        public Builder projectedPopulation(long p) {
            this.projectedPopulation = p;
            return this;
        }

        /** Default false. A skewed column needs a {@link #cardinalityOverride} (spec §7.6). */
        public Builder skewed(boolean skewed) {
            this.skewed = skewed;
            return this;
        }

        public Builder cardinalityOverride(ReviewedOverride o) {
            this.cardinalityOverride = o;
            return this;
        }

        /** Default {@link OnUnindexable#REFUSE}. */
        public Builder onUnindexable(OnUnindexable policy) {
            this.onUnindexable = policy;
            return this;
        }

        public Builder unindexableOverride(ReviewedOverride o) {
            this.unindexableOverride = o;
            return this;
        }

        public IndexDeclaration build() {
            return new IndexDeclaration(tableUuid, columnUuid, indexId, idf, argon2, normalize,
                    truncateBits, projectedPopulation, skewed, cardinalityOverride,
                    onUnindexable, unindexableOverride);
        }
    }
}
