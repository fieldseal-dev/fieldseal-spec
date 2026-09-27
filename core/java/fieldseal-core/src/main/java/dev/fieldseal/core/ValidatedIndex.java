package dev.fieldseal.core;

import dev.fieldseal.core.IndexDeclaration.Argon2Params;
import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.core.IndexDeclaration.OnUnindexable;
import dev.fieldseal.core.IndexDeclaration.ReviewedOverride;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * An {@link IndexDeclaration} as validated, with every default resolved (docs/09 §2,
 * "resolved, not as-declared"): {@code indexId} is never null, an Argon2id index always carries
 * its cost, and {@code onUnindexable} is never null. Two declarations that agree textually and
 * differ operationally therefore compare unequal here, which is what an adapter's registry check
 * needs (#62).
 *
 * <p>Obtained from {@link Fieldseal#validateIndexDeclaration} or {@link Fieldseal#indexes}. The
 * client never takes one as input, so a hand-built one validates nothing and changes nothing.
 * Immutable: the arrays are copied in and out.
 *
 * @param argon2 the cost for {@link Idf#ARGON2ID}; null for {@link Idf#HMAC_SHA512}, which has
 *     none
 */
public record ValidatedIndex(byte[] tableUuid, byte[] columnUuid, String indexId, Idf idf,
        Argon2Params argon2, Normalizer normalize, int truncateBits, long projectedPopulation,
        boolean skewed, ReviewedOverride cardinalityOverride, OnUnindexable onUnindexable,
        ReviewedOverride unindexableOverride) {

    public ValidatedIndex {
        tableUuid = tableUuid.clone();
        columnUuid = columnUuid.clone();
    }

    /** The key {@link Fieldseal#indexes} files this index under. */
    public String registryKey() {
        return Fieldseal.indexRegistryKey(tableUuid, columnUuid, indexId);
    }

    /** spec §6.1: {@code "index:" + indexId}, the purpose its key is derived for. */
    public String purpose() {
        return "index:" + indexId;
    }

    @Override
    public byte[] tableUuid() {
        return tableUuid.clone();
    }

    @Override
    public byte[] columnUuid() {
        return columnUuid.clone();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ValidatedIndex v && Arrays.equals(tableUuid, v.tableUuid)
                && Arrays.equals(columnUuid, v.columnUuid) && indexId.equals(v.indexId)
                && idf == v.idf && Objects.equals(argon2, v.argon2) && normalize == v.normalize
                && truncateBits == v.truncateBits && projectedPopulation == v.projectedPopulation
                && skewed == v.skewed
                && Objects.equals(cardinalityOverride, v.cardinalityOverride)
                && onUnindexable == v.onUnindexable
                && Objects.equals(unindexableOverride, v.unindexableOverride);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(tableUuid), Arrays.hashCode(columnUuid), indexId,
                idf, argon2, normalize, truncateBits, projectedPopulation, skewed, cardinalityOverride,
                onUnindexable, unindexableOverride);
    }

    @Override
    public String toString() {
        HexFormat h = HexFormat.of();
        return "ValidatedIndex[table=" + h.formatHex(tableUuid) + ", column="
                + h.formatHex(columnUuid) + ", indexId=" + indexId + ", idf=" + idf.id()
                + ", argon2=" + argon2 + ", normalize=" + normalize.id() + ", truncateBits="
                + truncateBits + ", projectedPopulation=" + projectedPopulation + ", skewed=" + skewed
                + ", cardinalityOverride=" + cardinalityOverride + ", onUnindexable="
                + onUnindexable.id() + ", unindexableOverride=" + unindexableOverride + "]";
    }
}
