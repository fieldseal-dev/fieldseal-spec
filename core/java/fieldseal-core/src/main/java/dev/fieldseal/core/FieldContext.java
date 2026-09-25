package dev.fieldseal.core;

import dev.fieldseal.core.errors.InvalidArgumentError;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * The context every value is bound to (spec §6.1): which table and column it belongs to, and
 * optionally which tenant and row. A value decrypted under a different context fails.
 *
 * <p>Two members of spec §6.1's tuple are not here, because the core fills them and a caller
 * must not: {@code suite_id} (from the configuration on a write, from the envelope on a read;
 * docs/09 §3.2 step 4) and {@code purpose} ({@code "encrypt"} for values; an index's from its
 * declaration at S5).
 *
 * <p>Immutable: the arrays are copied in and out.
 *
 * @param tableUuid 16 bytes: a stable surrogate for the table, never its SQL name (spec §6.1)
 * @param columnUuid 16 bytes: a stable surrogate for the column
 * @param tenantId the tenant, or null when the column is not tenant-scoped. An empty array is a
 *     present, zero-length tenant, which is a different context from null (spec §6.2)
 * @param rowId the row, or null when the value is not row-bound (spec §6.4)
 */
public record FieldContext(byte[] tableUuid, byte[] columnUuid, byte[] tenantId, byte[] rowId) {

    /** @throws InvalidArgumentError if a UUID is missing or not 16 bytes */
    public FieldContext {
        tableUuid = uuid("tableUuid", tableUuid);
        columnUuid = uuid("columnUuid", columnUuid);
        tenantId = tenantId == null ? null : tenantId.clone();
        rowId = rowId == null ? null : rowId.clone();
    }

    /** A context with neither tenant nor row. */
    public static FieldContext of(byte[] tableUuid, byte[] columnUuid) {
        return new FieldContext(tableUuid, columnUuid, null, null);
    }

    /** This context with {@code tenantId} (null for none). */
    public FieldContext withTenant(byte[] tenantId) {
        return new FieldContext(tableUuid, columnUuid, tenantId, rowId);
    }

    /** This context with {@code rowId} (null for none). */
    public FieldContext withRow(byte[] rowId) {
        return new FieldContext(tableUuid, columnUuid, tenantId, rowId);
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
    public byte[] tenantId() {
        return tenantId == null ? null : tenantId.clone();
    }

    @Override
    public byte[] rowId() {
        return rowId == null ? null : rowId.clone();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof FieldContext c && Arrays.equals(tableUuid, c.tableUuid)
                && Arrays.equals(columnUuid, c.columnUuid) && Arrays.equals(tenantId, c.tenantId)
                && Arrays.equals(rowId, c.rowId);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(new int[] {Arrays.hashCode(tableUuid), Arrays.hashCode(columnUuid),
            Arrays.hashCode(tenantId), Arrays.hashCode(rowId)});
    }

    /** Identifiers only, which spec §6.5 makes public. */
    @Override
    public String toString() {
        HexFormat h = HexFormat.of();
        return "FieldContext[table=" + h.formatHex(tableUuid) + ", column="
                + h.formatHex(columnUuid) + ", tenant="
                + (tenantId == null ? "absent" : h.formatHex(tenantId)) + ", row="
                + (rowId == null ? "absent" : h.formatHex(rowId)) + "]";
    }

    private static byte[] uuid(String name, byte[] v) {
        if (v == null || v.length != 16) {
            throw new InvalidArgumentError(name + " must be 16 bytes, got "
                    + (v == null ? "null" : v.length) + " (spec §6.1)");
        }
        return v.clone();
    }
}
