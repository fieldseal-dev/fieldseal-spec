package dev.fieldseal.core.keyprovider;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * What a provider is told about the key it is asked for: the spec §6.1 context of the call, less
 * {@code suite_id}, which does not choose a key. The purpose is always set by the core ({@code
 * "encrypt"}, or {@code "index:<id>"} from a validated index declaration), never forwarded from a
 * caller.
 *
 * <p>The arrays are copied in and copied out, so neither the caller's context nor a provider can
 * change what the other sees.
 *
 * @param tableUuid 16 bytes
 * @param columnUuid 16 bytes
 * @param tenantId the tenant, or null when the column is not tenant-scoped
 * @param rowId the row, or null when the column is not row-bound
 * @param purpose {@code "encrypt"} or {@code "index:<id>"}
 */
public record KeyRequest(byte[] tableUuid, byte[] columnUuid, byte[] tenantId, byte[] rowId,
        String purpose) {

    public KeyRequest {
        tableUuid = tableUuid.clone();
        columnUuid = columnUuid.clone();
        tenantId = tenantId == null ? null : tenantId.clone();
        rowId = rowId == null ? null : rowId.clone();
        if (purpose == null) {
            throw new IllegalArgumentException("purpose is required");
        }
    }

    /** Whether this request is for an index key rather than the DEK (spec §8). */
    public boolean isIndex() {
        return purpose.startsWith("index:");
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
        return o instanceof KeyRequest r && Arrays.equals(tableUuid, r.tableUuid)
                && Arrays.equals(columnUuid, r.columnUuid) && Arrays.equals(tenantId, r.tenantId)
                && Arrays.equals(rowId, r.rowId) && purpose.equals(r.purpose);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(new int[] {Arrays.hashCode(tableUuid), Arrays.hashCode(columnUuid),
            Arrays.hashCode(tenantId), Arrays.hashCode(rowId), purpose.hashCode()});
    }

    /** Identifiers only: UUIDs and ids are public (spec §6.5), and no key material is here. */
    @Override
    public String toString() {
        HexFormat h = HexFormat.of();
        return "KeyRequest[table=" + h.formatHex(tableUuid) + ", column=" + h.formatHex(columnUuid)
                + ", tenant=" + (tenantId == null ? "absent" : h.formatHex(tenantId))
                + ", row=" + (rowId == null ? "absent" : h.formatHex(rowId))
                + ", purpose=" + purpose + "]";
    }
}
