package dev.fieldseal.core.internal.context;

import dev.fieldseal.core.errors.InvalidArgumentError;

/**
 * The spec §6.1 {@code FieldContext} tuple, as this module sees it. The public {@code FieldContext}
 * lives in {@code api}, which no module may import (docs/09 §1), so {@code api} maps it onto this
 * record at the value path's boundary.
 *
 * <p>The record holds the caller's arrays, not copies: {@link CanonicalContext#encode} reads them
 * once, and nothing here retains them past the call that built the record.
 *
 * @param suiteId the {@code suite_id}, filled by the core and never by an adapter (docs/09 §12)
 * @param tableUuid 16 bytes, a stable surrogate (spec §6.1)
 * @param columnUuid 16 bytes, a stable surrogate (spec §6.1)
 * @param tenantId absent when null; present, possibly zero-length, otherwise (spec §6.2)
 * @param rowId absent when null; present, possibly zero-length, otherwise (spec §6.2)
 * @param purpose {@code "encrypt"} or {@code "index:<index-id>"} (spec §6.1)
 */
public record ContextFields(int suiteId, byte[] tableUuid, byte[] columnUuid, byte[] tenantId,
        byte[] rowId, String purpose) {

    public static final int UUID_LEN = 16;

    /**
     * Refuses a context the encoding must never see: a missing or wrongly sized UUID, or a
     * {@code suite_id} outside {@code uint16}. docs/09 §3.1 step 2 validates the context at the
     * API boundary, so this is {@code INVALID_ARGUMENT} and not a configuration error. The purpose
     * is not checked here: it comes from the core, never from the caller (see {@link Purpose}).
     *
     * @throws InvalidArgumentError on the first field that fails
     */
    public ContextFields {
        if (suiteId < 0 || suiteId > 0xFFFF) {
            throw new InvalidArgumentError("suite_id " + suiteId + " is not a uint16 (spec §6.1)");
        }
        requireUuid("table_uuid", tableUuid);
        requireUuid("column_uuid", columnUuid);
        if (purpose == null) {
            throw new InvalidArgumentError("purpose is required (spec §6.1)");
        }
    }

    /** The same context with {@code row_id} absent: what spec §7.2 derives an index key over. */
    public ContextFields withoutRowId() {
        return new ContextFields(suiteId, tableUuid, columnUuid, tenantId, null, purpose);
    }

    private static void requireUuid(String name, byte[] uuid) {
        if (uuid == null || uuid.length != UUID_LEN) {
            throw new InvalidArgumentError(name + " must be " + UUID_LEN + " bytes, got "
                    + (uuid == null ? "null" : uuid.length) + " (spec §6.1)");
        }
    }
}
