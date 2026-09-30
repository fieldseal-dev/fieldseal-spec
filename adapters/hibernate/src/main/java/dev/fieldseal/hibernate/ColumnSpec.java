package dev.fieldseal.hibernate;

import dev.fieldseal.core.FieldContext;
import java.nio.charset.StandardCharsets;
import org.hibernate.engine.spi.SharedSessionContractImplementor;

/**
 * One encrypted attribute, as the integrator resolved it: its context's fixed half, and its
 * codec. Immutable.
 */
final class ColumnSpec {
    final String entityName;
    final String attribute;
    /** {@code Entity.attribute}, for messages. */
    final String label;
    private final byte[] tableUuid;
    private final byte[] columnUuid;
    final boolean tenantBound;
    final Codec codec;

    ColumnSpec(String entityName, String attribute, String label, byte[] tableUuid,
            byte[] columnUuid, boolean tenantBound, Codec codec) {
        this.entityName = entityName;
        this.attribute = attribute;
        this.label = label;
        this.tableUuid = tableUuid.clone();
        this.columnUuid = columnUuid.clone();
        this.tenantBound = tenantBound;
        this.codec = codec;
    }

    byte[] tableUuid() {
        return tableUuid.clone();
    }

    byte[] columnUuid() {
        return columnUuid.clone();
    }

    /** The context for this column in {@code session}: the tenant is the session's (docs/29 §4). */
    FieldContext context(SharedSessionContractImplementor session) {
        FieldContext ctx = FieldContext.of(tableUuid, columnUuid);
        if (!tenantBound) {
            return ctx;
        }
        return ctx.withTenant(tenantBytes(session == null ? null
                : session.getTenantIdentifierValue()));
    }

    /** The context with an explicit tenant, for {@code warm}. */
    FieldContext context(Object tenant) {
        FieldContext ctx = FieldContext.of(tableUuid, columnUuid);
        return tenantBound ? ctx.withTenant(tenantBytes(tenant)) : ctx;
    }

    private byte[] tenantBytes(Object tenant) {
        if (tenant == null) {
            throw new FieldsealConfigurationException(label + " is declared tenantBound and the "
                    + "session has no tenant identifier. Open the session with "
                    + "SessionBuilder.tenantIdentifier(...) or configure a "
                    + "CurrentTenantIdentifierResolver; the adapter never falls back to a "
                    + "tenantless context for a tenant-bound column (docs/29 §4)");
        }
        if (tenant instanceof String s) {
            return s.getBytes(StandardCharsets.UTF_8);
        }
        if (tenant instanceof byte[] b) {
            return b.clone();
        }
        throw new FieldsealConfigurationException(label + " is tenant-bound, and the session's "
                + "tenant identifier is a " + tenant.getClass().getName() + "; this adapter "
                + "binds a String (as its UTF-8 bytes) or a byte[] (docs/29 §4)");
    }
}
