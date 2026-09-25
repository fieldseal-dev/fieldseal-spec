package dev.fieldseal.core.internal.context;

import java.nio.charset.StandardCharsets;

/**
 * {@code canonical_context} and the AAD (spec §6.2 [PROVISIONAL — G4]):
 *
 * <pre>
 * canonical_context(ctx) =
 *     u8(presence)
 *   ‖ u64be(len(suite_id))    ‖ suite_id
 *   ‖ u64be(len(table_uuid))  ‖ table_uuid
 *   ‖ u64be(len(column_uuid)) ‖ column_uuid
 *   ‖ [ u64be(len(tenant_id)) ‖ tenant_id ]      // present iff presence &amp; 0x01
 *   ‖ [ u64be(len(row_id))    ‖ row_id    ]      // present iff presence &amp; 0x02
 *   ‖ u64be(len(purpose))     ‖ purpose
 *
 * AAD(header, ctx) =
 *     u64be(len(fmt_ver))  ‖ fmt_ver
 *   ‖ u64be(len(key_id))   ‖ key_id
 *   ‖ u64be(len(msg_seed)) ‖ msg_seed
 *   ‖ canonical_context(ctx)
 * </pre>
 *
 * <p>An absent field contributes nothing and clears its presence bit; a present field contributes
 * its prefix and its bytes even when it is empty, so {@code null} and {@code b""} differ in the
 * first byte. Reserved bits 2–7 are written as zero. {@code suite_id} is two bytes, big-endian,
 * as in the envelope (spec §3.1). {@code purpose} is ASCII by its grammar (spec §6.1).
 *
 * <p>Lengths are summed as {@code long}. {@code tenant_id} and {@code row_id} are unbounded
 * (spec §6.1, G14), so two large ones can sum past any Java array; that is refused as an
 * {@link OutOfMemoryError}, as the codec refuses an envelope past the array limit (docs/27 §6.1),
 * never by letting an {@code int} wrap.
 */
public final class CanonicalContext {

    public static final int PRESENCE_TENANT = 0x01;
    public static final int PRESENCE_ROW = 0x02;

    private static final int PREFIX = 8;

    private CanonicalContext() {}

    /** spec §6.2's {@code canonical_context}. */
    public static byte[] encode(ContextFields ctx) {
        if (!Purpose.isValid(ctx.purpose())) {
            // The purpose comes from the core (Purpose), so this is the core's bug, not the caller's.
            throw new IllegalArgumentException("canonical_context precondition: purpose '"
                    + ctx.purpose() + "' is outside the spec §6.1 grammar");
        }
        byte[] suiteId = {(byte) (ctx.suiteId() >>> 8), (byte) ctx.suiteId()};
        byte[] purpose = ctx.purpose().getBytes(StandardCharsets.US_ASCII);
        int presence = (ctx.tenantId() != null ? PRESENCE_TENANT : 0)
                | (ctx.rowId() != null ? PRESENCE_ROW : 0);

        long total = 1L + field(suiteId) + field(ctx.tableUuid()) + field(ctx.columnUuid())
                + field(ctx.tenantId()) + field(ctx.rowId()) + field(purpose);
        Writer w = new Writer(total, "canonical_context");
        w.u8(presence);
        w.prefixed(suiteId);
        w.prefixed(ctx.tableUuid());
        w.prefixed(ctx.columnUuid());
        if (ctx.tenantId() != null) {
            w.prefixed(ctx.tenantId());
        }
        if (ctx.rowId() != null) {
            w.prefixed(ctx.rowId());
        }
        w.prefixed(purpose);
        return w.done();
    }

    /**
     * spec §7.2's {@code info}: {@code canonical_context} with {@code row_id} absent, whatever the
     * caller supplied. The index key must not vary per row, or no two rows would share one.
     */
    public static byte[] encodeForIndexKey(ContextFields ctx) {
        return encode(ctx.withoutRowId());
    }

    /** spec §6.2's {@code AAD(header, ctx)}, over an already encoded {@code canonical_context}. */
    public static byte[] aad(int fmtVer, byte[] keyId, byte[] msgSeed, byte[] canonicalContext) {
        byte[] ver = {(byte) fmtVer};
        long total = field(ver) + field(keyId) + field(msgSeed) + canonicalContext.length;
        Writer w = new Writer(total, "AAD");
        w.prefixed(ver);
        w.prefixed(keyId);
        w.prefixed(msgSeed);
        w.raw(canonicalContext);
        return w.done();
    }

    /** What one optional or mandatory field adds: nothing when absent. */
    private static long field(byte[] value) {
        return value == null ? 0 : PREFIX + (long) value.length;
    }

    private static final class Writer {
        private final byte[] out;
        private int at;

        Writer(long total, String what) {
            if (total > Integer.MAX_VALUE - 8) {
                throw new OutOfMemoryError("a " + what + " of " + total
                        + " bytes is longer than any Java array (spec §6.1, G14; docs/27 §6.1)");
            }
            out = new byte[(int) total];
        }

        void u8(int v) {
            out[at++] = (byte) v;
        }

        void prefixed(byte[] value) {
            long len = value.length;
            for (int shift = 56; shift >= 0; shift -= 8) {
                out[at++] = (byte) (len >>> shift);
            }
            raw(value);
        }

        void raw(byte[] value) {
            System.arraycopy(value, 0, out, at, value.length);
            at += value.length;
        }

        byte[] done() {
            if (at != out.length) {
                throw new IllegalStateException("encoded " + at + " of " + out.length + " bytes");
            }
            return out;
        }
    }
}
