package dev.fieldseal.core.internal.envelope;

import dev.fieldseal.core.internal.registry.Registry;
import dev.fieldseal.core.internal.registry.Suite;
import java.util.ArrayList;
import java.util.List;

/**
 * An {@link Operand} of any {@code long} length that no array could back (docs/27 §6.2). It
 * serves {@code served} at offset 0 and records every content access. A read outside what it
 * serves throws {@link Unserved}, unless it was built to fabricate bytes there.
 */
public final class SyntheticOperand implements Operand {

    /** A content access the test did not permit. Not a FieldsealError, so it cannot pass as one. */
    public static final class Unserved extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Unserved(long from, long len) {
            super("content access at " + from + " (+" + len + ") outside the served bytes");
        }
    }

    private final long length;
    private final byte[] served;
    private final boolean fabricateBeyond;
    /** Every access, as {offset, length}. */
    public final List<long[]> reads = new ArrayList<>();

    private SyntheticOperand(long length, byte[] served, boolean fabricateBeyond) {
        this.length = length;
        this.served = served.clone();
        this.fabricateBeyond = fabricateBeyond;
    }

    /** Serves {@code served} and refuses every other offset. */
    public static SyntheticOperand strict(long length, byte[] served) {
        return new SyntheticOperand(length, served, false);
    }

    /** Serves {@code served}, and a deterministic byte at every other offset below the length. */
    public static SyntheticOperand fabricating(long length, byte[] served) {
        return new SyntheticOperand(length, served, true);
    }

    /** The header and nonce of a well-formed envelope under {@code suite}: 51 + nonce bytes. */
    public static byte[] header(Suite suite) {
        byte[] h = new byte[BufferLimits.HEADER_LEN + suite.nonceLen()];
        h[0] = 0x01;
        h[1] = (byte) (suite.id() >>> 8);
        h[2] = (byte) suite.id();
        for (int i = 3; i < h.length; i++) {
            h[i] = (byte) i;
        }
        return h;
    }

    /** {@link #header} for {@code 0xFF01}: the first 51 + 12 bytes. */
    public static byte[] ff01Header() {
        return header(Registry.FF01);
    }

    /** The highest offset any access touched, or -1 if none did. */
    public long highestOffsetRead() {
        return reads.stream().mapToLong(r -> r[0] + r[1] - 1).max().orElse(-1);
    }

    private byte at(long i) {
        if (i < 0 || i >= length) {
            throw new IndexOutOfBoundsException("offset " + i + " of " + length);
        }
        if (i < served.length) {
            return served[(int) i];
        }
        if (!fabricateBeyond) {
            throw new Unserved(i, 1);
        }
        return (byte) (i * 31);
    }

    @Override
    public long length() {
        return length;
    }

    @Override
    public byte byteAt(long index) {
        reads.add(new long[] {index, 1});
        return at(index);
    }

    @Override
    public void copyTo(long from, byte[] dst, int off, int len) {
        reads.add(new long[] {from, len});
        for (int i = 0; i < len; i++) {
            dst[off + i] = at(from + i);
        }
    }
}
