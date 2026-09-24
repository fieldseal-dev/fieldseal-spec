package dev.fieldseal.core.internal.envelope;

import dev.fieldseal.core.errors.InvalidArgumentError;

/**
 * The length seam (docs/09 §4, G26; docs/27 §6.2): the one internal type every operand of
 * {@code encrypt}, {@code decrypt} and {@code rotate} travels as. Each public entry point builds
 * it exactly once, from the caller's {@code byte[]}, and every later step reads through it.
 *
 * <p>Its length is a {@code long}. No {@code byte[]} is 2<sup>31</sup> bytes long, so on this
 * platform the spec §3.5 guard is unreachable from the public API; a synthetic operand reporting
 * such a length, driven through the same path, is how the guard is shown to fire (docs/14 §4,
 * {@code basis: "seam"}).
 */
public interface Operand {

    /** The operand's length in bytes. */
    long length();

    /** The byte at {@code index}, which must be in {@code [0, length())}. */
    byte byteAt(long index);

    /** Copies {@code len} bytes starting at {@code from} into {@code dst} at {@code off}. */
    void copyTo(long from, byte[] dst, int off, int len);

    /**
     * Wraps the caller's array without copying it (docs/27 §6.3).
     *
     * @throws InvalidArgumentError if {@code bytes} is null
     */
    static Operand of(byte[] bytes) {
        if (bytes == null) {
            throw new InvalidArgumentError("the operand is null");
        }
        return new ArrayOperand(bytes);
    }

    /** The only production implementation: a view of the caller's array. */
    record ArrayOperand(byte[] bytes) implements Operand {

        @Override
        public long length() {
            return bytes.length;
        }

        @Override
        public byte byteAt(long index) {
            return bytes[(int) java.util.Objects.checkIndex(index, bytes.length)];
        }

        @Override
        public void copyTo(long from, byte[] dst, int off, int len) {
            System.arraycopy(bytes, Math.toIntExact(from), dst, off, len);
        }
    }
}
