package dev.fieldseal.core.internal.envelope;

import dev.fieldseal.core.internal.registry.Registry;
import dev.fieldseal.core.internal.registry.Suite;
import java.util.Optional;

/**
 * The envelope codec (spec §3; docs/09 §4): recognition, the decrypt front, parse and serialize.
 *
 * <pre>
 * fmt_ver 1 | suite_id 2 | key_id 16 | msg_seed 32 | nonce | ciphertext | tag | commitment
 * \___________ header, 51 bytes ________________/
 * </pre>
 *
 * <p>Every length is a {@code long}, read from the {@link Operand}, so no step here assumes an
 * operand fits an {@code int} (docs/27 §6.2).
 */
public final class EnvelopeCodec {

    public static final int FMT_VER = 0x01;

    /** spec §3.1: reserved for the next version of this format, and never written. */
    public static final int RESERVED_FMT_VER = 0x02;

    /**
     * spec §3.1: a {@code fmt_ver} 0x02 envelope MUST NOT be shorter than 111 bytes, so shorter
     * {@code 0x02}-prefixed input is not reserved-version input (spec §3.4).
     */
    public static final long RESERVED_VERSION_MIN_LEN = 111;

    private EnvelopeCodec() {}

    /**
     * spec §3.4, the whole table. Reads at most bytes 0–2 of the operand, and its length.
     */
    public static Recognition recognize(Operand op) {
        long n = op.length();
        if (n < 1) {
            return Recognition.NON_ENVELOPE;
        }
        int version = op.byteAt(0) & 0xFF;
        if (version == RESERVED_FMT_VER) {
            return n >= RESERVED_VERSION_MIN_LEN
                    ? Recognition.RESERVED_VERSION : Recognition.NON_ENVELOPE;
        }
        if (version != FMT_VER || n < 3) {
            return Recognition.NON_ENVELOPE;
        }
        Optional<Suite> suite = Registry.lookup(((op.byteAt(1) & 0xFF) << 8) | (op.byteAt(2) & 0xFF));
        if (suite.isEmpty() || n < BufferLimits.fixedOverhead(suite.get())) {
            return Recognition.NON_ENVELOPE;
        }
        return new Recognition.Envelope(suite.get());
    }

    /**
     * spec §3.4 {@code is_ciphertext}: true for the first row of the table only. Registered, not
     * allow-listed; never decrypts.
     */
    public static boolean isCiphertext(byte[] bytes) {
        return recognize(Operand.of(bytes)) instanceof Recognition.Envelope;
    }

    /**
     * The front of {@code decrypt} and {@code rotate}, in this order:
     *
     * <ol>
     *   <li>recognition (docs/09 §3.2 step 2), which reads bytes 0–2;
     *   <li>the spec §3.5 guard, which reads the length only. docs/27 §6.2 places it here, right
     *       after recognition and before anything else: before the parse copies a field, before
     *       the allow-list, key lookup and output allocation. That choice is declared in the
     *       report's {@code decrypt-order};
     *   <li>the parse, which copies the fixed fields and locates ct‖tag.
     * </ol>
     *
     * @throws dev.fieldseal.core.errors.LengthExceededError if the implied plaintext exceeds the bound
     */
    public static DecryptFront frontOfDecrypt(Operand op) {
        return switch (recognize(op)) {
            case Recognition.ReservedVersion r -> new DecryptFront.ReservedVersion();
            case Recognition.NonEnvelope r -> new DecryptFront.NonEnvelope();
            case Recognition.Envelope e -> {
                BufferLimits.requireImpliedWithinBound(op, e.suite());
                yield new DecryptFront.Ready(parse(op, e.suite()));
            }
        };
    }

    /** Parses an operand recognition has already accepted for {@code suite}. */
    static ParsedEnvelope parse(Operand op, Suite suite) {
        long n = op.length();
        long ctOffset = ciphertextOffset(suite);
        byte[] keyId = copy(op, 3, 16);
        byte[] msgSeed = copy(op, 19, 32);
        byte[] nonce = copy(op, BufferLimits.HEADER_LEN, suite.nonceLen());
        byte[] commitment = copy(op, n - suite.commitLen(), suite.commitLen());
        return new ParsedEnvelope(suite, keyId, msgSeed, nonce, commitment, ctOffset,
                n - ctOffset - suite.commitLen());
    }

    private static byte[] copy(Operand op, long from, int len) {
        byte[] out = new byte[len];
        op.copyTo(from, out, 0, len);
        return out;
    }

    /** Where ct‖tag starts: 63 for {@code 0xFF01} (docs/27 §5.1). */
    public static int ciphertextOffset(Suite suite) {
        return BufferLimits.HEADER_LEN + suite.nonceLen();
    }

    /** Where the commitment starts, for a plaintext of {@code plaintextLen} bytes. */
    public static long commitmentOffset(Suite suite, long plaintextLen) {
        return ciphertextOffset(suite) + plaintextLen + suite.tagLen();
    }

    /**
     * Allocates the whole envelope for a plaintext of {@code plaintextLen} bytes and writes its
     * header and nonce, so that the AEAD writes ct‖tag straight into it and the commitment
     * follows: one allocation, the envelope itself (docs/27 §5.1).
     *
     * <p>{@code plaintextLen} is within spec §3.5's bound by the time this runs (the API boundary
     * checks it). An envelope for a plaintext near the bound is longer than any Java array
     * (docs/27 §6.1): the platform fails below the bound, which spec §3.5 makes conformant, so
     * the outcome is an {@link OutOfMemoryError} and not {@code LENGTH_EXCEEDED}. For a total
     * the VM can attempt, the error is the VM's own. For a total no {@code int} holds, the codec
     * raises one itself, with a message that says so, rather than let the cast wrap; the heap is
     * not involved. It is an {@link Error} on purpose: a converter's {@code catch (Exception)}
     * must not turn an unencryptable value into a silent one.
     */
    public static byte[] newEnvelope(Suite suite, byte[] keyId, byte[] msgSeed, byte[] nonce,
            long plaintextLen) {
        require(keyId.length == 16, "key_id is 16 bytes");
        require(msgSeed.length == 32, "msg_seed is 32 bytes");
        require(nonce.length == suite.nonceLen(), "nonce length is the suite's");
        require(BufferLimits.plaintextWithinBound(plaintextLen), "plaintext within the bound");
        long total = BufferLimits.fixedOverhead(suite) + plaintextLen;
        if (total > Integer.MAX_VALUE) {
            throw new OutOfMemoryError("an envelope of " + total
                    + " bytes is longer than any Java array; raised by the codec, not by the heap"
                    + " (docs/27 §6.1)");
        }
        byte[] env = new byte[(int) total];
        env[0] = FMT_VER;
        env[1] = (byte) (suite.id() >>> 8);
        env[2] = (byte) suite.id();
        System.arraycopy(keyId, 0, env, 3, 16);
        System.arraycopy(msgSeed, 0, env, 19, 32);
        System.arraycopy(nonce, 0, env, BufferLimits.HEADER_LEN, nonce.length);
        return env;
    }

    /** Single-pass concatenation, for callers that already hold ct‖tag (docs/09 §4). */
    public static byte[] serialize(Suite suite, byte[] keyId, byte[] msgSeed, byte[] nonce,
            byte[] ctAndTag, byte[] commitment) {
        require(ctAndTag.length >= suite.tagLen(), "ct‖tag holds at least the tag");
        require(commitment.length == suite.commitLen(), "commitment length is the suite's");
        long plaintextLen = ctAndTag.length - suite.tagLen();
        byte[] env = newEnvelope(suite, keyId, msgSeed, nonce, plaintextLen);
        System.arraycopy(ctAndTag, 0, env, ciphertextOffset(suite), ctAndTag.length);
        System.arraycopy(commitment, 0, env, (int) commitmentOffset(suite, plaintextLen),
                commitment.length);
        return env;
    }

    /** A violated precondition here is a bug in the core, not a caller's error. */
    private static void require(boolean condition, String what) {
        if (!condition) {
            throw new IllegalArgumentException("envelope codec precondition: " + what);
        }
    }
}
