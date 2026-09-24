package dev.fieldseal.core.internal.envelope;

import dev.fieldseal.core.errors.LengthExceededError;
import dev.fieldseal.core.internal.registry.Suite;

/**
 * The spec §3.5 plaintext bound, in the three rules of docs/27 §6.2:
 *
 * <ol>
 *   <li>every length is computed in 64-bit arithmetic, so no near-bound length wraps;
 *   <li>a negative implied length belongs to recognition, not to this bound: it means the
 *       envelope is too short for its suite;
 *   <li>over the bound is {@code LENGTH_EXCEEDED}, never the platform's error, with no clamping
 *       and no wrapping.
 * </ol>
 */
public final class BufferLimits {

    /** 2<sup>31</sup>−1, spec §3.5. A {@code long}, so 2<sup>31</sup> and beyond compare. */
    public static final long MAX_PLAINTEXT = 2_147_483_647L;

    /** {@code fmt_ver} 1 + {@code suite_id} 2 + {@code key_id} 16 + {@code msg_seed} 32. */
    public static final int HEADER_LEN = 51;

    private BufferLimits() {}

    /** Everything in an envelope but the ciphertext: 111 bytes for {@code 0xFF01}. */
    public static long fixedOverhead(Suite s) {
        return (long) HEADER_LEN + s.nonceLen() + s.tagLen() + s.commitLen();
    }

    public static long impliedPlaintextLen(long received, Suite s) {
        return received - fixedOverhead(s);
    }

    public static boolean plaintextWithinBound(long len) {
        return len >= 0 && len <= MAX_PLAINTEXT;
    }

    public static boolean impliedWithinBound(long received, Suite s) {
        return impliedPlaintextLen(received, s) <= MAX_PLAINTEXT;
    }

    /** The encrypt-side guard (docs/09 §3.1 step 1b). Reads the operand's length only. */
    public static void requirePlaintextWithinBound(Operand plaintext) {
        long len = plaintext.length();
        if (!plaintextWithinBound(len)) {
            throw new LengthExceededError("plaintext", len);
        }
    }

    /** The decrypt-side guard (spec §3.5). Reads the operand's length only. */
    public static void requireImpliedWithinBound(Operand envelope, Suite s) {
        if (!impliedWithinBound(envelope.length(), s)) {
            throw new LengthExceededError("implied plaintext",
                    impliedPlaintextLen(envelope.length(), s));
        }
    }
}
