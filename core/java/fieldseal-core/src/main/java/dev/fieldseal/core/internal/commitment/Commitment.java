package dev.fieldseal.core.internal.commitment;

import dev.fieldseal.core.internal.registry.Suite;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Key commitment (spec §4.6 [PROVISIONAL — G1]):
 *
 * <pre>
 * commitment = KDF(ikm = record_key, salt = "", info = "fieldseal-commit-v1", length = 32)
 * </pre>
 *
 * <p><b>Where the KDF comes from.</b> docs/09 §1 lets this module depend on {@code registry} and
 * {@code errors} only, and HKDF lives in {@code kdf}. So the suite's KDF is passed in as a
 * {@link Kdf}, and {@code api} passes {@code kdf}'s. The dependency rule stays as written, and a
 * Gate 0b change to the construction still touches this module alone (docs/26 §6).
 */
public final class Commitment {

    /** The spec §4.6 domain separator: 19 ASCII bytes. */
    static final byte[] INFO = "fieldseal-commit-v1".getBytes(StandardCharsets.US_ASCII);

    private static final byte[] EMPTY_SALT = new byte[0];

    private Commitment() {}

    /** The suite's KDF, as {@code (ikm, salt, info, length) -> okm}. */
    @FunctionalInterface
    public interface Kdf {
        byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length);
    }

    /** spec §4.6's {@code commitment} for {@code recordKey}, under {@code suite}. */
    public static byte[] compute(Suite suite, byte[] recordKey, Kdf kdf) {
        if (suite.commitLen() == 0) {
            throw new IllegalArgumentException(suite.hexId()
                    + " commits natively and carries no commitment field (spec §4.6)");
        }
        return kdf.derive(recordKey, EMPTY_SALT, INFO.clone(), suite.commitLen());
    }

    /**
     * Recomputes the commitment from {@code recordKey} and compares it with the envelope's field
     * in constant time (spec §4.6; docs/09 §3.2 step 6). The recomputed value is erased.
     *
     * @throws IllegalStateException if {@code envelopeCommitment} is not the suite's length
     */
    public static boolean verify(Suite suite, byte[] recordKey, byte[] envelopeCommitment,
            Kdf kdf) {
        // The codec copies exactly commitLen bytes, so a wrong length is the core's bug, not a
        // forged envelope. It is checked first (docs/27 §5.3), before any derivation, and thrown
        // rather than answered: "no match" would surface as COMMITMENT_INVALID, a spec §9 code
        // that blames the ciphertext for an internal fault. The lengths are public, so the check
        // leaks nothing.
        if (envelopeCommitment.length != suite.commitLen()) {
            throw new IllegalStateException("commitment precondition: " + suite.hexId()
                    + " commitments are " + suite.commitLen() + " bytes, got "
                    + envelopeCommitment.length);
        }
        byte[] expected = compute(suite, recordKey, kdf);
        try {
            return MessageDigest.isEqual(expected, envelopeCommitment);
        } finally {
            Arrays.fill(expected, (byte) 0);
        }
    }

    /** The spec §4.6 label, for the harness to assert; a copy. */
    public static byte[] info() {
        return INFO.clone();
    }
}
