package dev.fieldseal.core.internal.envelope;

import dev.fieldseal.core.internal.registry.Suite;

/**
 * A recognized envelope, parsed without copying its ciphertext (docs/27 §6.3). The small fixed
 * fields are copied, because the KDF and the key provider need arrays; ct‖tag stays in the
 * operand, located by {@link #ctOffset} and {@link #ctAndTagLen}.
 *
 * <p>The arrays are this record's own copies, and the record is internal: nothing outside the
 * core receives one.
 */
public record ParsedEnvelope(Suite suite, byte[] keyId, byte[] msgSeed, byte[] nonce,
        byte[] commitment, long ctOffset, long ctAndTagLen) {

    /** The plaintext length this envelope implies; within spec §3.5's bound once parsed. */
    public long plaintextLen() {
        return ctAndTagLen - suite.tagLen();
    }
}
