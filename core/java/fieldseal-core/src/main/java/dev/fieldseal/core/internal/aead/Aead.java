package dev.fieldseal.core.internal.aead;

import dev.fieldseal.core.internal.registry.Registry;
import dev.fieldseal.core.internal.registry.Suite;
import java.util.Optional;

/**
 * A suite's AEAD, working in place on the envelope (docs/27 §5.1): {@code seal} writes ct‖tag
 * into the pre-sized envelope, and {@code open} reads ct‖tag from it. Nothing here copies the
 * operand.
 */
public sealed interface Aead permits Ff01Aead {

    /**
     * Encrypts {@code plaintext} and writes ct‖tag into {@code envelope} at {@code ctOffset}.
     * {@code envelope} has room for exactly that (the codec sized it).
     */
    void sealInto(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext, byte[] envelope,
            int ctOffset);

    /**
     * Decrypts the {@code ctAndTagLen} bytes of ct‖tag at {@code ctOffset} in {@code envelope}.
     * A failed tag is an {@link Opened.TagFailed}, not an exception: what it becomes is the
     * client's decision, and it becomes {@code TAG_INVALID} only once the commitment has verified
     * (docs/09 §3.2 step 6).
     */
    Opened open(byte[] key, byte[] nonce, byte[] aad, byte[] envelope, int ctOffset,
            int ctAndTagLen);

    /** The outcome of {@link #open}. */
    sealed interface Opened {
        record Plaintext(byte[] bytes) implements Opened {}

        /** The tag did not verify. No plaintext was released (docs/27 §5.1). */
        record TagFailed() implements Opened {}
    }

    /** The AEAD this core performs for {@code suite}, or empty for a suite it has not built. */
    static Optional<Aead> forSuite(Suite suite) {
        return suite.id() == Registry.FF01.id() && suite.implemented()
                ? Optional.of(Ff01Aead.INSTANCE) : Optional.empty();
    }
}
