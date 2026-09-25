package dev.fieldseal.core.keyprovider;

/**
 * The seam between the envelope provider and a KMS (docs/09 §8.2): {@code wrap(dek)} and
 * {@code unwrap(blob)}. Cloud SDKs stay out of the core; a deployment implements this over
 * whichever it uses.
 *
 * <p>The envelope provider calls {@link #unwrap} only from {@code warm}, never on the value path,
 * so an implementation may do network I/O. What {@code unwrap} returns is copied into the core's
 * cache and not written to; the implementation may erase its own array after the call returns.
 */
public interface Wrapper {

    /** Wraps a DEK under the KMS key. Used by provisioning, not by the core's value path. */
    byte[] wrap(byte[] dek);

    /** Unwraps a blob {@link #wrap} produced. May block on the KMS. */
    byte[] unwrap(byte[] blob);
}
