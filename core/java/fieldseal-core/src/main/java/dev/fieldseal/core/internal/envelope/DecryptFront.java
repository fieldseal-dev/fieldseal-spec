package dev.fieldseal.core.internal.envelope;

/**
 * What the front of {@code decrypt} and {@code rotate} yields (docs/09 §3.2 step 2; docs/27
 * §6.2): a parsed envelope within spec §3.5's bound, or one of the two outcomes the caller maps
 * by operation and read mode (spec §3.4, §10.3). That mapping belongs to the client, which is the
 * only module that knows the mode.
 */
public sealed interface DecryptFront {

    record Ready(ParsedEnvelope envelope) implements DecryptFront {}

    /** {@code UNKNOWN_FORMAT_VERSION}, in every mode and on both operations. */
    record ReservedVersion() implements DecryptFront {}

    /** {@code decrypt}: NOT_CIPHERTEXT in strict, pass-through otherwise. {@code rotate}: refused. */
    record NonEnvelope() implements DecryptFront {}
}
