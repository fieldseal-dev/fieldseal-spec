package dev.fieldseal.core.internal.envelope;

import dev.fieldseal.core.internal.registry.Suite;

/**
 * spec §3.4's three recognition outcomes. Recognition is a pure function of the registry: it
 * never consults the allow-list, never decrypts, and never infers a suite by trial.
 */
public sealed interface Recognition {

    /** {@code fmt_ver} 0x01, a registered {@code suite_id}, and at least that suite's minimum. */
    record Envelope(Suite suite) implements Recognition {}

    /**
     * {@code fmt_ver} 0x02 at 111 bytes or more (spec §3.1, §3.4). Not an envelope to
     * {@code is_ciphertext}; {@code UNKNOWN_FORMAT_VERSION} to {@code decrypt}, in every mode.
     */
    record ReservedVersion() implements Recognition {}

    /** Anything else: {@code NOT_CIPHERTEXT} or pass-through, by read mode (spec §10.3). */
    record NonEnvelope() implements Recognition {}

    ReservedVersion RESERVED_VERSION = new ReservedVersion();
    NonEnvelope NON_ENVELOPE = new NonEnvelope();
}
