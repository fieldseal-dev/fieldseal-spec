package dev.fieldseal.core;

/**
 * The read modes of spec §10.3 (docs/27 §4).
 *
 * <p>How each mode behaves is implemented with the client (S4): non-envelope input raises
 * {@code NOT_CIPHERTEXT} in {@link #STRICT} and is returned as-is in the other two, and
 * {@link #READONLY} refuses the ciphertext-producing operations with {@code MODE_VIOLATION}.
 */
public enum ReadMode {
    /** spec §10.3 {@code strict}: the default for production. */
    STRICT,
    /** spec §10.3 {@code permissive}: migration only. */
    PERMISSIVE,
    /** spec §10.3 {@code readonly}: read replicas, analytics jobs, rollback windows. */
    READONLY
}
