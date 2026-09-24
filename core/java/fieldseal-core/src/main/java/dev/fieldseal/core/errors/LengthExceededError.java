package dev.fieldseal.core.errors;

/**
 * spec §9: a plaintext exceeds the spec §3.5 bound of 2<sup>31</sup>−1 bytes, on encrypt or as
 * implied by an envelope on decrypt. Never the platform's error in its place (docs/27 §6.2).
 */
public final class LengthExceededError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    /**
     * @param what {@code "plaintext"} or {@code "implied plaintext"}
     * @param length the offending length. A length is not plaintext; the envelope's own length
     *     is public, and the implied length follows from it.
     */
    public LengthExceededError(String what, long length) {
        super(what + " of " + length + " bytes exceeds the spec §3.5 bound of 2^31-1 bytes");
    }

    @Override
    public String code() {
        return "LENGTH_EXCEEDED";
    }
}
