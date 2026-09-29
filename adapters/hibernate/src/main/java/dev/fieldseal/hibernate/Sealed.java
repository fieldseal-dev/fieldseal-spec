package dev.fieldseal.hibernate;

/**
 * An encrypted attribute's value as the listener leaves it in a state array: the plaintext the
 * entity holds, and the envelope the statement binds (docs/29 §2.1). Only the listener makes one,
 * so a value that reaches {@link EncryptedType#nullSafeSet} unsealed did not come through it.
 *
 * <p>The state array is also Hibernate's dirty-checking snapshot after the statement runs, which
 * is why the plaintext travels with the envelope: {@link EncryptedType#equals} compares on it.
 */
final class Sealed {
    final ColumnSpec spec;
    final Object plaintext;
    private final byte[] envelope;

    Sealed(ColumnSpec spec, Object plaintext, byte[] envelope) {
        this.spec = spec;
        this.plaintext = plaintext;
        this.envelope = envelope;
    }

    byte[] envelope() {
        return envelope.clone();
    }

    @Override
    public String toString() {
        // Never the plaintext: a state array can reach a log.
        return "Sealed[" + spec.label + ", " + envelope.length + " bytes]";
    }
}
