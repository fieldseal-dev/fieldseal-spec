package dev.fieldseal.core;

import static dev.fieldseal.core.Fixtures.builder;
import static dev.fieldseal.core.Fixtures.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.FieldsealError;
import dev.fieldseal.core.internal.envelope.BufferLimits;
import dev.fieldseal.core.internal.envelope.SyntheticOperand;
import dev.fieldseal.core.internal.registry.Registry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * The {@code api-boundary-order} pin (docs/14 §4, D-04) and this core's {@code decrypt-order}, as
 * observed precedence: each case violates two or more checks at once and asserts which code wins,
 * and each asserts the provider was not reached when the winner precedes key acquisition.
 *
 * <pre>
 * encrypt: MODE_VIOLATION → SUITE_PROVISIONAL → operand (null: INVALID_ARGUMENT; LENGTH_EXCEEDED)
 *          → context (INVALID_ARGUMENT) → key acquisition (KEY_UNAVAILABLE)
 * rotate:  MODE_VIOLATION → SUITE_PROVISIONAL → operand (null) → recognition (UNKNOWN_FORMAT_VERSION,
 *          NOT_CIPHERTEXT in every mode) → LENGTH_EXCEEDED → then decrypt's order
 * decrypt: operand (null) → recognition → LENGTH_EXCEEDED → SUITE_NOT_ALLOWED → context
 *          → KEY_UNAVAILABLE → per candidate: commitment, then tag → COMMITMENT_INVALID
 * </pre>
 */
class ApiBoundaryOrderTest {

    private static final long OVER = 1L << 31;
    private static final byte[] PLAIN = {'x'};
    private static final byte[] RESERVED = reserved();

    private static byte[] reserved() {
        byte[] r = new byte[111];
        r[0] = 0x02;
        return r;
    }

    private static SyntheticOperand overlongPlaintext() {
        return SyntheticOperand.strict(OVER, new byte[0]);
    }

    private static SyntheticOperand overlongEnvelope() {
        return SyntheticOperand.strict(BufferLimits.fixedOverhead(Registry.FF01) + OVER,
                SyntheticOperand.ff01Header());
    }

    private static void expect(String code, Fixtures.SpyProvider p, boolean providerReached,
            Executable call) {
        FieldsealError e = assertThrows(FieldsealError.class, call);
        assertEquals(code, e.code(), e.getMessage());
        assertEquals(providerReached, !p.calls.isEmpty(), "provider reached: " + p.calls);
        p.calls.clear();
    }

    @Test
    void encrypt() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        Fieldseal readonlyUnarmed = builder(p).readMode(ReadMode.READONLY)
                .armProvisionalSuites(false).build();
        Fieldseal unarmed = builder(p).armProvisionalSuites(false).build();
        Fieldseal fs = builder(p).build();

        expect("MODE_VIOLATION", p, false, () -> readonlyUnarmed.encrypt((byte[]) null, null));
        expect("MODE_VIOLATION", p, false, () -> readonlyUnarmed.encrypt(overlongPlaintext(), null));
        expect("SUITE_PROVISIONAL", p, false, () -> unarmed.encrypt(overlongPlaintext(), null));
        expect("SUITE_PROVISIONAL", p, false, () -> unarmed.encrypt((byte[]) null, null));
        expect("LENGTH_EXCEEDED", p, false, () -> fs.encrypt(overlongPlaintext(), null));
        FieldsealError nullOperand = assertThrows(FieldsealError.class,
                () -> fs.encrypt((byte[]) null, null));
        assertEquals("INVALID_ARGUMENT", nullOperand.code());
        assertTrue(nullOperand.getMessage().contains("plaintext"), "the operand, not the context");
        expect("INVALID_ARGUMENT", p, false, () -> fs.encrypt(PLAIN, null));
        p.failWith = new IllegalStateException();
        expect("KEY_UNAVAILABLE", p, true, () -> fs.encrypt(PLAIN, ctx()));
    }

    @Test
    void rotate() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        Fieldseal readonlyUnarmed = builder(p).readMode(ReadMode.READONLY)
                .armProvisionalSuites(false).build();
        Fieldseal unarmed = builder(p).armProvisionalSuites(false).build();
        Fieldseal permissive = builder(p).readMode(ReadMode.PERMISSIVE).build();

        expect("MODE_VIOLATION", p, false, () -> readonlyUnarmed.rotate(RESERVED, null));
        expect("SUITE_PROVISIONAL", p, false, () -> unarmed.rotate(RESERVED, null));
        expect("SUITE_PROVISIONAL", p, false, () -> unarmed.rotate(overlongEnvelope(), null));
        expect("UNKNOWN_FORMAT_VERSION", p, false, () -> permissive.rotate(RESERVED, null));
        expect("NOT_CIPHERTEXT", p, false, () -> permissive.rotate(PLAIN, null));
        expect("LENGTH_EXCEEDED", p, false, () -> permissive.rotate(overlongEnvelope(), null));
    }

    @Test
    void decrypt() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        Fieldseal fs = builder(p).build();
        byte[] env = fs.encrypt(PLAIN, ctx());
        p.calls.clear();
        byte[] ff02 = java.util.Arrays.copyOf(SyntheticOperand.header(Registry.FF02),
                (int) BufferLimits.fixedOverhead(Registry.FF02));

        expect("UNKNOWN_FORMAT_VERSION", p, false, () -> fs.decrypt(RESERVED, null));
        expect("NOT_CIPHERTEXT", p, false, () -> fs.decrypt(PLAIN, null));
        expect("LENGTH_EXCEEDED", p, false, () -> fs.decrypt(overlongEnvelope(), null));
        expect("SUITE_NOT_ALLOWED", p, false, () -> fs.decrypt(ff02, null));
        expect("INVALID_ARGUMENT", p, false, () -> fs.decrypt(env, null));
        byte[] otherKeyId = env.clone();
        otherKeyId[3] ^= 1;
        expect("KEY_UNAVAILABLE", p, true, () -> fs.decrypt(otherKeyId, ctx()));
        byte[] both = env.clone();
        both[63] ^= 1;
        expect("COMMITMENT_INVALID", p, true,
                () -> fs.decrypt(both, ctx().withTenant(null)));
        expect("TAG_INVALID", p, true, () -> fs.decrypt(both, ctx()));
    }

    /** The shipped vectors pair two of these, and this core agrees with them. */
    @Test
    void readonlyAndUnarmedTogetherIsModeViolation() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        expect("MODE_VIOLATION", p, false, () -> builder(p).readMode(ReadMode.READONLY)
                .armProvisionalSuites(false).build().encrypt(PLAIN, ctx()));
    }
}
