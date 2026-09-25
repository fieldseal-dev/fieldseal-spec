package dev.fieldseal.core.internal.commitment;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.internal.registry.Registry;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * spec §4.6 over an injected KDF. A recording KDF shows exactly what the construction asks of
 * the suite's KDF; the real HKDF is exercised by the {@code commitment/} vectors in the testing
 * module, and this module does not depend on {@code kdf} (docs/09 §1).
 */
class CommitmentTest {

    private record Call(byte[] ikm, byte[] salt, byte[] info, int length) {}

    /** Records each call and returns {@code length} bytes of the ikm's first byte. */
    private static final class RecordingKdf implements Commitment.Kdf {
        final List<Call> calls = new ArrayList<>();

        @Override
        public byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
            calls.add(new Call(ikm, salt, info, length));
            byte[] out = new byte[length];
            java.util.Arrays.fill(out, ikm[0]);
            return out;
        }
    }

    @Test
    void asksTheKdfForSpec46sDerivation() {
        RecordingKdf kdf = new RecordingKdf();
        byte[] rk = {5, 6, 7};
        Commitment.compute(Registry.FF01, rk, kdf);
        Call c = kdf.calls.get(0);
        assertArrayEquals(rk, c.ikm());
        assertEquals(0, c.salt().length, "salt is empty");
        assertEquals("fieldseal-commit-v1", new String(c.info(), StandardCharsets.US_ASCII));
        assertEquals(19, c.info().length);
        assertEquals(32, c.length());
    }

    @Test
    void verifyMatchesOnlyTheRecomputedValue() {
        RecordingKdf kdf = new RecordingKdf();
        byte[] good = Commitment.compute(Registry.FF01, new byte[] {9}, kdf);
        assertTrue(Commitment.verify(Registry.FF01, new byte[] {9}, good, kdf));
        byte[] flipped = good.clone();
        flipped[31] ^= 1;
        assertFalse(Commitment.verify(Registry.FF01, new byte[] {9}, flipped, kdf));
        assertFalse(Commitment.verify(Registry.FF01, new byte[] {8}, good, kdf));
    }

    @Test
    void aWrongLengthIsNoMatch() {
        RecordingKdf kdf = new RecordingKdf();
        byte[] good = Commitment.compute(Registry.FF01, new byte[] {9}, kdf);
        assertFalse(Commitment.verify(Registry.FF01, new byte[] {9},
                java.util.Arrays.copyOf(good, 31), kdf));
        assertFalse(Commitment.verify(Registry.FF01, new byte[] {9},
                java.util.Arrays.copyOf(good, 33), kdf));
        assertFalse(Commitment.verify(Registry.FF01, new byte[] {9}, new byte[0], kdf));
    }

    /** A caller that mutates the label it was given must not change the next commitment. */
    @Test
    void theLabelIsNotShared() {
        Commitment.Kdf mutating = (ikm, salt, info, len) -> {
            info[0] = 'X';
            return new byte[len];
        };
        Commitment.compute(Registry.FF01, new byte[] {1}, mutating);
        assertEquals("fieldseal-commit-v1",
                new String(Commitment.info(), StandardCharsets.US_ASCII));
    }
}
