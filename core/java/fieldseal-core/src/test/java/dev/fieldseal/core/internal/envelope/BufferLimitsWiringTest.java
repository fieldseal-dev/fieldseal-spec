package dev.fieldseal.core.internal.envelope;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.LengthExceededError;
import dev.fieldseal.core.internal.registry.Registry;
import org.junit.jupiter.api.Test;

/**
 * docs/27 §6.2's wiring test, the codec half (S3). Synthetic operands no {@code byte[]} can
 * represent go through the same entry points the public operations will call, and the spec §3.5
 * refusal must come before any read of the operand's content.
 *
 * <p>The other half, zero key-provider calls, needs the client and a provider, which arrive at
 * S4: that stage drives these operands through {@code encrypt}, {@code decrypt} and
 * {@code rotate} with a spy provider. What this half already shows is the order inside the
 * codec, which is where a misplaced guard would sit.
 */
class BufferLimitsWiringTest {

    private static final long TWO_31 = 1L << 31;
    private static final long OVERHEAD = BufferLimits.fixedOverhead(Registry.FF01);

    @Test
    void encryptRefusesA2To31ByteOperandWithoutReadingIt() {
        for (long len : new long[] {TWO_31, 1L << 32, Long.MAX_VALUE}) {
            SyntheticOperand op = SyntheticOperand.strict(len, new byte[0]);
            LengthExceededError e = assertThrows(LengthExceededError.class,
                    () -> BufferLimits.requirePlaintextWithinBound(op));
            assertEquals("LENGTH_EXCEEDED", e.code());
            assertEquals(0, op.reads.size(), "content read before the guard");
        }
    }

    @Test
    void encryptAcceptsExactlyTheBound() {
        SyntheticOperand op = SyntheticOperand.strict(TWO_31 - 1, new byte[0]);
        BufferLimits.requirePlaintextWithinBound(op);
        assertEquals(0, op.reads.size());
    }

    /**
     * An envelope implying a plaintext of 2^31 bytes or more, with a valid {@code 0xFF01} header.
     * Recognition may read bytes 0–2; the guard must fire before the parse copies anything else.
     */
    @Test
    void decryptRefusesAnImpliedPlaintextOf2To31BeforeParsing() {
        for (long implied : new long[] {TWO_31, 1L << 32, Long.MAX_VALUE - OVERHEAD}) {
            SyntheticOperand op = SyntheticOperand.strict(OVERHEAD + implied,
                    SyntheticOperand.ff01Header());
            LengthExceededError e = assertThrows(LengthExceededError.class,
                    () -> EnvelopeCodec.frontOfDecrypt(op));
            assertEquals("LENGTH_EXCEEDED", e.code());
            assertTrue(op.highestOffsetRead() <= 2,
                    "read offset " + op.highestOffsetRead() + " before the guard");
        }
    }

    /**
     * One byte under: the guard lets it through, and the parse then reads the commitment at the
     * far end, which this operand does not serve. So the guard's threshold is exactly the bound,
     * and nothing past recognition ran before it.
     */
    @Test
    void decryptPassesAnImpliedPlaintextOfExactlyTheBound() {
        SyntheticOperand op = SyntheticOperand.strict(OVERHEAD + TWO_31 - 1,
                SyntheticOperand.ff01Header());
        assertThrows(SyntheticOperand.Unserved.class, () -> EnvelopeCodec.frontOfDecrypt(op));

        SyntheticOperand fabricated = SyntheticOperand.fabricating(OVERHEAD + TWO_31 - 1,
                SyntheticOperand.ff01Header());
        DecryptFront.Ready ready = assertInstanceOf(DecryptFront.Ready.class,
                EnvelopeCodec.frontOfDecrypt(fabricated));
        assertEquals(TWO_31 - 1, ready.envelope().plaintextLen());
    }
}
