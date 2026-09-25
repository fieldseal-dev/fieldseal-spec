package dev.fieldseal.core;

import static dev.fieldseal.core.Fixtures.builder;
import static dev.fieldseal.core.Fixtures.ctx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.LengthExceededError;
import dev.fieldseal.core.internal.envelope.BufferLimits;
import dev.fieldseal.core.internal.envelope.SyntheticOperand;
import dev.fieldseal.core.internal.registry.Registry;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * docs/27 §6.2's wiring test, the provider half (S4b; the codec half is {@code
 * BufferLimitsWiringTest}). Synthetic operands no {@code byte[]} can represent go through the
 * same package-private pipeline every public {@code encrypt}, {@code decrypt} and {@code rotate}
 * enters. Each must be refused with {@code LENGTH_EXCEEDED}, with zero key-provider calls and no
 * content read (past the three recognition bytes, for an envelope). This is what the {@code
 * spec/3.5/length-bound} entries' {@code basis: "seam"} rests on (docs/14 §4).
 */
class SeamWiringTest {

    private static final long TWO_31 = 1L << 31;
    private static final long OVERHEAD = BufferLimits.fixedOverhead(Registry.FF01);
    private static final List<Long> PLAINTEXT_LENGTHS = List.of(TWO_31, 1L << 32, Long.MAX_VALUE);
    private static final List<Long> IMPLIED_LENGTHS =
            List.of(TWO_31, 1L << 32, Long.MAX_VALUE - OVERHEAD);

    @Test
    void encryptRefusesBeforeAnyProviderCallOrRead() {
        for (long len : PLAINTEXT_LENGTHS) {
            Fixtures.SpyProvider p = new Fixtures.SpyProvider();
            SyntheticOperand op = SyntheticOperand.strict(len, new byte[0]);
            LengthExceededError e = assertThrows(LengthExceededError.class,
                    () -> builder(p).build().encrypt(op, ctx()));
            assertEquals("LENGTH_EXCEEDED", e.code());
            assertEquals(List.of(), p.calls, "provider called before the guard, length " + len);
            assertEquals(0, op.reads.size(), "operand read before the guard, length " + len);
        }
    }

    @Test
    void decryptAndRotateRefuseBeforeAnyProviderCallOrReadPastRecognition() {
        for (long implied : IMPLIED_LENGTHS) {
            for (String operation : List.of("decrypt", "rotate")) {
                Fixtures.SpyProvider p = new Fixtures.SpyProvider();
                Fieldseal fs = builder(p).build();
                SyntheticOperand op = SyntheticOperand.strict(OVERHEAD + implied,
                        SyntheticOperand.ff01Header());
                assertThrows(LengthExceededError.class, () -> {
                    if (operation.equals("decrypt")) {
                        fs.decrypt(op, ctx());
                    } else {
                        fs.rotate(op, ctx());
                    }
                });
                assertEquals(List.of(), p.calls, operation + ": provider called, implied "
                        + implied);
                assertTrue(op.highestOffsetRead() <= 2, operation + ": read offset "
                        + op.highestOffsetRead());
            }
        }
    }
}
