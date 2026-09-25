package dev.fieldseal.core.internal.aead;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.internal.registry.Registry;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * {@code 0xFF01}'s AEAD in place (docs/27 §5.1): a round trip at an offset, and a flipped tag,
 * ciphertext or AAD bit giving {@link Aead.Opened.TagFailed} with no plaintext released. The
 * {@code envelope/} vectors, run in the testing module, are the known answers.
 */
class Ff01AeadTest {

    private static final Aead AEAD = Aead.forSuite(Registry.FF01).orElseThrow();
    private static final byte[] KEY = new byte[32];
    private static final byte[] NONCE = new byte[12];
    private static final byte[] AAD = {1, 2, 3};
    private static final int OFFSET = 63;

    static {
        Arrays.fill(KEY, (byte) 0x42);
        Arrays.fill(NONCE, (byte) 0x24);
    }

    private static byte[] sealed(byte[] plaintext) {
        byte[] env = new byte[OFFSET + plaintext.length + 16 + 32];
        AEAD.sealInto(KEY, NONCE, AAD, plaintext, env, OFFSET);
        return env;
    }

    @Test
    void roundTripInPlace() {
        for (byte[] pt : new byte[][] {new byte[0], "hello".getBytes(), new byte[4096]}) {
            byte[] env = sealed(pt);
            Aead.Opened o = AEAD.open(KEY, NONCE, AAD, env, OFFSET, pt.length + 16);
            assertArrayEquals(pt, assertInstanceOf(Aead.Opened.Plaintext.class, o).bytes());
        }
    }

    @Test
    void anyFlippedBitIsTagFailed() {
        byte[] pt = "a plaintext of some length".getBytes();
        int len = pt.length + 16;
        for (int at : new int[] {OFFSET, OFFSET + pt.length - 1, OFFSET + pt.length,
                OFFSET + len - 1}) {
            byte[] env = sealed(pt);
            env[at] ^= 1;
            assertInstanceOf(Aead.Opened.TagFailed.class,
                    AEAD.open(KEY, NONCE, AAD, env, OFFSET, len), "flip at " + at);
        }
        byte[] env = sealed(pt);
        assertInstanceOf(Aead.Opened.TagFailed.class,
                AEAD.open(KEY, NONCE, new byte[] {1, 2, 4}, env, OFFSET, len), "AAD flip");
        byte[] otherKey = KEY.clone();
        otherKey[0] ^= 1;
        assertInstanceOf(Aead.Opened.TagFailed.class,
                AEAD.open(otherKey, NONCE, AAD, env, OFFSET, len), "wrong key");
    }

    @Test
    void wrongSizesAreTheCoresBug() {
        byte[] env = sealed(new byte[1]);
        assertThrows(IllegalArgumentException.class,
                () -> AEAD.open(new byte[16], NONCE, AAD, env, OFFSET, 17));
        assertThrows(IllegalArgumentException.class,
                () -> AEAD.open(KEY, new byte[24], AAD, env, OFFSET, 17));
        assertThrows(IllegalArgumentException.class,
                () -> AEAD.open(KEY, NONCE, AAD, env, OFFSET, 15));
    }

    /**
     * docs/27 §5.1: decrypt is one {@code doFinal}, never {@code update()}, which buffers about
     * 3× the operand (§6.3, measured at S2). {@code open} allocates its output; beyond that, it
     * must allocate less than 1 MiB over a 16 MiB operand.
     */
    @Test
    void openDoesNotBufferTheOperand() {
        int mib = 1 << 20;
        int size = 16 * mib;
        byte[] env = sealed(new byte[size]);
        com.sun.management.ThreadMXBean mx = (com.sun.management.ThreadMXBean)
                java.lang.management.ManagementFactory.getThreadMXBean();
        AEAD.open(KEY, NONCE, AAD, sealed(new byte[mib]), OFFSET, mib + 16); // warm-up
        long before = mx.getCurrentThreadAllocatedBytes();
        Aead.Opened o = AEAD.open(KEY, NONCE, AAD, env, OFFSET, size + 16);
        long allocated = mx.getCurrentThreadAllocatedBytes() - before;
        assertInstanceOf(Aead.Opened.Plaintext.class, o);
        assertTrue(allocated >= size, "the counter missed the output array: " + allocated);
        assertTrue(allocated < size + mib, "open allocated " + allocated + " for a " + size
                + "-byte plaintext");
    }

    @Test
    void onlyFf01IsBuilt() {
        assertTrue(Aead.forSuite(Registry.FF02).isEmpty());
    }
}
