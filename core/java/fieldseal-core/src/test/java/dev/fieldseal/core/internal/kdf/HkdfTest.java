package dev.fieldseal.core.internal.kdf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/**
 * The core's HKDF-SHA-512 (docs/27 §5.2). The {@code kdf/} and {@code commitment/} vectors are
 * the known answers (the testing module runs them); this class pins what they cannot isolate:
 * RFC 5869's two steps written out by hand, the empty-salt substitution, and the length bounds.
 */
class HkdfTest {

    private static final byte[] IKM = bytes(32, 0x0b);
    private static final byte[] SALT = bytes(13, 0x01);
    private static final byte[] INFO = bytes(10, 0xf0);

    @Test
    void matchesRfc5869StepsWrittenOut() throws GeneralSecurityException {
        byte[] prk = hmac(SALT, IKM);
        byte[] t1 = hmac(prk, concat(INFO, new byte[] {1}));
        byte[] t2 = hmac(prk, concat(t1, INFO, new byte[] {2}));
        byte[] okm = Hkdf.derive(IKM, SALT, INFO, 100);
        assertArrayEquals(concat(t1, Arrays.copyOf(t2, 36)), okm);
    }

    /**
     * RFC 5869 §2.2: an absent salt is HashLen zero bytes. SecretKeySpec refuses an empty key,
     * which is the trap docs/27 §5.2 names; the empty salt must behave as the 64 zero bytes.
     */
    @Test
    void emptySaltIsHashLenZeroBytes() {
        assertArrayEquals(Hkdf.derive(IKM, new byte[Hkdf.HASH_LEN], INFO, 32),
                Hkdf.derive(IKM, new byte[0], INFO, 32));
        assertFalse(Arrays.equals(Hkdf.derive(IKM, new byte[] {1}, INFO, 32),
                Hkdf.derive(IKM, new byte[0], INFO, 32)));
    }

    @Test
    void shorterOutputIsAPrefix() {
        byte[] long_ = Hkdf.derive(IKM, SALT, INFO, 200);
        for (int n : new int[] {1, 32, 63, 64, 65, 128, 199}) {
            assertArrayEquals(Arrays.copyOf(long_, n), Hkdf.derive(IKM, SALT, INFO, n), "L=" + n);
        }
    }

    @Test
    void lengthBoundsAreRfc5869s() {
        assertEquals(Hkdf.MAX_LENGTH, Hkdf.derive(IKM, SALT, INFO, Hkdf.MAX_LENGTH).length);
        assertThrows(IllegalArgumentException.class, () -> Hkdf.derive(IKM, SALT, INFO, 0));
        assertThrows(IllegalArgumentException.class,
                () -> Hkdf.derive(IKM, SALT, INFO, Hkdf.MAX_LENGTH + 1));
    }

    /** Node caps {@code info} at 1024 bytes (spec §6.1, G14); {@code Mac} does not. */
    @Test
    void infoIsNotCapped() {
        assertEquals(32, Hkdf.derive(IKM, SALT, new byte[64 * 1024], 32).length);
    }

    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        return mac.doFinal(data);
    }

    private static byte[] bytes(int n, int value) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) value);
        return b;
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }
}
