package dev.fieldseal.core.capabilities;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 5869 HKDF-SHA-512 over {@code javax.crypto.Mac}: the construction docs/27 §5.2 commits the
 * core to at the JDK 21 floor, written here only to audit it against {@code kdf/} and
 * {@code commitment/}. The core's own HKDF is S4's, in {@code internal/kdf}.
 */
final class HkdfOverMac {

    static final int HASH_LEN = 64;

    private HkdfOverMac() {}

    /**
     * {@code salt} may be empty. RFC 5869 §2.2 then uses HashLen zero bytes, and so does this
     * method, because {@code SecretKeySpec} refuses an empty key (docs/27 §5.2).
     */
    static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length)
            throws GeneralSecurityException {
        byte[] prk = extract(salt.length == 0 ? new byte[HASH_LEN] : salt, ikm);
        try {
            return expand(prk, info, length);
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    static byte[] extract(byte[] macKey, byte[] ikm) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(macKey, "HmacSHA512"));
        return mac.doFinal(ikm);
    }

    private static byte[] expand(byte[] prk, byte[] info, int length)
            throws GeneralSecurityException {
        if (length < 1 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("HKDF length " + length);
        }
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(prk, "HmacSHA512"));
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        for (int i = 1, off = 0; off < length; i++) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            int n = Math.min(t.length, length - off);
            System.arraycopy(t, 0, out, off, n);
            off += n;
        }
        Arrays.fill(t, (byte) 0);
        return out;
    }
}
