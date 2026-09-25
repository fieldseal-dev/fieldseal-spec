package dev.fieldseal.core.internal.kdf;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF-SHA-512 (RFC 5869), the KDF of both provisional suites (spec §4.2), written over
 * {@code Mac.getInstance("HmacSHA512")} because JDK 21 has no HKDF of its own (docs/27 §5.2).
 *
 * <p><b>The empty salt.</b> RFC 5869 §2.2 substitutes HashLen (64) zero bytes for an absent salt,
 * and spec §4.6 and §7.3 use one. {@code SecretKeySpec} refuses an empty key, so the substitution
 * is made here, explicitly. HMAC pads its key with zeros to the 128-byte block, so the two are the
 * same key (docs/27 §5.2, confirmed at S2).
 *
 * <p><b>Erasure.</b> The PRK and every expand block are this method's own buffers and are zeroed
 * before it returns (docs/09 §3; docs/27 §5.4). What {@code SecretKeySpec} and {@code Mac} copy
 * internally is out of reach, and docs/27 §5.4 says so.
 */
public final class Hkdf {

    public static final int HASH_LEN = 64;

    /** RFC 5869 §2.3: L &lt;= 255 * HashLen. */
    public static final int MAX_LENGTH = 255 * HASH_LEN;

    private static final String HMAC = "HmacSHA512";

    private Hkdf() {}

    /**
     * {@code HKDF-SHA-512(ikm, salt, info, length)}. {@code salt} may be empty; {@code info} may
     * be any length, since {@code Mac} does not cap it (docs/27 §5.2, G14).
     */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length < 1 || length > MAX_LENGTH) {
            throw new IllegalArgumentException("HKDF length " + length + " is outside 1.."
                    + MAX_LENGTH + " (RFC 5869 §2.3)");
        }
        byte[] macKey = salt.length == 0 ? new byte[HASH_LEN] : salt;
        byte[] prk = mac(macKey).doFinal(ikm);
        try {
            return expand(prk, info, length);
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    private static byte[] expand(byte[] prk, byte[] info, int length) {
        Mac mac = mac(prk);
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        for (int i = 1, off = 0; off < length; i++) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            byte[] next = mac.doFinal();
            Arrays.fill(t, (byte) 0);
            t = next;
            int n = Math.min(t.length, length - off);
            System.arraycopy(t, 0, out, off, n);
            off += n;
        }
        Arrays.fill(t, (byte) 0);
        return out;
    }

    private static Mac mac(byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("every JDK provides " + HMAC, e);
        }
    }
}
