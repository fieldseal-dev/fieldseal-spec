package dev.fieldseal.core.internal.aead;

import dev.fieldseal.core.internal.registry.Registry;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Suite {@code 0xFF01}'s AES-256-GCM over {@code javax.crypto.Cipher} (docs/27 §5.1):
 * {@code AES/GCM/NoPadding}, a 128-bit tag, the AAD before any data.
 *
 * <ul>
 *   <li><b>A new {@code Cipher} every call.</b> Instances are not thread-safe, and SunJCE refuses a
 *       repeated key and IV on an encrypting instance anyway.
 *   <li><b>Decrypt is one {@code doFinal}, never {@code update()}.</b> Through {@code update()},
 *       SunJCE buffers the ciphertext and allocates about 3× the operand; one {@code doFinal}
 *       over the whole of ct‖tag allocates no operand-sized buffer (docs/27 §5.1, §6.3, measured
 *       at S2).
 *   <li><b>A tag failure releases no plaintext.</b> The output array is zeroed and dropped on the
 *       failure path, whatever the provider left in it (docs/27 §5.1).
 * </ul>
 */
final class Ff01Aead implements Aead {

    static final Ff01Aead INSTANCE = new Ff01Aead();

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_BITS = Registry.FF01.tagLen() * 8;

    private Ff01Aead() {}

    @Override
    public void sealInto(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext, byte[] envelope,
            int ctOffset) {
        requireSizes(key, nonce);
        try {
            Cipher c = cipher(Cipher.ENCRYPT_MODE, key, nonce);
            c.updateAAD(aad);
            int written = c.doFinal(plaintext, 0, plaintext.length, envelope, ctOffset);
            if (written != plaintext.length + Registry.FF01.tagLen()) {
                throw new IllegalStateException("GCM wrote " + written + " bytes");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-GCM encryption failed on valid input", e);
        }
    }

    @Override
    public Opened open(byte[] key, byte[] nonce, byte[] aad, byte[] envelope, int ctOffset,
            int ctAndTagLen) {
        requireSizes(key, nonce);
        if (ctAndTagLen < Registry.FF01.tagLen()) {
            throw new IllegalArgumentException("ct‖tag is shorter than the tag");
        }
        byte[] out = new byte[ctAndTagLen - Registry.FF01.tagLen()];
        try {
            Cipher c = cipher(Cipher.DECRYPT_MODE, key, nonce);
            c.updateAAD(aad);
            int written = c.doFinal(envelope, ctOffset, ctAndTagLen, out, 0);
            if (written != out.length) {
                throw new IllegalStateException("GCM released " + written + " bytes");
            }
            return new Opened.Plaintext(out);
        } catch (AEADBadTagException e) {
            Arrays.fill(out, (byte) 0);
            return new Opened.TagFailed();
        } catch (GeneralSecurityException e) {
            Arrays.fill(out, (byte) 0);
            throw new IllegalStateException("AES-256-GCM decryption failed on valid input", e);
        }
    }

    private static Cipher cipher(int mode, byte[] key, byte[] nonce)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(TRANSFORMATION);
        c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
        return c;
    }

    /** Violations are bugs in the core: the KDF and the codec fix both lengths. */
    private static void requireSizes(byte[] key, byte[] nonce) {
        if (key.length != Registry.FF01.keyLen() || nonce.length != Registry.FF01.nonceLen()) {
            throw new IllegalArgumentException("0xFF01 takes a " + Registry.FF01.keyLen()
                    + "-byte key and a " + Registry.FF01.nonceLen() + "-byte nonce");
        }
    }
}
