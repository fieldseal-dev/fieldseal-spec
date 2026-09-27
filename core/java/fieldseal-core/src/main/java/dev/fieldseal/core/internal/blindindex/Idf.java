package dev.fieldseal.core.internal.blindindex;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * spec §7.2's {@code truncate(IDF(index_key, normalized), b)}, for the two IDFs of spec §7.3.
 *
 * <p><b>The HKDF is injected.</b> spec §7.3 derives the Argon2id salt with HKDF-SHA-512, and
 * docs/09 §1 forbids {@code blindindex} → {@code kdf}. The maintainer chose injection for {@code
 * commitment} (docs/07 §7, 2026-09-25), and this module does the same (docs/27 §8, S4a).
 *
 * <p><b>Erasure</b> (docs/27 §5.4): the untruncated output, the Argon2id salt, and both
 * BouncyCastle salt copies this code can reach ({@code Builder.clear()} and {@code
 * Argon2Parameters.clear()}). The copy BouncyCastle takes inside every {@code generateBytes} is out
 * of reach, and docs/27 §5.4 says so.
 */
public final class Idf {

    /** spec §7.3's fixed Argon2id parameters, which "MUST NOT vary". */
    public static final int ARGON2_MIN_TIME_COST = 3;
    public static final int ARGON2_MIN_MEMORY_KIB = 32768;
    static final int ARGON2_PARALLELISM = 1;
    static final int OUTPUT_LEN = 64;
    static final int SALT_LEN = 16;

    private static final byte[] SALT_INFO =
            "fieldseal-argon2-salt-v1".getBytes(StandardCharsets.US_ASCII);
    private static final String HMAC = "HmacSHA512";

    /** HKDF-SHA-512, injected (see the class comment). */
    @FunctionalInterface
    public interface Kdf {
        byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length);
    }

    /** Which IDF, with its cost where it has one. */
    public sealed interface Params {
        record HmacSha512() implements Params {}

        record Argon2id(int timeCost, int memoryKib) implements Params {}
    }

    private Idf() {}

    /**
     * {@code truncate(IDF(indexKey, normalized), bits)}. Neither argument is kept or written;
     * everything this derives along the way is erased before it returns.
     */
    public static byte[] blindIndex(Params p, byte[] indexKey, byte[] normalized, int bits,
            Kdf kdf) {
        byte[] raw = raw(p, indexKey, normalized, kdf);
        try {
            return truncate(raw, bits);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    /**
     * {@code IDF(indexKey, normalized)}, untruncated: 64 bytes. The caller erases it. Public for
     * the vector harness, which asserts {@code raw} apart from {@code index} (docs/08 §4.4).
     */
    public static byte[] raw(Params p, byte[] indexKey, byte[] normalized, Kdf kdf) {
        return switch (p) {
            case Params.HmacSha512 h -> hmacSha512(indexKey, normalized);
            case Params.Argon2id a -> argon2id(indexKey, normalized, a.timeCost(), a.memoryKib(),
                    kdf);
        };
    }

    /**
     * spec §7.3's salt, {@code HKDF-SHA-512(index_key, "", "fieldseal-argon2-salt-v1", 16)}. The
     * caller erases it. Public so the harness can tell an HKDF-step bug from an Argon2-step one
     * (docs/08 §4.4).
     */
    public static byte[] argon2Salt(byte[] indexKey, Kdf kdf) {
        return kdf.derive(indexKey, new byte[0], SALT_INFO.clone(), SALT_LEN);
    }

    /**
     * spec §7.2, bit-exactly: the first {@code ⌈b/8⌉} bytes, with the trailing {@code 8⌈b/8⌉ − b}
     * bits of the last one zeroed, bits numbered MSB-first.
     */
    public static byte[] truncate(byte[] raw, int bits) {
        if (bits < 1 || bits > raw.length * 8) {
            throw new IllegalArgumentException("truncation to " + bits + " bits of a "
                    + raw.length + "-byte value");
        }
        byte[] out = Arrays.copyOf(raw, (bits + 7) / 8);
        int spare = out.length * 8 - bits;
        out[out.length - 1] &= (byte) (0xFF << spare);
        return out;
    }

    /**
     * Refuses a cost BouncyCastle would refuse at derivation time, so that the refusal happens
     * when the index is declared (docs/09 §12). Its memory ceiling is a system property,
     * {@code org.bouncycastle.argon2.max_memory_exp}, 2^24 KiB by default (docs/27 §2).
     *
     * @return null if accepted, or the reason
     */
    public static String argon2CostRefusal(int timeCost, int memoryKib) {
        try {
            Argon2Parameters.Builder b = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withIterations(timeCost).withMemoryAsKB(memoryKib);
            b.clear();
            return null;
        } catch (IllegalArgumentException e) {
            return "BouncyCastle refuses t = " + timeCost + ", m = " + memoryKib + " KiB: "
                    + e.getMessage();
        }
    }

    private static byte[] hmacSha512(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("every JDK provides " + HMAC, e);
        }
    }

    /** spec §7.3's invocation: the index key enters only through the salt; no K, no X. */
    private static byte[] argon2id(byte[] indexKey, byte[] password, int t, int m, Kdf kdf) {
        byte[] salt = argon2Salt(indexKey, kdf);
        Argon2Parameters.Builder builder = null;
        Argon2Parameters params = null;
        try {
            builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(t)
                    .withMemoryAsKB(m)
                    .withParallelism(ARGON2_PARALLELISM)
                    .withSalt(salt);
            params = builder.build();
            Argon2BytesGenerator g = new Argon2BytesGenerator();
            g.init(params);
            byte[] out = new byte[OUTPUT_LEN];
            g.generateBytes(password, out);
            return out;
        } finally {
            Arrays.fill(salt, (byte) 0);
            if (builder != null) {
                builder.clear();
            }
            if (params != null) {
                params.clear();
            }
        }
    }
}
