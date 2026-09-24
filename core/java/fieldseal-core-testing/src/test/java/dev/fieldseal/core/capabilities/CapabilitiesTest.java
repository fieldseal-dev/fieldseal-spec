package dev.fieldseal.core.capabilities;

import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.capabilities.SuiteFiles.slug;
import static dev.fieldseal.core.capabilities.SuiteFiles.vectors;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * docs/27 §8 stage S2, the capability audit: every platform and library claim docs/27 marks
 * [VERIFY], checked on this toolchain against the pinned vectors. This class is the stage's exit
 * gate. It exercises the JDK and BouncyCastle directly; nothing here is core code, which starts
 * at S3. Each result is recorded in docs/07 §7 (2026-09-24) and in docs/27 where the claim sits.
 */
class CapabilitiesTest {

    private static final int HEADER_LEN = 51;
    private static final int NONCE_LEN = 12;
    private static final int TAG_LEN = 16;
    private static final int COMMIT_LEN = 32;
    /** docs/27 §5.1: ciphertext starts after the header and the nonce. */
    private static final int CT_OFFSET = HEADER_LEN + NONCE_LEN;

    private static final byte[] COMMIT_INFO = ascii("fieldseal-commit-v1");
    private static final byte[] ARGON2_SALT_INFO = ascii("fieldseal-argon2-salt-v1");

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static Cipher gcm(int mode, byte[] key, byte[] nonce, byte[] aad)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LEN * 8, nonce));
        c.updateAAD(aad);
        return c;
    }

    /** docs/27 §5.1 and §5.2: AES-256-GCM through JCA at the documented offsets. */
    @Nested
    class Gcm {

        /**
         * An envelope vector's fields. The decrypt and tag-failure tests read only these, so
         * that they stand on their own: a regression on the encrypt side does not hide them.
         */
        private record Parts(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext,
                byte[] expected) {
            int ctAndTag() {
                return expected.length - CT_OFFSET - COMMIT_LEN;
            }
        }

        private static Parts parts(JsonNode v) {
            JsonNode exp = v.path("expected");
            byte[] expected = hex(exp.path("envelope"));
            assertEquals(exp.path("envelope_bytes").asInt(), expected.length);
            return new Parts(hex(v.path("intermediates").path("record_key")), hex(v.path("nonce")),
                    hex(exp.path("aad")), hex(v.path("plaintext")), expected);
        }

        private static Parts parts(String slug) {
            return parts(vectors("envelope/ff01.json").stream()
                    .filter(v -> slug(v).equals(slug)).findFirst().orElseThrow());
        }

        /** The envelope built from the vector's fields, with ct‖tag written at 63. */
        private byte[] build(JsonNode v, Parts p) throws GeneralSecurityException {
            // The header from the vector's fields, never copied from the expected envelope.
            byte[] env = new byte[p.expected().length];
            env[0] = 0x01;
            int suite = Integer.decode(v.path("suite_id").asText());
            env[1] = (byte) (suite >>> 8);
            env[2] = (byte) suite;
            System.arraycopy(hex(v.path("key_id")), 0, env, 3, 16);
            System.arraycopy(hex(v.path("msg_seed")), 0, env, 19, 32);
            System.arraycopy(p.nonce(), 0, env, HEADER_LEN, NONCE_LEN);

            // One doFinal writes ct‖tag straight into the pre-sized envelope (docs/27 §5.1).
            int written = gcm(Cipher.ENCRYPT_MODE, p.key(), p.nonce(), p.aad())
                    .doFinal(p.plaintext(), 0, p.plaintext().length, env, CT_OFFSET);
            assertEquals(p.plaintext().length + TAG_LEN, written);
            byte[] commitment = HkdfOverMac.derive(p.key(), new byte[0], COMMIT_INFO, COMMIT_LEN);
            System.arraycopy(commitment, 0, env, CT_OFFSET + written, COMMIT_LEN);
            return env;
        }

        @TestFactory
        Stream<DynamicTest> encryptWritesTheEnvelopeAtOffset63() {
            return vectors("envelope/ff01.json").stream().map(v -> DynamicTest.dynamicTest(slug(v),
                    () -> {
                        Parts p = parts(v);
                        assertEquals(hex(p.expected()), hex(build(v, p)));
                    }));
        }

        @TestFactory
        Stream<DynamicTest> decryptReadsCtAndTagInPlaceFromOffset63() {
            return vectors("envelope/ff01.json").stream().map(v -> DynamicTest.dynamicTest(slug(v),
                    () -> {
                        Parts p = parts(v);
                        byte[] out = new byte[p.ctAndTag() - TAG_LEN];
                        int n = gcm(Cipher.DECRYPT_MODE, p.key(), p.nonce(), p.aad())
                                .doFinal(p.expected(), CT_OFFSET, p.ctAndTag(), out, 0);
                        assertEquals(p.plaintext().length, n);
                        assertArrayEquals(p.plaintext(), out);
                    }));
        }

        /** docs/27 §4 maps exactly this class to TAG_INVALID. */
        @Test
        void aTagFailureIsExactlyAeadBadTagException() {
            Parts b = parts("basic-roundtrip");
            int ctAndTag = b.ctAndTag();

            byte[] tagFlipped = b.expected().clone();
            tagFlipped[CT_OFFSET + ctAndTag - 1] ^= 0x01;
            byte[] ctFlipped = b.expected().clone();
            ctFlipped[CT_OFFSET] ^= (byte) 0x80;
            byte[] aadFlipped = b.aad().clone();
            aadFlipped[aadFlipped.length - 1] ^= 0x01;

            List<Throwable> failures = new ArrayList<>();
            for (byte[][] c : new byte[][][] {
                    {tagFlipped, b.aad()}, {ctFlipped, b.aad()}, {b.expected(), aadFlipped}}) {
                failures.add(assertThrows(GeneralSecurityException.class,
                        () -> gcm(Cipher.DECRYPT_MODE, b.key(), b.nonce(), c[1])
                                .doFinal(c[0], CT_OFFSET, ctAndTag, new byte[ctAndTag], 0)));
            }
            failures.forEach(f -> assertEquals(AEADBadTagException.class, f.getClass(),
                    () -> "not exactly AEADBadTagException: " + f));
        }

        /**
         * GcmAllocation finds that a one-shot decrypt does not buffer the operand, so what does
         * the caller's output array hold after a tag failure? The one property the core relies
         * on (docs/27 §5.1) is that it is not the plaintext; that is what this asserts. What the
         * range does hold is the provider's business (SunJCE on Temurin 21 zero-fills it, and
         * does not leave it as it was), so it is printed, not pinned: the core discards the
         * array and assumes nothing about its contents.
         */
        @Test
        void aTagFailureLeavesNoPlaintextInTheOutput() {
            Parts b = parts("one-kib");
            int ctAndTag = b.ctAndTag();
            byte[] tagFlipped = b.expected().clone();
            tagFlipped[CT_OFFSET + ctAndTag - 1] ^= 0x01;
            byte[] out = new byte[ctAndTag - TAG_LEN];
            java.util.Arrays.fill(out, (byte) 0x5A);
            assertThrows(AEADBadTagException.class,
                    () -> gcm(Cipher.DECRYPT_MODE, b.key(), b.nonce(), b.aad())
                            .doFinal(tagFlipped, CT_OFFSET, ctAndTag, out, 0));
            assertFalse(java.util.Arrays.equals(b.plaintext(), out), "plaintext released");
            String fill = java.util.Arrays.equals(new byte[out.length], out) ? "zero-filled"
                    : java.util.stream.IntStream.range(0, out.length).allMatch(i -> out[i] == 0x5A)
                            ? "left as it was" : "neither zero-filled nor left as it was";
            System.out.printf("After a tag failure the output range is %s on %s %s%n", fill,
                    System.getProperty("java.vendor"), System.getProperty("java.runtime.version"));
        }

        /** docs/27 §5.1: "SunJCE refuses a repeated key and IV on an encrypting instance". */
        @Test
        void sunJceRefusesARepeatedKeyAndNonceOnOneEncryptingInstance() throws Exception {
            byte[] key = new byte[32];
            GCMParameterSpec spec = new GCMParameterSpec(128, new byte[NONCE_LEN]);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            c.doFinal(new byte[1]);
            assertThrows(InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec));
        }
    }

    /** docs/27 §5.2: HKDF-SHA-512 written over Mac, and the empty-salt trap. */
    @Nested
    class Hkdf {

        @Test
        void secretKeySpecRefusesAnEmptyKey() {
            assertThrows(IllegalArgumentException.class,
                    () -> new SecretKeySpec(new byte[0], "HmacSHA512"));
        }

        /**
         * docs/27 §5.2's argument that 64 zero bytes stand in for the empty salt: HMAC pads a key
         * of up to one block (128 bytes) with zeros, so every all-zero key of 1..128 bytes is the
         * same key. At 129 bytes the key is hashed first, and the equivalence stops.
         */
        @Test
        void allZeroMacKeysUpToOneBlockAreOneKey() throws GeneralSecurityException {
            byte[] ikm = ascii("ikm");
            byte[] at64 = HkdfOverMac.extract(new byte[64], ikm);
            assertArrayEquals(at64, HkdfOverMac.extract(new byte[1], ikm));
            assertArrayEquals(at64, HkdfOverMac.extract(new byte[128], ikm));
            assertFalse(java.util.Arrays.equals(at64, HkdfOverMac.extract(new byte[129], ikm)));
        }

        /**
         * The {@code distinct} vectors in both kdf/ files are left out: they give a context
         * object, not {@code info}, and canonical_context is S4's. Every value vector is run.
         */
        private static Stream<JsonNode> valueVectors(String file) {
            return vectors(file).stream().filter(v -> !v.has("assertion"));
        }

        @TestFactory
        Stream<DynamicTest> recordKey() {
            return valueVectors("kdf/record-key.json").map(v -> DynamicTest.dynamicTest(slug(v),
                    () -> {
                        JsonNode exp = v.path("expected");
                        byte[] salt = hex(exp.path("salt"));
                        assertArrayEquals(concat(hex(v.path("key_id")), hex(v.path("msg_seed"))),
                                salt);
                        assertEquals(exp.path("record_key").asText(), hex(HkdfOverMac.derive(
                                hex(v.path("tenant_dek")), salt, hex(exp.path("info")), 32)));
                    }));
        }

        @TestFactory
        Stream<DynamicTest> indexKey() {
            return valueVectors("kdf/index-key.json").map(v -> DynamicTest.dynamicTest(slug(v),
                    () -> {
                        JsonNode exp = v.path("expected");
                        byte[] salt = hex(exp.path("salt"));
                        assertArrayEquals(ascii("fieldseal-index-v1"), salt);
                        assertEquals(exp.path("index_key").asText(), hex(HkdfOverMac.derive(
                                hex(v.path("tenant_index_key")), salt, hex(exp.path("info")), 32)));
                    }));
        }

        /** The empty-salt trap, first site: spec §4.6. */
        @TestFactory
        Stream<DynamicTest> commitmentWithTheEmptySalt() {
            return vectors("commitment/ff01.json").stream()
                    .filter(v -> v.path("expected").has("commitment"))
                    .map(v -> DynamicTest.dynamicTest(slug(v), () -> {
                        JsonNode exp = v.path("expected");
                        byte[] salt = hex(exp.path("salt"));
                        assertEquals(0, salt.length);
                        assertArrayEquals(COMMIT_INFO, hex(exp.path("info")));
                        assertEquals(exp.path("commitment").asText(), hex(HkdfOverMac.derive(
                                hex(v.path("record_key")), salt, COMMIT_INFO,
                                exp.path("length").asInt())));
                    }));
        }

        @TestFactory
        Stream<DynamicTest> commitmentDistinctKeys() {
            return vectors("commitment/ff01.json").stream()
                    .filter(v -> v.path("assertion").asText().equals("distinct"))
                    .map(v -> DynamicTest.dynamicTest(slug(v), () -> {
                        JsonNode in = v.path("inputs");
                        JsonNode exp = v.path("expected");
                        assertFalse(exp.path("must_be_equal").asBoolean(true));
                        for (String x : List.of("a", "b")) {
                            assertEquals(exp.path("commitment_" + x).asText(),
                                    hex(HkdfOverMac.derive(hex(in.path("record_key_" + x)),
                                            new byte[0], COMMIT_INFO, COMMIT_LEN)));
                        }
                    }));
        }

        /** The empty-salt trap, second site: spec §7.3's Argon2id salt. */
        @TestFactory
        Stream<DynamicTest> argon2SaltWithTheEmptySalt() {
            return argon2Vectors().stream()
                    .filter(v -> inputs(v).has("index_key"))
                    .map(v -> DynamicTest.dynamicTest(slug(v), () -> {
                        JsonNode in = inputs(v);
                        assertEquals(in.path("idf_params").path("salt").asText(), hex(HkdfOverMac
                                .derive(hex(in.path("index_key")), new byte[0], ARGON2_SALT_INFO, 16)));
                    }));
        }

        /** The envelope family's intermediates, end to end through HKDF. */
        @TestFactory
        Stream<DynamicTest> envelopeIntermediates() {
            return vectors("envelope/ff01.json").stream().map(v -> DynamicTest.dynamicTest(slug(v),
                    () -> {
                        JsonNode mid = v.path("intermediates");
                        byte[] recordKey = HkdfOverMac.derive(hex(v.path("tenant_dek")),
                                concat(hex(v.path("key_id")), hex(v.path("msg_seed"))),
                                hex(v.path("expected").path("canonical_context")), 32);
                        assertEquals(mid.path("record_key").asText(), hex(recordKey));
                        assertEquals(mid.path("commitment").asText(), hex(HkdfOverMac.derive(
                                recordKey, new byte[0], COMMIT_INFO, COMMIT_LEN)));
                    }));
        }
    }

    /** docs/27 §4: {@code blindIndex(byte[])} decodes with a reporting CharsetDecoder. */
    @Nested
    class StrictUtf8 {

        private static CharsetDecoder strict() {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
        }

        /** Malformed by RFC 3629 §3-§4; each must be refused. */
        private static final List<String> MALFORMED = List.of(
                "c0af", "c1bf",                 // overlong two-byte
                "e080af", "f08080af",           // overlong three- and four-byte
                "eda080", "edbfbf",             // UTF-16 surrogates, encoded (CESU-8)
                "f4908080", "f5808080", "ff",   // past U+10FFFF, and bytes never valid
                "80", "e282", "f09f98",         // lone continuation, truncated sequences
                "61e28262");                    // truncated in the middle of text

        /** Boundary code points of each sequence length, plus U+FFFD and a noncharacter. */
        private static final List<String> WELL_FORMED = List.of(
                "", "7f", "c280", "dfbf", "e0a080", "efbfbd", "efbfbf", "ee8080", "f0908080",
                "f48fbfbf", "616c696365406578616d706c652e636f6d");

        @Test
        void malformedInputIsReported() {
            for (String h : MALFORMED) {
                assertThrows(MalformedInputException.class,
                        () -> strict().decode(ByteBuffer.wrap(java.util.HexFormat.of().parseHex(h))),
                        h);
            }
        }

        @Test
        void wellFormedInputRoundTrips() throws CharacterCodingException {
            for (String h : WELL_FORMED) {
                byte[] bytes = java.util.HexFormat.of().parseHex(h);
                String s = strict().decode(ByteBuffer.wrap(bytes)).toString();
                assertArrayEquals(bytes, s.getBytes(StandardCharsets.UTF_8), h);
            }
        }

        /** The blind-index {@code refuse} vectors' preimages, and why the CI grep exists. */
        @Test
        void everyRefuseVectorPreimageIsReportedAndStringWouldHideIt() {
            List<JsonNode> refuse = new ArrayList<>();
            for (String f : List.of("blind-index/argon2id.json", "blind-index/hmac-sha512.json")) {
                vectors(f).stream().filter(v -> v.path("assertion").asText().equals("refuse"))
                        .filter(v -> inputs(v).has("preimage")).forEach(refuse::add);
            }
            assertFalse(refuse.isEmpty());
            for (JsonNode v : refuse) {
                byte[] preimage = hex(inputs(v).path("preimage"));
                assertEquals("INVALID_ARGUMENT", v.path("expected").path("refuse").asText());
                assertThrows(MalformedInputException.class,
                        () -> strict().decode(ByteBuffer.wrap(preimage)), slug(v));
                // new String(bytes, UTF_8) accepts the same bytes silently (docs/27 §4).
                assertTrue(new String(preimage, StandardCharsets.UTF_8).contains("�"),
                        slug(v));
            }
        }

        /** A fresh decoder already reports; the core still sets REPORT explicitly. */
        @Test
        void aNewDecoderReportsByDefault() {
            CharsetDecoder d = StandardCharsets.UTF_8.newDecoder();
            assertEquals(CodingErrorAction.REPORT, d.malformedInputAction());
            assertEquals(CodingErrorAction.REPORT, d.unmappableCharacterAction());
        }
    }

    // --- Argon2id (docs/27 §2, §5.3) ----------------------------------------------------------

    private static List<JsonNode> argon2Vectors() {
        return vectors("blind-index/argon2id.json");
    }

    /** Assertion-shaped vectors nest their inputs; value vectors carry them at the top. */
    private static JsonNode inputs(JsonNode v) {
        return v.has("inputs") ? v.path("inputs") : v;
    }

    private static Argon2Parameters.Builder spec713(byte[] salt, int t, int m) {
        return new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(t)
                .withMemoryAsKB(m)
                .withParallelism(1)
                .withSalt(salt);
    }

    private static byte[] generate(Argon2Parameters p, byte[] password) {
        Argon2BytesGenerator g = new Argon2BytesGenerator();
        g.init(p);
        byte[] out = new byte[64];
        g.generateBytes(password, out);
        return out;
    }

    /** docs/27 §2: BouncyCastle's Argon2id, for Argon2id only. */
    @Nested
    class Argon2id {

        private static String costPoint(JsonNode params) {
            return "t=" + params.path("time_cost").asInt() + ",m=" + params.path("memory_kib").asInt();
        }

        private List<JsonNode> rawVectors() {
            return argon2Vectors().stream().filter(v -> v.has("plaintext")
                    && v.path("expected").has("raw")).toList();
        }

        @TestFactory
        Stream<DynamicTest> reproducesEveryRawValue() {
            return rawVectors().stream().map(v -> DynamicTest.dynamicTest(slug(v), () -> {
                JsonNode p = v.path("idf_params");
                // The spec §7.3 invariants, so a vector that varied them could not pass here.
                assertEquals(0x13, p.path("version").asInt());
                assertEquals(1, p.path("parallelism").asInt());
                assertEquals(64, p.path("output_len").asInt());
                byte[] salt = hex(p.path("salt"));
                assertEquals(16, salt.length);
                Argon2Parameters params = spec713(salt, p.path("time_cost").asInt(),
                        p.path("memory_kib").asInt()).build();
                assertEquals(v.path("expected").path("raw").asText(),
                        hex(generate(params, hex(v.path("plaintext")))));
            }));
        }

        /** "at every cost point it pins" (docs/27 §8 S5 exit), checked here first. */
        @Test
        void theRawVectorsCoverEveryCostPointTheFilePins() {
            Set<String> pinned = new TreeSet<>();
            argon2Vectors().forEach(v -> pinned.add(costPoint(inputs(v).path("idf_params"))));
            Set<String> covered = new TreeSet<>();
            rawVectors().forEach(v -> covered.add(costPoint(v.path("idf_params"))));
            assertEquals(pinned, covered);
            assertTrue(covered.size() >= 2, "expected the minimum and a raised cost: " + covered);
        }

        /** docs/27 §2 "whether the builder copies the salt": it does, and so does build(). */
        @Test
        void theBuilderAndTheParametersEachHoldTheirOwnCopyOfTheSalt() {
            JsonNode v = rawVectors().getFirst();
            JsonNode p = v.path("idf_params");
            byte[] password = hex(v.path("plaintext"));
            String expected = v.path("expected").path("raw").asText();
            int t = p.path("time_cost").asInt();
            int m = p.path("memory_kib").asInt();

            // Erasing the caller's salt after withSalt changes nothing: the builder copied it.
            byte[] salt = hex(p.path("salt"));
            Argon2Parameters.Builder builder = spec713(salt, t, m);
            java.util.Arrays.fill(salt, (byte) 0);
            Argon2Parameters params = builder.build();
            assertEquals(expected, hex(generate(params, password)));

            // Builder.clear() erases the builder's copy, not the one build() already made.
            builder.clear();
            assertArrayEquals(new byte[16], builder.build().getSalt());
            assertEquals(expected, hex(generate(params, password)));

            // getSalt() hands out a copy: flipping a bit of it leaves the parameters' own salt
            // as the vector pinned it, and the derivation unchanged.
            params.getSalt()[0] ^= 0x01;
            assertArrayEquals(hex(p.path("salt")), params.getSalt());
            assertEquals(expected, hex(generate(params, password)));

            // Parameters.clear() erases the parameters' own copy.
            params.clear();
            assertArrayEquals(new byte[16], params.getSalt());
            assertNotEquals(expected, hex(generate(params, password)));
        }

        /**
         * BouncyCastle caps memory by a system property, org.bouncycastle.argon2.max_memory_exp,
         * default 24: m up to 2^24 KiB (16 GiB). Spec §7.3 lets a deployment raise m; this pins
         * where the library would stop it.
         */
        @Test
        void theDefaultMemoryCapIs2To24KiB() {
            new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withMemoryAsKB(1 << 24);
            assertThrows(IllegalArgumentException.class,
                    () -> new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                            .withMemoryAsKB((1 << 24) + 1));
        }
    }

    /**
     * docs/27 §6.3: what SunJCE's GCM allocates on its own, beyond the arrays the caller passes
     * in. Measured, and printed for docs/27 §6.3; the assertion is a tripwire on the figure
     * recorded there, not a conformance requirement.
     */
    @Nested
    class GcmAllocation {

        private static final int MIB = 1 << 20;

        private long allocatedBy(Runnable r) {
            com.sun.management.ThreadMXBean mx =
                    (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
            long before = mx.getCurrentThreadAllocatedBytes();
            r.run();
            return mx.getCurrentThreadAllocatedBytes() - before;
        }

        /** Bytes allocated by encrypt, one-shot decrypt, and decrypt fed through update(). */
        private long[] measure(int size) throws GeneralSecurityException {
            byte[] key = new byte[32];
            byte[] nonce = new byte[NONCE_LEN];
            byte[] aad = new byte[64];
            byte[] plaintext = new byte[size];
            byte[] env = new byte[size + TAG_LEN];
            byte[] out = new byte[size];
            Cipher enc = gcm(Cipher.ENCRYPT_MODE, key, nonce, aad);
            Cipher dec = gcm(Cipher.DECRYPT_MODE, key, nonce, aad);
            Cipher streamed = gcm(Cipher.DECRYPT_MODE, key, nonce, aad);
            long e = allocatedBy(() -> call(() -> enc.doFinal(plaintext, 0, size, env, 0)));
            long d = allocatedBy(() -> call(() -> dec.doFinal(env, 0, env.length, out, 0)));
            assertArrayEquals(plaintext, out);
            java.util.Arrays.fill(out, (byte) 1);
            long u = allocatedBy(() -> call(() -> {
                int n = streamed.update(env, 0, env.length, out, 0);
                return n + streamed.doFinal(out, n);
            }));
            assertArrayEquals(plaintext, out);
            return new long[] {e, d, u};
        }

        private interface Call {
            int run() throws GeneralSecurityException;
        }

        private static void call(Call c) {
            try {
                c.run();
            } catch (GeneralSecurityException ex) {
                throw new AssertionError(ex);
            }
        }

        /** The counter sees a large allocation, so a near-zero reading below means something. */
        @Test
        void theAllocationCounterSeesALargeArray() {
            long seen = allocatedBy(() -> assertEquals(64 * MIB, new byte[64 * MIB].length));
            assertTrue(seen >= 64L * MIB, "counted " + seen);
        }

        /**
         * docs/27 §6.3 said SunJCE's GCM decrypt buffers about the operand. On one doFinal over
         * the whole of ct‖tag into a separate output array, it does not; fed through update(),
         * it does. The core decrypts in one doFinal (docs/27 §5.1), so the first figure is its.
         */
        @Test
        void oneShotDecryptDoesNotBufferTheOperand() throws GeneralSecurityException {
            measure(MIB); // warm-up: class loading and JIT allocate on the first calls
            int size = 64 * MIB;
            long[] a = measure(size);
            System.out.printf("GCM allocation beyond the caller's arrays on %s %s, %d MiB operand:"
                            + " encrypt %d B, one-shot decrypt %d B, update()+doFinal decrypt %d B"
                            + " (%.3fx)%n",
                    System.getProperty("java.vendor"), System.getProperty("java.runtime.version"),
                    size / MIB, a[0], a[1], a[2], (double) a[2] / size);
            assertTrue(a[0] < MIB, "encrypt allocated " + a[0]);
            assertTrue(a[1] < MIB, "one-shot decrypt allocated " + a[1]);
            // The update() path is what docs/27 §6.3 described, and more: measured at 3.0x.
            assertTrue(a[2] > size, "update()+doFinal decrypt allocated " + a[2]);
        }
    }
}
