package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.capabilities.SuiteFiles.slug;
import static dev.fieldseal.core.capabilities.SuiteFiles.vectors;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.internal.envelope.DecryptFront;
import dev.fieldseal.core.internal.envelope.EnvelopeCodec;
import dev.fieldseal.core.internal.envelope.Operand;
import dev.fieldseal.core.internal.envelope.ParsedEnvelope;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * docs/27 §8 stage S3's exit, as far as a codec can reach it: {@code envelope/} and the
 * recognition half of {@code errors/}, run against the codec directly.
 *
 * <p><b>What S3 cannot run.</b> There is no client or key provider until S4, so every outcome
 * decided after recognition (the allow-list, key lookup, the commitment, the tag), and every
 * API-boundary outcome ({@code MODE_VIOLATION}, {@code SUITE_PROVISIONAL}), waits for S4. For a
 * decrypt vector whose outcome lies after recognition, this test still asserts the part S3 owns:
 * the input is recognized as an envelope, within spec §3.5's bound. {@link #PARTITION} pins how
 * many vectors fall on each side, so a suite change that moves one fails here rather than
 * shrinking what is checked.
 *
 * <p>The read-mode mapping below is spec §3.4 and §10.3's tables, restated. In the core it
 * belongs to the client (S4), the only module that knows the mode; the S6 harness then runs every
 * vector through the public API, and this test's reason to exist ends.
 */
class CodecVectorsTest {

    /** Per file: {vectors run to their expected outcome at S3, vectors whose outcome is S4's}. */
    private static final Map<String, int[]> PARTITION = new LinkedHashMap<>();

    static {
        PARTITION.put("errors/format.json", new int[] {40, 1});
        PARTITION.put("errors/crypto.json", new int[] {0, 12});
        PARTITION.put("errors/policy.json", new int[] {4, 12});
    }

    /** One vector's S3 verdict: run to its expected outcome, or deferred to S4 and why. */
    private record Verdict(boolean ran, String deferredBecause) {
        static final Verdict RAN = new Verdict(true, null);

        static Verdict deferred(String why) {
            return new Verdict(false, why);
        }
    }

    @TestFactory
    Stream<DynamicTest> envelopeFamilyParsesAndReserializes() {
        return vectors("envelope/ff01.json").stream().map(v -> DynamicTest.dynamicTest(slug(v),
                () -> {
                    byte[] env = hex(v.path("expected").path("envelope"));
                    assertEquals(v.path("expected").path("envelope_bytes").asInt(), env.length);
                    ParsedEnvelope p = assertInstanceOf(DecryptFront.Ready.class,
                            EnvelopeCodec.frontOfDecrypt(Operand.of(env))).envelope();
                    assertEquals(Integer.decode(v.path("suite_id").asText()), p.suite().id());
                    assertArrayEquals(hex(v.path("key_id")), p.keyId());
                    assertArrayEquals(hex(v.path("msg_seed")), p.msgSeed());
                    assertArrayEquals(hex(v.path("nonce")), p.nonce());
                    assertArrayEquals(hex(v.path("intermediates").path("commitment")),
                            p.commitment());
                    assertEquals(hex(v.path("plaintext")).length, p.plaintextLen());

                    byte[] ctAndTag = Arrays.copyOfRange(env, (int) p.ctOffset(),
                            (int) (p.ctOffset() + p.ctAndTagLen()));
                    assertEquals(hex(env), hex(EnvelopeCodec.serialize(p.suite(), p.keyId(),
                            p.msgSeed(), p.nonce(), ctAndTag, p.commitment())));
                }));
    }

    @Test
    void errorsFamilyRecognitionHalf() {
        List<String> failures = new ArrayList<>();
        Map<String, int[]> seen = new LinkedHashMap<>();
        List<String> deferred = new ArrayList<>();
        for (String file : PARTITION.keySet()) {
            int[] counts = new int[2];
            for (JsonNode v : vectors(file)) {
                try {
                    Verdict verdict = run(v);
                    counts[verdict.ran() ? 0 : 1]++;
                    if (!verdict.ran()) {
                        deferred.add(slug(v) + " (" + verdict.deferredBecause() + ")");
                    }
                } catch (AssertionError | RuntimeException e) {
                    failures.add(v.path("id").asText() + ": " + e.getMessage());
                }
            }
            seen.put(file, counts);
        }
        if (!failures.isEmpty()) {
            fail(String.join("\n", failures));
        }
        System.out.println("deferred to S4: " + deferred);
        PARTITION.forEach((file, want) -> assertArrayEquals(want, seen.get(file),
                file + " run/deferred counts moved: " + Arrays.toString(seen.get(file))));
    }

    private static Verdict run(JsonNode v) {
        String op = v.path("operation").asText();
        JsonNode expected = v.path("expected");
        if (op.equals("is_ciphertext")) {
            assertEquals(expected.path("is_ciphertext").asBoolean(),
                    EnvelopeCodec.isCiphertext(hex(v.path("input"))));
            return Verdict.RAN;
        }
        String mode = v.path("config").path("read_mode").asText();
        if (!op.equals("decrypt") && !op.equals("rotate")) {
            return Verdict.deferred(op + ": the client's");
        }
        if (op.equals("rotate") && mode.equals("readonly")) {
            return Verdict.deferred("MODE_VIOLATION precedes recognition");
        }

        byte[] input = hex(v.path("input"));
        DecryptFront front = EnvelopeCodec.frontOfDecrypt(Operand.of(input));
        String error = expected.path("error").asText(null);
        boolean recognitionLevel = expected.has("value") || "NOT_CIPHERTEXT".equals(error)
                || "UNKNOWN_FORMAT_VERSION".equals(error);
        if (!recognitionLevel) {
            // The outcome lies after recognition: S3 owns only that the input got that far.
            // Under any registered suite: suite-not-allowed is a 0xFF02 envelope, recognized
            // and then refused by the allow-list (spec §3.4).
            assertInstanceOf(DecryptFront.Ready.class, front,
                    "expected " + expected + " needs a recognized envelope");
            return Verdict.deferred(error == null ? "a plaintext" : error);
        }

        // spec §3.4, §10.3: what recognition becomes, by operation and mode.
        switch (front) {
            case DecryptFront.ReservedVersion r -> assertEquals("UNKNOWN_FORMAT_VERSION", error);
            case DecryptFront.NonEnvelope n -> {
                if (op.equals("rotate") || mode.equals("strict")) {
                    assertEquals("NOT_CIPHERTEXT", error);
                } else {
                    assertEquals(hex(input), expected.path("value").asText());
                }
            }
            case DecryptFront.Ready r -> fail("recognized as an envelope; expected " + expected);
        }
        return Verdict.RAN;
    }
}
