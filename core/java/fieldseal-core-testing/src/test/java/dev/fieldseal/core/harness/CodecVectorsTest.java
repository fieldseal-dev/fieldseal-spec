package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.files;
import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.capabilities.SuiteFiles.slug;
import static dev.fieldseal.core.capabilities.SuiteFiles.vectors;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.internal.envelope.DecryptFront;
import dev.fieldseal.core.internal.envelope.EnvelopeCodec;
import dev.fieldseal.core.internal.envelope.Operand;
import dev.fieldseal.core.internal.envelope.ParsedEnvelope;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * {@code envelope/} against the codec alone (docs/27 §8, S3): each pinned envelope parses to its
 * vector's fields and re-serializes byte for byte. The file is enumerated from {@code
 * MANIFEST.files}, so a file added to the family fails here until it is pinned.
 *
 * <p><b>What left at S6.</b> Until S6 this class also ran the recognition half of {@code errors/}
 * against the codec, with spec §3.4 and §10.3's read-mode tables restated in the test. The
 * client has run every {@code errors/} vector since S4b ({@code ClientVectorsTest}), and the
 * report is built from that run, so the restatement is gone: the read-mode mapping is asserted
 * where it lives, in the client.
 */
class CodecVectorsTest {

    /** Per envelope/ file: its vector count; every one runs. */
    private static final Map<String, Integer> ENVELOPE = Map.of("envelope/ff01.json", 9);

    /** The {@code MANIFEST.files} entries under {@code family/}: exactly those {@code pinned}. */
    private static List<VectorHarness.FileWalk> family(String family, Set<String> pinned) {
        List<VectorHarness.FileWalk> listed = files().stream()
                .filter(f -> f.path().startsWith(family + "/")).toList();
        assertEquals(pinned, listed.stream().map(VectorHarness.FileWalk::path)
                .collect(Collectors.toSet()),
                family + "/ in MANIFEST.files is not the set of files this test pins");
        return listed;
    }

    @TestFactory
    Stream<DynamicTest> envelopeFamilyParsesAndReserializes() {
        return family("envelope", ENVELOPE.keySet()).stream().flatMap(file -> {
            List<JsonNode> vs = vectors(file.path());
            assertEquals(ENVELOPE.get(file.path()).intValue(), vs.size(),
                    file.path() + ": vector count moved");
            return vs.stream();
        }).map(v -> DynamicTest.dynamicTest(slug(v),
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
}
