package dev.fieldseal.core.harness;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The cross producer and consumer (S7) against each other, and each consumer guard against a
 * document broken in exactly one way. The self-pair here is the one CI runs as {@code java ->
 * java}; the other pairs need the other implementations' documents and run only in CI.
 */
class CrossTest {

    private static final Path VECTORS = Path.of(System.getProperty("fieldseal.vectors"));
    private static final Consumer<String> QUIET = w -> { };

    /** One production, copied by each test that breaks it. */
    private static ObjectNode produced;

    @TempDir
    Path dir;

    @BeforeAll
    static void produce() throws IOException {
        produced = CrossProduce.produce(VECTORS, QUIET);
    }

    private static ObjectNode copy() {
        return produced.deepCopy();
    }

    private List<CrossConsume.Pair> consume(JsonNode doc) throws IOException {
        Path file = dir.resolve("cross-java.json");
        Files.writeString(file, Cross.JSON.writeValueAsString(doc));
        return CrossConsume.consume(VECTORS, file, QUIET);
    }

    private static CrossConsume.Pair half(List<CrossConsume.Pair> pairs, String half) {
        return pairs.stream().filter(p -> p.half().equals(half)).findFirst().orElseThrow();
    }

    /** The one failure in {@code half}, which must mention {@code because}. */
    private void failsOnce(JsonNode doc, String half, String because) throws IOException {
        List<CrossConsume.Pair> pairs = consume(doc);
        List<String> failures = pairs.stream().flatMap(p -> p.failures().stream()).toList();
        assertEquals(1, failures.size(), "failures: " + failures);
        assertEquals(1, half(pairs, half).failures().size(), "the failure is in " + half);
        assertTrue(failures.get(0).contains(because), failures.get(0));
    }

    private static ObjectNode envelopeCase(ObjectNode doc, int i) {
        return (ObjectNode) doc.path("cases").get(i);
    }

    private static ObjectNode indexCase(ObjectNode doc, String slug) {
        for (JsonNode c : doc.path("index_cases")) {
            if (c.path("id").asText().endsWith("/" + slug)) {
                return (ObjectNode) c;
            }
        }
        throw new AssertionError("no index case " + slug);
    }

    // --- the producer --------------------------------------------------------------------------

    @Test
    void theProducerWritesEveryCorpusCaseAsCrossV2() throws IOException {
        JsonNode corpus = Cross.support(VECTORS, "cross/corpus.json");
        assertEquals(Cross.V2, produced.path("schema").asText());
        assertEquals("java", produced.path("producer").path("implementation").asText());
        assertEquals(corpus.path("suite_id"), produced.path("suite_id"));
        assertEquals(corpus.path("cases").size(), produced.path("cases").size());
        assertEquals(corpus.path("index_cases").size(), produced.path("index_cases").size());
        for (int i = 0; i < corpus.path("cases").size(); i++) {
            JsonNode in = corpus.path("cases").get(i);
            JsonNode out = produced.path("cases").get(i);
            assertEquals("cross/java/" + in.path("case").asText(), out.path("id").asText());
            assertEquals(in.path("context"), out.path("context"));
            assertEquals(in.path("plaintext"), out.path("plaintext"));
        }
    }

    @Test
    void theSelfPairIsGreen() throws IOException {
        List<CrossConsume.Pair> pairs = consume(produced);
        assertEquals(2, pairs.size());
        assertEquals(List.of(), half(pairs, "envelope").failures());
        assertEquals(List.of(), half(pairs, "index").failures());
        assertEquals(produced.path("cases").size(), half(pairs, "envelope").pass());
        assertEquals(produced.path("index_cases").size(), half(pairs, "index").pass());
    }

    /** The CSPRNG, not a constant: a second production shares no envelope with the first. */
    @Test
    void aSecondProductionDrawsFreshEntropy() throws IOException {
        ObjectNode again = CrossProduce.produce(VECTORS, QUIET);
        for (int i = 0; i < produced.path("cases").size(); i++) {
            assertNotEquals(produced.path("cases").get(i).path("envelope"),
                    again.path("cases").get(i).path("envelope"));
        }
        assertEquals(produced.path("index_cases"), again.path("index_cases"),
                "an index is deterministic");
    }

    @Test
    void theProducerRefusesAnArmedProcess() {
        assertThrows(IllegalStateException.class,
                () -> CrossProduce.refuseArmed(Map.of("FIELDSEAL_TEST_MODE", "1")));
        assertDoesNotThrow(() -> CrossProduce.refuseArmed(Map.of()));
        assertDoesNotThrow(() -> CrossProduce.refuseArmed(Map.of("FIELDSEAL_TEST_MODE", "0")));
    }

    @Test
    void theProducerRefusesARepeatedSeed() {
        ArrayNode cases = copy().withArray("cases");
        cases.add(cases.get(0).deepCopy());
        assertThrows(IllegalStateException.class, () -> CrossProduce.fresh(cases));
        assertDoesNotThrow(() -> CrossProduce.fresh(copy().withArray("cases")));
    }

    // --- the consumer's guards -----------------------------------------------------------------

    /** A support file is read only once MANIFEST.support's length and SHA-256 match. */
    @Test
    void aSupportFileThatFailsItsHashIsNotRead() throws IOException {
        Path copy = dir.resolve("vectors");
        for (String f : List.of("MANIFEST.json", "keys/test-keys.json", "cross/corpus.json")) {
            Files.createDirectories(copy.resolve(f).getParent());
            Files.copy(VECTORS.resolve(f), copy.resolve(f));
        }
        assertDoesNotThrow(() -> Cross.support(copy, "cross/corpus.json"), "the unaltered copy");
        byte[] corpus = Files.readAllBytes(copy.resolve("cross/corpus.json"));
        corpus[corpus.length / 2] ^= 1;
        Files.write(copy.resolve("cross/corpus.json"), corpus);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Cross.support(copy, "cross/corpus.json"));
        assertTrue(e.getMessage().contains("MANIFEST.support says"), e.getMessage());
    }

    /** Strict mode: a value that is not an envelope is not handed back as its own plaintext. */
    @Test
    void aNonEnvelopeFails() throws IOException {
        ObjectNode doc = copy();
        ObjectNode c = envelopeCase(doc, 2);
        c.put("envelope", c.path("plaintext").asText());
        failsOnce(doc, "envelope", "NOT_CIPHERTEXT");
    }

    @Test
    void anUnknownSchemaFails() throws IOException {
        ObjectNode doc = copy().put("schema", "fieldseal-vectors/cross/v3");
        failsOnce(doc, "document", "schema");
    }

    @Test
    void aV1DocumentCarryingIndexCasesFails() throws IOException {
        failsOnce(copy().put("schema", Cross.V1), "document", "carries index_cases");
    }

    @Test
    void aV2DocumentWithoutIndexCasesFails() throws IOException {
        ObjectNode doc = copy();
        doc.putArray("index_cases");
        failsOnce(doc, "document", "without index cases");
    }

    @Test
    void aV1DocumentIsReadForItsEnvelopesAlone() throws IOException {
        ObjectNode doc = copy().put("schema", Cross.V1);
        doc.remove("index_cases");
        List<CrossConsume.Pair> pairs = consume(doc);
        assertEquals(List.of("envelope"), pairs.stream().map(CrossConsume.Pair::half).toList());
        assertEquals(List.of(), pairs.get(0).failures());
    }

    @Test
    void aFlippedEnvelopeBitFails() throws IOException {
        ObjectNode doc = copy();
        ObjectNode c = envelopeCase(doc, 3);
        String e = c.path("envelope").asText();
        // The tag's last byte: the 32-byte commitment follows it (spec §3.1).
        int at = e.length() - 2 * 33;
        String flipped = String.format("%02x", Integer.parseInt(e.substring(at, at + 2), 16) ^ 1);
        c.put("envelope", e.substring(0, at) + flipped + e.substring(at + 2));
        failsOnce(doc, "envelope", "TAG_INVALID");
    }

    @Test
    void aWrongPlaintextFails() throws IOException {
        ObjectNode doc = copy();
        envelopeCase(doc, 2).put("plaintext", "00");
        failsOnce(doc, "envelope", "decrypts to");
    }

    @Test
    void anEnvelopeUnderAnotherContextFails() throws IOException {
        ObjectNode doc = copy();
        ((ObjectNode) envelopeCase(doc, 2).path("context")).put("row_id", "01");
        failsOnce(doc, "envelope", "COMMITMENT_INVALID");
    }

    @Test
    void aRepeatedEnvelopeFails() throws IOException {
        ObjectNode doc = copy();
        ObjectNode twin = envelopeCase(doc, 0).deepCopy().put("id", "cross/java/twin");
        doc.withArray("cases").add(twin);
        failsOnce(doc, "envelope", "repeats the msg_seed");
    }

    @Test
    void anUnknownContextFieldFails() throws IOException {
        ObjectNode doc = copy();
        ((ObjectNode) envelopeCase(doc, 1).path("context")).put("key_version", "1");
        failsOnce(doc, "envelope", "context fields");
    }

    @Test
    void aWrongIndexFails() throws IOException {
        ObjectNode doc = copy();
        ObjectNode c = indexCase(doc, "exact-ascii");
        c.put("index", c.path("index").asText().equals("0000") ? "0001" : "0000");
        failsOnce(doc, "index", "derives");
    }

    @Test
    void aPurposeThatDisagreesWithTheIndexIdFails() throws IOException {
        ObjectNode doc = copy();
        ((ObjectNode) indexCase(doc, "exact-ascii").path("context")).put("purpose", "index:wide");
        failsOnce(doc, "index", "context.purpose");
    }

    @Test
    void twoValueFieldsFail() throws IOException {
        ObjectNode doc = copy();
        indexCase(doc, "exact-ascii").put("value_bytes", "00");
        failsOnce(doc, "index", "not exactly one");
    }

    @Test
    void valueBytesUnderANormalizerOtherThanIdentityFails() throws IOException {
        ObjectNode doc = copy();
        ObjectNode c = indexCase(doc, "exact-ascii");
        c.remove("value_text");
        c.put("value_bytes", "616c696365406578616d706c652e636f6d");
        failsOnce(doc, "index", "not identity");
    }

    @Test
    void aFalseMarkerFails() throws IOException {
        ObjectNode doc = copy();
        indexCase(doc, "bucket-marker").put("value_marker", false);
        failsOnce(doc, "index", "value_marker is not true");
    }

    @Test
    void anUnknownDeclarationFieldFails() throws IOException {
        ObjectNode doc = copy();
        ((ObjectNode) indexCase(doc, "digits-only").path("declaration")).put("salt", "00");
        failsOnce(doc, "index", "unknown [salt]");
    }

    @Test
    void anUnbuiltSuiteIsSkippedVisibly() throws IOException {
        List<CrossConsume.Pair> pairs = consume(copy().put("suite_id", "0xFF02"));
        assertEquals(List.of(), pairs.stream().flatMap(p -> p.failures().stream()).toList());
        assertEquals(0, pairs.stream().mapToInt(CrossConsume.Pair::pass).sum());
        assertEquals(produced.path("cases").size(), half(pairs, "envelope").skipped());
        assertEquals(produced.path("index_cases").size(), half(pairs, "index").skipped());
        JsonNode v = CrossConsume.verdict(pairs).path("summary");
        assertEquals(produced.path("cases").size() + produced.path("index_cases").size(),
                v.path("skipped").asInt());
    }

    @Test
    void anUnregisteredSuiteFailsEveryCase() throws IOException {
        List<CrossConsume.Pair> pairs = consume(copy().put("suite_id", "0xFF03"));
        assertEquals(0, pairs.stream().mapToInt(CrossConsume.Pair::pass).sum());
        assertEquals(produced.path("cases").size(), half(pairs, "envelope").failures().size());
        assertEquals(produced.path("index_cases").size(), half(pairs, "index").failures().size());
    }
}
