package dev.fieldseal.core.harness;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
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

    /**
     * docs/08 §4.7's case set for a core producer, which the corpus is meant to meet: at least 16
     * envelope cases for the one suite; each context shape (row_id and tenant_id, each present and
     * absent); and in the index half a non-ASCII value, a pair that must collide, the marker for
     * every {@code bucket} declaration, and every registry normalizer. A core can declare {@code
     * bucket} as it can any normalizer, so this reads the marker rule as {@code docs/08} reads the
     * normalizer rule for a core: at least one {@code bucket} declaration, each with its marker.
     */
    static List<String> belowCoreFloor(JsonNode doc) {
        List<String> below = new ArrayList<>();
        JsonNode cases = doc.path("cases");
        if (cases.size() < 16) {
            below.add("fewer than 16 envelope cases: " + cases.size());
        }
        for (String field : List.of("row_id", "tenant_id")) {
            boolean present = false;
            boolean absent = false;
            for (JsonNode c : cases) {
                boolean isNull = c.path("context").path(field).isNull();
                present |= !isNull;
                absent |= isNull;
            }
            if (!present || !absent) {
                below.add(field + " not both present and absent");
            }
        }
        JsonNode index = doc.path("index_cases");
        Set<String> normalizers = new TreeSet<>();
        Set<String> bucketed = new TreeSet<>();
        Set<String> marked = new TreeSet<>();
        boolean nonAscii = false;
        boolean collides = false;
        for (JsonNode c : index) {
            JsonNode d = c.path("declaration");
            normalizers.add(d.path("normalize").asText());
            if (d.path("on_unindexable").asText().equals("bucket")) {
                bucketed.add(d.path("index_id").asText());
            }
            if (c.path("value_marker").asBoolean(false)) {
                marked.add(d.path("index_id").asText());
            }
            nonAscii |= c.path("value_text").asText("").chars().anyMatch(ch -> ch > 0x7f);
            for (JsonNode o : index) {
                collides |= o != c && !o.path("value_marker").asBoolean(false)
                        && !c.path("value_marker").asBoolean(false)
                        && o.path("key_ref").equals(c.path("key_ref"))
                        && o.path("declaration").equals(d)
                        && o.path("context").equals(c.path("context"))
                        && !o.path("value_text").equals(c.path("value_text"))
                        && o.path("index").equals(c.path("index"));
            }
        }
        Set<String> registry = new TreeSet<>();
        for (Normalizer n : Normalizer.values()) {
            registry.add(n.id());
        }
        if (!normalizers.containsAll(registry)) {
            below.add("normalizers " + normalizers + ", not every one of " + registry);
        }
        if (bucketed.isEmpty() || !marked.containsAll(bucketed)) {
            below.add("bucket indexes " + bucketed + " without a marker case: marked " + marked);
        }
        if (!nonAscii) {
            below.add("no non-ASCII value");
        }
        if (!collides) {
            below.add("no pair that must collide");
        }
        return below;
    }

    @Test
    void theProducerMeetsTheCoreFloor() {
        assertEquals(List.of(), belowCoreFloor(produced));
    }

    /** The floor check against the document with one rule's cases removed, rule by rule. */
    @Test
    void theFloorCheckSeesEachShortfall() {
        Map<String, List<String>> removed = Map.of(
                "fewer than 16", List.of("cross/java/key-tenant-b-row-present"),
                "row_id not both", List.of("cross/java/shape-row-present",
                        "cross/java/shape-row-present-one-kib",
                        "cross/java/shape-tenant-absent-row-present",
                        "cross/java/shape-tenant-zero-length-row-present",
                        "cross/java/shape-tenant-row-255b", "cross/java/shape-max-context",
                        "cross/java/key-tenant-b-row-present"),
                "identity", List.of("cross/java/index/identity-bytes"),
                "without a marker", List.of("cross/java/index/bucket-marker"),
                "non-ASCII", List.of("cross/java/index/exact-non-ascii",
                        "cross/java/index/nfc-pair-composed",
                        "cross/java/index/nfc-pair-decomposed"),
                "must collide", List.of("cross/java/index/fold-pair-upper",
                        "cross/java/index/nfc-pair-decomposed"));
        removed.forEach((rule, ids) -> {
            ObjectNode doc = copy();
            for (String array : List.of("cases", "index_cases")) {
                ArrayNode a = doc.withArray(array);
                for (int i = a.size() - 1; i >= 0; i--) {
                    if (ids.contains(a.get(i).path("id").asText())) {
                        a.remove(i);
                    }
                }
            }
            assertEquals(produced.path("cases").size() + produced.path("index_cases").size()
                    - ids.size(), doc.path("cases").size() + doc.path("index_cases").size(),
                    rule + ": every id named was removed");
            List<String> below = belowCoreFloor(doc);
            assertTrue(below.stream().anyMatch(b -> b.contains(rule)), rule + ": " + below);
        });
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
        // The tag's last byte: the 32-byte commitment follows it (spec §3.1). `at` indexes the
        // hex string, two characters a byte; the tag is the 16 bytes after header, nonce and
        // ciphertext (63 + plaintext length), so its last byte is at 63 + length + 15.
        int at = e.length() - 2 * 33;
        assertEquals(63 + c.path("plaintext").asText().length() / 2 + 15, at / 2,
                "the flipped byte is the tag's last");
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
