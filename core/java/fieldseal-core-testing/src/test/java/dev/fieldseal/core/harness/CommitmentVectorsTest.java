package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.harness.PrimitiveVectors.suiteId;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.internal.commitment.Commitment;
import dev.fieldseal.core.internal.kdf.Hkdf;
import dev.fieldseal.core.internal.registry.Registry;
import dev.fieldseal.core.internal.registry.Suite;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * {@code commitment/} (docs/08 §4.5) through the core's spec §4.6 construction, with {@code kdf}'s
 * HKDF injected as the client injects it (the {@code docs/09} §1 resolution logged at S4).
 */
class CommitmentVectorsTest {

    private static final Map<String, int[]> PINNED = Map.of("commitment/ff01.json",
            new int[] {1, 1});

    private static final Commitment.Kdf KDF = Hkdf::derive;

    @TestFactory
    Stream<DynamicTest> commitment() {
        return PrimitiveVectors.run(PrimitiveVectors.family("commitment", PINNED),
                CommitmentVectorsTest::value, CommitmentVectorsTest::pair);
    }

    private static void value(JsonNode v) {
        Suite suite = suite(v);
        JsonNode e = v.path("expected");
        byte[] recordKey = hex(v.path("record_key"));
        assertEquals("", e.path("salt").asText(), "salt: spec §4.6 fixes it empty");
        assertEquals(e.path("info").asText(), hex(Commitment.info()), "info");
        byte[] c = Commitment.compute(suite, recordKey, KDF);
        assertEquals(e.path("length").asInt(), c.length, "length");
        assertEquals(e.path("commitment").asText(), hex(c), "commitment");
        assertTrue(Commitment.verify(suite, recordKey, hex(e.path("commitment")), KDF),
                "verify accepts the pinned commitment");
    }

    private static byte[][] pair(JsonNode v) {
        Suite suite = suite(v);
        JsonNode in = v.path("inputs");
        return new byte[][] {
            Commitment.compute(suite, hex(in.path("record_key_a")), KDF),
            Commitment.compute(suite, hex(in.path("record_key_b")), KDF)
        };
    }

    private static Suite suite(JsonNode v) {
        return Registry.lookup(suiteId(v)).orElseThrow(
                () -> new AssertionError("unregistered suite " + v.path("suite_id")));
    }
}
