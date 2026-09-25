package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.harness.PrimitiveVectors.context;
import static dev.fieldseal.core.harness.PrimitiveVectors.suiteId;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.internal.context.CanonicalContext;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * {@code context/} (docs/08 §4.3) through the core's {@code canonical_context} (spec §6.2): the
 * presence byte, the encoding and its length, and the absent-versus-zero-length distinction.
 */
class ContextVectorsTest {

    private static final Map<String, int[]> PINNED = Map.of("context/canonical.json",
            new int[] {14, 1});

    @TestFactory
    Stream<DynamicTest> canonicalContext() {
        return PrimitiveVectors.run(PrimitiveVectors.family("context", PINNED),
                ContextVectorsTest::value, ContextVectorsTest::pair);
    }

    private static void value(JsonNode v) {
        byte[] cc = CanonicalContext.encode(context(suiteId(v), v.path("context")));
        JsonNode e = v.path("expected");
        assertEquals(e.path("canonical_context").asText(), hex(cc), "canonical_context");
        assertEquals(e.path("length").asInt(), cc.length, "length");
        assertEquals(e.path("presence").asInt(), cc[0] & 0xFF, "presence");
    }

    private static byte[][] pair(JsonNode v) {
        int suite = suiteId(v);
        JsonNode in = v.path("inputs");
        return new byte[][] {
            CanonicalContext.encode(context(suite, in.path("context_a"))),
            CanonicalContext.encode(context(suite, in.path("context_b")))
        };
    }
}
