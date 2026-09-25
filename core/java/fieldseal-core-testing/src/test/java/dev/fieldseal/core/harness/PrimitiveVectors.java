package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.files;
import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.capabilities.SuiteFiles.slug;
import static dev.fieldseal.core.capabilities.SuiteFiles.vectors;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.internal.context.ContextFields;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;

/**
 * What the S4 primitive families ({@code kdf/}, {@code context/}, {@code commitment/}) share: the
 * manifest enumeration with pinned counts, the assertion-kind dispatch, and the context reader.
 *
 * <p>docs/08 §4's two assertion kinds these families use are a value vector (no
 * {@code assertion} field) and {@code distinct}. Any other kind fails the vector: docs/08 says a
 * harness "MUST fail on an assertion kind it does not recognise, never skip it".
 */
final class PrimitiveVectors {

    private PrimitiveVectors() {}

    /** Per-file pinned counts: {value vectors, distinct vectors}. */
    static Stream<JsonNode> family(String family, Map<String, int[]> pinned) {
        List<String> listed = files().stream().map(VectorHarness.FileWalk::path)
                .filter(p -> p.startsWith(family + "/")).toList();
        assertEquals(pinned.keySet(), listed.stream().collect(Collectors.toSet()),
                family + "/ in MANIFEST.files is not the set of files this test pins");
        List<JsonNode> all = new ArrayList<>();
        for (String path : listed) {
            List<JsonNode> vs = vectors(path);
            int[] seen = new int[2];
            vs.forEach(v -> seen[v.has("assertion") ? 1 : 0]++);
            assertEquals(Arrays.toString(pinned.get(path)), Arrays.toString(seen),
                    path + ": {value, distinct} counts moved");
            all.addAll(vs);
        }
        return all.stream();
    }

    /**
     * One dynamic test per vector: {@code value} runs a value vector; a {@code distinct} vector
     * is recomputed from its {@code inputs} by {@code pair}, which returns the two outputs.
     */
    static Stream<DynamicTest> run(Stream<JsonNode> vectors, java.util.function.Consumer<JsonNode> value,
            Function<JsonNode, byte[][]> pair) {
        return vectors.map(v -> DynamicTest.dynamicTest(slug(v), () -> {
            if (!v.has("assertion")) {
                value.accept(v);
            } else if ("distinct".equals(v.path("assertion").asText())) {
                distinct(v, pair.apply(v));
            } else {
                fail(v.path("id").asText() + ": unrecognised assertion kind '"
                        + v.path("assertion").asText() + "' (docs/08 §4: fail, never skip)");
            }
        }));
    }

    /**
     * docs/08 §4 {@code distinct}: the two outputs, recomputed from {@code inputs}, equal the two
     * hex fields of {@code expected} in file order, and their equality is {@code must_be_equal}.
     * Recomputing is the point: a harness that merely compared the two literals would check
     * nothing (docs/08 §4).
     */
    private static void distinct(JsonNode v, byte[][] computed) {
        List<String> fields = new ArrayList<>();
        v.path("expected").fieldNames().forEachRemaining(fields::add);
        fields.remove("must_be_equal");
        assertEquals(2, fields.size(), "a distinct vector names two outputs: " + fields);
        assertEquals(v.path("expected").path(fields.get(0)).asText(), hex(computed[0]),
                fields.get(0));
        assertEquals(v.path("expected").path(fields.get(1)).asText(), hex(computed[1]),
                fields.get(1));
        JsonNode mustBeEqual = v.path("expected").path("must_be_equal");
        if (!mustBeEqual.isBoolean()) {
            fail("must_be_equal is not a boolean");
        }
        assertEquals(mustBeEqual.asBoolean(), Arrays.equals(computed[0], computed[1]),
                "must_be_equal");
    }

    static int suiteId(JsonNode v) {
        return Integer.decode(v.path("suite_id").asText());
    }

    /** A vector's {@code context} object: UUIDs and optional fields in hex, null when absent. */
    static ContextFields context(int suiteId, JsonNode c) {
        return new ContextFields(suiteId, hex(c.path("table_uuid")), hex(c.path("column_uuid")),
                optional(c.path("tenant_id")), optional(c.path("row_id")),
                c.path("purpose").asText());
    }

    private static byte[] optional(JsonNode n) {
        if (n.isNull()) {
            return null;
        }
        if (n.isMissingNode()) {
            throw new IllegalArgumentException("an optional context field must be present or null");
        }
        return hex(n);
    }
}
