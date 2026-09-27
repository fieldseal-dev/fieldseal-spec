package dev.fieldseal.core.harness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.fieldseal.core.harness.ConformanceReport.Assembled;
import dev.fieldseal.core.harness.ConformanceReport.Outcome;
import dev.fieldseal.core.harness.ConformanceReport.Status;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The report's assembly and its validation (docs/14 §4; docs/27 §9 gate D), against the pinned
 * suite's required ids and synthetic outcomes. Running the tests is the launcher's business and
 * the {@code vectors} task's; what is checked here is what the report makes of what ran, and that
 * each rule a reader relies on is one {@link ConformanceReport#validate} enforces.
 */
class ConformanceReportTest {

    private static Path vectors;
    private static JsonNode manifest;
    private static List<String> expected;

    @BeforeAll
    static void suite() throws IOException {
        vectors = Path.of(System.getProperty("fieldseal.vectors"));
        VectorHarness.Walk walk = VectorHarness.walk(vectors);
        assertEquals(List.of(), walk.problems());
        manifest = VectorHarness.read(vectors.resolve("MANIFEST.json"));
        expected = ConformanceReport.expectedIds(vectors, walk);
    }

    /** Every vector once, #decrypt per envelope/ vector, #pipeline per primitive blind-index/. */
    @Test
    void theRequiredIdsFollowTheSuite() throws IOException {
        int vectorCount = 0;
        int envelope = 0;
        int primitive = 0;
        for (VectorHarness.FileWalk f : VectorHarness.walk(vectors).files()) {
            for (JsonNode v : VectorHarness.read(vectors.resolve(f.path())).path("vectors")) {
                vectorCount++;
                assertTrue(expected.contains(v.path("id").asText()), v.path("id").asText());
                envelope += f.path().startsWith("envelope/") ? 1 : 0;
                primitive += f.path().startsWith("blind-index/") && !v.has("assertion") ? 1 : 0;
            }
        }
        assertEquals(vectorCount + envelope + primitive, expected.size());
        assertEquals(envelope, expected.stream().filter(i -> i.endsWith("#decrypt")).count());
        assertEquals(primitive, expected.stream().filter(i -> i.endsWith("#pipeline")).count());
        assertEquals(expected.size(), new java.util.HashSet<>(expected).size());
    }

    // --- assembly ------------------------------------------------------------------------------

    private static List<Outcome> allPassing() {
        List<Outcome> out = new ArrayList<>();
        expected.forEach(id -> out.add(new Outcome(id, true, Status.PASS, null)));
        out.add(new Outcome("aHarnessCheck()", true, Status.PASS, null));
        return out;
    }

    private static Map<String, List<Outcome>> oobPassing() {
        Map<String, List<Outcome>> m = new LinkedHashMap<>();
        for (ConformanceReport.OutOfBand e : ConformanceReport.OUT_OF_BAND) {
            m.put(e.id(), e.tests().stream()
                    .map(t -> new Outcome(t + "()", true, Status.PASS, null)).toList());
        }
        return m;
    }

    private static Assembled assemble(List<Outcome> harness, Map<String, List<Outcome>> oob) {
        return ConformanceReport.assemble(manifest, expected, harness, oob,
                ConformanceReport.OUT_OF_BAND,
                ConformanceReport.implementation(vectors), ConformanceReport.environment());
    }

    private static List<String> validate(JsonNode r) {
        return ConformanceReport.validate(r, manifest, expected);
    }

    @Test
    void allPassingIsAValidL0Report() {
        Assembled a = assemble(allPassing(), oobPassing());
        assertEquals(List.of(), a.problems());
        assertEquals(List.of(), validate(a.report()));
        JsonNode r = a.report();
        assertTrue(r.path("claimed_levels").path("L0").asBoolean());
        assertEquals(expected.size(), r.path("summary").path("pass").asInt());
        assertEquals(0, r.path("summary").path("fail").asInt());
        assertEquals(manifest.path("vector_suite_version").asText(),
                r.path("vector_suite_version").asText());
        assertTrue(r.path("provisional_suites").asBoolean());
        assertFalse(r.path("async_companions").asBoolean());
        ConformanceReport.MANDATORY_PINNED.forEach(k ->
                assertFalse(r.path("pinned_decisions").path(k).asText().isBlank(), k));
        List<String> basis = new ArrayList<>();
        r.path("out_of_band").forEach(o -> basis.add(o.path("id").asText() + "="
                + o.path("basis").asText() + "/" + o.path("status").asText()));
        assertEquals(List.of("spec/3.5/length-bound=seam/pass",
                "spec/3.5/length-bound#decrypt=seam/pass",
                "docs/09/7.1/lone-surrogate-refusal=direct/pass"), basis);
    }

    @Test
    void aVectorNoTestRanIsAFailedResultNotAnAbsentOne() {
        List<Outcome> harness = allPassing();
        String dropped = expected.get(3);
        harness.removeIf(o -> o.name().equals(dropped));
        Assembled a = assemble(harness, oobPassing());
        JsonNode r = a.report();
        JsonNode e = result(r, dropped);
        assertEquals("fail", e.path("status").asText());
        assertTrue(e.path("reason").asText().startsWith("not run"));
        assertEquals(1, r.path("summary").path("fail").asInt());
        assertFalse(r.path("claimed_levels").path("L0").asBoolean());
        assertEquals(List.of(), validate(r), "a failing report still validates");
    }

    @Test
    void aFailingTestIsAFailedResultWithItsReason() {
        List<Outcome> harness = allPassing();
        String id = expected.get(0);
        harness.replaceAll(o -> o.name().equals(id)
                ? new Outcome(id, true, Status.FAIL, "AssertionFailedError: raw") : o);
        JsonNode e = result(assemble(harness, oobPassing()).report(), id);
        assertEquals("fail", e.path("status").asText());
        assertEquals("AssertionFailedError: raw", e.path("reason").asText());
    }

    @Test
    void whatTheSuiteDoesNotAccountForIsAProblem() {
        List<Outcome> harness = allPassing();
        harness.add(new Outcome("kdf/record-key/not-in-the-suite", true, Status.PASS, null));
        harness.add(new Outcome(expected.get(0), true, Status.PASS, null));
        harness.add(new Outcome("envelopeFamily()", false, Status.FAIL, "counts moved"));
        harness.add(new Outcome("aHarnessCheck()", true, Status.FAIL, "distinguishable"));
        List<String> problems = assemble(harness, oobPassing()).problems();
        assertEquals(4, problems.size(), problems.toString());
        assertTrue(problems.get(0).contains("not-in-the-suite"));
        assertTrue(problems.get(1).startsWith("two tests report"));
        assertTrue(problems.get(2).startsWith("container failed: envelopeFamily()"));
        assertTrue(problems.get(3).startsWith("harness check aHarnessCheck()"));
        assertFalse(assemble(harness, oobPassing()).report().path("claimed_levels").path("L0")
                .asBoolean());
    }

    @Test
    void anOutOfBandTestThatFailsOrDidNotRunFailsItsEntry() {
        Map<String, List<Outcome>> oob = oobPassing();
        oob.put("spec/3.5/length-bound", oob.get("spec/3.5/length-bound").subList(0, 1));
        oob.put("docs/09/7.1/lone-surrogate-refusal", List.of(
                new Outcome("a()", true, Status.PASS, null),
                new Outcome("b()", true, Status.FAIL, "same message")));
        JsonNode r = assemble(allPassing(), oob).report();
        assertEquals("fail", r.path("out_of_band").get(0).path("status").asText());
        assertEquals("pass", r.path("out_of_band").get(1).path("status").asText());
        assertEquals("fail", r.path("out_of_band").get(2).path("status").asText());
        assertFalse(r.path("claimed_levels").path("L0").asBoolean());
        assertEquals(List.of(), validate(r));
    }

    // --- validation: each rule, broken once ---------------------------------------------------

    private static void assertInvalid(String fragment, Consumer<ObjectNode> breakIt) {
        ObjectNode r = assemble(allPassing(), oobPassing()).report().deepCopy();
        breakIt.accept(r);
        List<String> v = validate(r);
        assertTrue(v.stream().anyMatch(x -> x.contains(fragment)),
                "expected a violation containing '" + fragment + "', got " + v);
    }

    @Test
    void eachRuleIsEnforced() {
        assertInvalid("schema", r -> r.put("schema", "fieldseal-conformance/v2"));
        assertInvalid("implementation.commit", r -> ((ObjectNode) r.path("implementation"))
                .remove("commit"));
        assertInvalid("vector_suite_version", r -> r.put("vector_suite_version", "0.0.1"));
        assertInvalid("provisional_suites", r -> r.put("provisional_suites", false));
        assertInvalid("environment.unicode_tables", r -> ((ObjectNode) r.path("environment"))
                .remove("unicode_tables"));
        for (String k : ConformanceReport.MANDATORY_PINNED) {
            assertInvalid("pinned_decisions." + k, r -> ((ObjectNode) r.path("pinned_decisions"))
                    .remove(k));
        }
        assertInvalid("duplicate id", r -> ((ArrayNode) r.path("results"))
                .add(r.path("results").get(0).deepCopy()));
        assertInvalid("not exactly the ids", r -> ((ArrayNode) r.path("results")).remove(0));
        assertInvalid("carries no reason", r -> ((ObjectNode) r.path("results").get(0))
                .put("status", "skipped"));
        assertInvalid("not pass, fail or skipped", r -> ((ObjectNode) r.path("results").get(0))
                .put("status", "not-verified"));
        assertInvalid("#async", r -> ((ObjectNode) r.path("results").get(0))
                .put("id", expected.get(0) + "#async"));
        assertInvalid("held_out does not mirror", r -> ((ArrayNode) r.path("held_out"))
                .addObject().put("path", "kdf/x.json").put("status", "not-run")
                .put("reason", "r"));
        assertInvalid("out_of_band is not exactly", r -> ((ArrayNode) r.path("out_of_band"))
                .remove(2));
        assertInvalid("basis", r -> ((ObjectNode) r.path("out_of_band").get(0))
                .put("basis", "argument"));
        assertInvalid("async_companions", r -> r.put("async_companions", true));
        assertInvalid("summary", r -> ((ObjectNode) r.path("summary")).put("pass", 1));
        assertInvalid("L0 is claimed", r -> {
            ((ObjectNode) r.path("results").get(0)).put("status", "fail").put("reason", "x");
            ((ObjectNode) r.path("summary")).put("pass", expected.size() - 1).put("fail", 1);
        });
        assertInvalid("L0 is claimed", r -> ((ObjectNode) r.path("out_of_band").get(1))
                .put("status", "not-run"));
    }

    private static JsonNode result(JsonNode r, String id) {
        for (JsonNode e : r.path("results")) {
            if (e.path("id").asText().equals(id)) {
                return e;
            }
        }
        throw new AssertionError("no result " + id);
    }
}
