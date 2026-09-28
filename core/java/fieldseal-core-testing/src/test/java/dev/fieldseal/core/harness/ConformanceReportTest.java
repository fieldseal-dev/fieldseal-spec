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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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

    private static Map<String, List<Outcome>> pinsPassing() {
        Map<String, List<Outcome>> m = new LinkedHashMap<>();
        ConformanceReport.PINNED_TESTS.forEach((key, tests) -> m.put(key, tests.stream()
                .map(t -> new Outcome(t + "()", true, Status.PASS, null)).toList()));
        return m;
    }

    private static Assembled assemble(List<Outcome> harness, Map<String, List<Outcome>> oob) {
        return assemble(harness, oob, pinsPassing());
    }

    private static Assembled assemble(List<Outcome> harness, Map<String, List<Outcome>> oob,
            Map<String, List<Outcome>> pins) {
        return ConformanceReport.assemble(manifest, expected, harness, oob,
                ConformanceReport.OUT_OF_BAND, pins,
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

    /**
     * #225: a backed pinned decision whose test did not run, or failed, is a problem, and the L0
     * claim goes with it. The key's text stays: it states the decision, and the problem says it is
     * not backed.
     */
    @Test
    void aBackedPinWhoseTestFailsOrDidNotRunIsAProblem() {
        for (List<Outcome> ran : List.of(List.<Outcome>of(),
                List.of(new Outcome("theIndexRoleHasNoUseBudget()", true, Status.FAIL, "evicted")),
                List.of(new Outcome("EnvelopeProviderTest", false, Status.FAIL, "no class")))) {
            Map<String, List<Outcome>> pins = pinsPassing();
            pins.put("index-role-use-budget", ran);
            Assembled a = assemble(allPassing(), oobPassing(), pins);
            assertEquals(1, a.problems().size(), a.problems().toString());
            assertTrue(a.problems().get(0).startsWith(
                    "pinned_decisions.index-role-use-budget is not backed: "), a.problems().get(0));
            assertFalse(a.report().path("claimed_levels").path("L0").asBoolean());
            assertEquals(List.of(), validate(a.report()));
        }
    }

    /**
     * Each backed key's text cites its tests, and each test exists as a JUnit test: the report
     * would record a renamed one as not run, and this says which.
     */
    @Test
    void eachBackedPinCitesTestsThatExist() throws ReflectiveOperationException {
        assertEquals(Set.of("index-role-use-budget"), ConformanceReport.PINNED_TESTS.keySet());
        for (var e : ConformanceReport.PINNED_TESTS.entrySet()) {
            String text = ConformanceReport.PINNED_DECISIONS.get(e.getKey());
            assertFalse(e.getValue().isEmpty(), e.getKey());
            for (String t : e.getValue()) {
                String cls = t.substring(0, t.indexOf('#'));
                String method = t.substring(t.indexOf('#') + 1);
                String cited = cls.substring(cls.lastIndexOf('.') + 1) + "." + method;
                assertTrue(text.contains(cited), e.getKey() + " does not cite " + cited);
                assertTrue(Class.forName(cls).getDeclaredMethod(method)
                        .isAnnotationPresent(Test.class), t + " is not a @Test");
            }
        }
    }

    /**
     * A test that does not exist runs no test: the launcher reports a failed discovery instead,
     * and {@link ConformanceReport#unmet} counts zero tests of one. The control: the real backing
     * tests run, each once, and pass.
     */
    @Test
    void aMissingBackingTestIsUnmet() {
        for (List<String> real : ConformanceReport.PINNED_TESTS.values()) {
            List<Outcome> ran = ConformanceReport.runMethods(real);
            assertEquals(real.size(), ran.stream().filter(Outcome::test).count(), ran.toString());
            assertEquals(null, ConformanceReport.unmet(real, ran));
        }
        List<String> missing = List.of(
                "dev.fieldseal.core.EnvelopeProviderTest#theIndexRoleHasNoUseBudgetRenamed");
        List<Outcome> ran = ConformanceReport.runMethods(missing);
        assertEquals(0, ran.stream().filter(Outcome::test).count(), ran.toString());
        assertTrue(ConformanceReport.unmet(missing, ran).startsWith("0 of 1 named tests ran"));
    }

    /**
     * A problem found after assembly (the schema check, a validation violation) withdraws the L0
     * claim in the printed report, and the report still validates.
     */
    @Test
    void aLateProblemWithdrawsTheL0Claim() {
        Assembled a = assemble(allPassing(), oobPassing());
        ConformanceReport.finish(a.report(), List.of());
        assertTrue(a.report().path("claimed_levels").path("L0").asBoolean(), "no problem");
        ConformanceReport.finish(a.report(), List.of("vectors/schema/ exists"));
        assertFalse(a.report().path("claimed_levels").path("L0").asBoolean());
        assertEquals(List.of(), validate(a.report()));
    }

    /**
     * What {@code main} runs after assembly: a {@code schema/} directory beside the manifest, or a
     * report that fails validation, is a problem, and the claim is withdrawn before printing.
     */
    @Test
    void concludeWithdrawsTheClaimForTheSchemaCheckAndForAViolation(@TempDir Path dir)
            throws IOException {
        Assembled clean = assemble(allPassing(), oobPassing());
        assertEquals(List.of(), ConformanceReport.conclude(dir, manifest, expected, clean));
        assertTrue(clean.report().path("claimed_levels").path("L0").asBoolean());

        Files.createDirectory(dir.resolve("schema"));
        Assembled schema = assemble(allPassing(), oobPassing());
        List<String> p = ConformanceReport.conclude(dir, manifest, expected, schema);
        assertTrue(p.size() == 1 && p.get(0).startsWith("vectors/schema/ exists"), p.toString());
        assertFalse(schema.report().path("claimed_levels").path("L0").asBoolean());

        Assembled invalid = assemble(allPassing(), oobPassing());
        ((ObjectNode) invalid.report().path("environment")).remove("os");
        p = ConformanceReport.conclude(vectors, manifest, expected, invalid);
        assertTrue(p.stream().anyMatch(x -> x.startsWith("invalid: environment.os")), p.toString());
        assertFalse(invalid.report().path("claimed_levels").path("L0").asBoolean());
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
        List<String> keys = new ArrayList<>(ConformanceReport.MANDATORY_PINNED);
        keys.add("index-role-use-budget");
        for (String k : keys) {
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
