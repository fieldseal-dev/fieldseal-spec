package dev.fieldseal.core.harness;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.fieldseal.core.Fieldseal;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.platform.engine.DiscoverySelector;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.EngineFilter;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

/**
 * The conformance report (docs/14 §4; docs/08 §5 item 6; docs/27 §8, S6), printed by {@code
 * ./gradlew -q vectors}.
 *
 * <p><b>Where the results come from.</b> Not from a second implementation of the harness: this
 * class runs the build's own vector tests again through the JUnit launcher, in one process, and
 * reads each dynamic test's outcome under its name, which is the vector id plus the docs/14 §4
 * suffix. So a result and the test {@code ./gradlew build} runs are the same code. {@link
 * #HARNESS} lists the classes whose dynamic tests are results; {@link #OUT_OF_BAND} names the
 * tests behind each out-of-band entry, and {@link #PINNED_TESTS} the tests behind each pinned
 * decision that one backs (#225).
 *
 * <p><b>What cannot go missing silently.</b> The ids a run must produce are computed from the
 * suite, not from the run: every vector of every file {@code MANIFEST.files} lists, plus {@code
 * #decrypt} for {@code envelope/} and {@code #pipeline} for a {@code blind-index/} primitive
 * vector. An expected id no test produced is a failed result that says so; a vector-named test
 * that no expected id matches, a duplicated one, a failed container or a failed harness check
 * outside the results is a problem, and so is a backed pinned decision whose tests did not all run
 * and pass. Problems are printed to stderr and fail the run, and so does a report that does not
 * validate ({@link #validate}).
 */
public final class ConformanceReport {

    static final String SCHEMA = "fieldseal-conformance/v1";

    /** docs/14 §4: the keys every core MUST carry. */
    static final List<String> MANDATORY_PINNED = List.of("decrypt-order", "aad-mismatch",
            "api-boundary-order", "unimplemented-registered-suite", "commitment-construction",
            "key-material-ownership");

    /** docs/14 §4: the out-of-band ids every core reports. */
    static final List<String> OUT_OF_BAND_IDS = List.of("spec/3.5/length-bound",
            "spec/3.5/length-bound#decrypt", "docs/09/7.1/lone-surrogate-refusal");

    /** The classes whose dynamic tests are the results, each result from exactly one of them. */
    static final List<Class<?>> HARNESS = List.of(KdfVectorsTest.class,
            ContextVectorsTest.class, CommitmentVectorsTest.class, EnvelopeVectorsTest.class,
            ClientVectorsTest.class, BlindIndexVectorsTest.class);

    /** One out-of-band entry: its basis and method, and the tests ({@code Class#method}) behind it. */
    record OutOfBand(String id, String basis, String method, List<String> tests) {}

    static final List<OutOfBand> OUT_OF_BAND = List.of(
            new OutOfBand("spec/3.5/length-bound", "seam", "seam: byte[] length is int, so a"
                    + " 2^31-byte operand is unrepresentable here and the guard is unreachable"
                    + " from the public byte[] API. The refusal is proven on synthetic operands of"
                    + " length 2^31, 2^32 and Long.MAX_VALUE, driven through the internal Operand"
                    + " pipeline that the public encrypt (byte[]) enters, and through the codec's"
                    + " guard: LENGTH_EXCEEDED, zero key-provider calls and zero operand reads"
                    + " (SeamWiringTest, BufferLimitsWiringTest). Moving the guard one statement"
                    + " later turns them red (core/java/scripts/bite_checks.py).",
                    List.of("dev.fieldseal.core.SeamWiringTest"
                                    + "#encryptRefusesBeforeAnyProviderCallOrRead",
                            "dev.fieldseal.core.internal.envelope.BufferLimitsWiringTest"
                                    + "#encryptRefusesA2To31ByteOperandWithoutReadingIt")),
            new OutOfBand("spec/3.5/length-bound#decrypt", "seam", "seam: byte[] length is int,"
                    + " so an envelope implying a plaintext of 2^31 bytes or more is"
                    + " unrepresentable here and the guard is unreachable from the public byte[]"
                    + " API. The refusal is proven on synthetic 0xFF01 envelopes whose implied"
                    + " plaintext length (received length minus the suite's fixed overhead) is"
                    + " 2^31, 2^32 and near Long.MAX_VALUE, driven through the internal Operand"
                    + " pipeline that the public decrypt and rotate (byte[]) enter, and through"
                    + " the codec's decrypt front: LENGTH_EXCEEDED, zero key-provider calls, and"
                    + " no read past the three recognition bytes (SeamWiringTest,"
                    + " BufferLimitsWiringTest).",
                    List.of("dev.fieldseal.core.SeamWiringTest"
                                    + "#decryptAndRotateRefuseBeforeAnyProviderCallOrReadPastRecognition",
                            "dev.fieldseal.core.internal.envelope.BufferLimitsWiringTest"
                                    + "#decryptRefusesAnImpliedPlaintextOf2To31BeforeParsing")),
            new OutOfBand("docs/09/7.1/lone-surrogate-refusal", "direct", "\"a\\uD800b\" and"
                    + " \"a\\uDC00b\" are both refused with INVALID_ARGUMENT, by nfc-casefold-v1"
                    + " (Normalizers) and through the public blindIndex(String), and the two"
                    + " refusals are distinguishable: the messages differ, naming U+D800 and"
                    + " U+DC00 (NormalizersTest, BlindIndexClientTest).",
                    List.of("dev.fieldseal.core.internal.blindindex.NormalizersTest"
                                    + "#refusesTwoDistinctLoneSurrogatesDistinguishably",
                            "dev.fieldseal.core.BlindIndexClientTest"
                                    + "#twoLoneSurrogatesAreRefusedDistinguishably")));

    /**
     * The pinned decisions a test backs, and the tests ({@code Class#method}) behind each (#225).
     * A rule with no bytes to compare cannot be a vector (docs/08 §8), so the report runs the test
     * that proves it, and a backing test that is missing or not passing is a problem. A backing
     * test is a single Jupiter {@code @Test} method: {@link #run} filters to the Jupiter engine,
     * so a jqwik {@code @Property} would run no test, and a {@code @ParameterizedTest} or {@code
     * @TestFactory} more than one ({@code ConformanceReportTest} refuses both). Insertion-ordered,
     * so the problems and violations it produces come out in the same order on every run.
     */
    static final Map<String, List<String>> PINNED_TESTS = pinnedTests();

    private static Map<String, List<String>> pinnedTests() {
        Map<String, List<String>> m = new LinkedHashMap<>();
        m.put("index-role-use-budget",
                List.of("dev.fieldseal.core.EnvelopeProviderTest#theIndexRoleHasNoUseBudget"));
        return Collections.unmodifiableMap(m);
    }

    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private ConformanceReport() {}

    // --- running -------------------------------------------------------------------------------

    enum Status { PASS, FAIL, SKIPPED }

    /** One finished test or failed container, as the launcher reported it. */
    record Outcome(String name, boolean test, Status status, String reason) {}

    /** Runs {@code selectors} and returns every test's outcome and every failed container. */
    static List<Outcome> run(List<DiscoverySelector> selectors) {
        List<Outcome> out = Collections.synchronizedList(new ArrayList<>());
        TestExecutionListener listener = new TestExecutionListener() {
            @Override
            public void executionFinished(TestIdentifier id, TestExecutionResult r) {
                if (!id.isTest() && r.getStatus() == TestExecutionResult.Status.SUCCESSFUL) {
                    return;
                }
                Status s = r.getStatus() == TestExecutionResult.Status.SUCCESSFUL
                        ? Status.PASS : Status.FAIL;
                String reason = r.getThrowable().map(ConformanceReport::describe)
                        .orElse(s == Status.PASS ? null : r.getStatus().toString());
                out.add(new Outcome(id.getDisplayName(), id.isTest(), s, reason));
            }

            @Override
            public void executionSkipped(TestIdentifier id, String reason) {
                out.add(new Outcome(id.getDisplayName(), id.isTest(), Status.SKIPPED, reason));
            }
        };
        Launcher launcher = LauncherFactory.create();
        // Jupiter only: fieldseal-core's test classpath also carries jqwik's engine, and the
        // selected tests are all Jupiter's.
        launcher.execute(LauncherDiscoveryRequestBuilder.request().selectors(selectors)
                .filters(EngineFilter.includeEngines("junit-jupiter")).build(), listener);
        return List.copyOf(out);
    }

    /** Runs the named tests ({@code Class#method}). */
    static List<Outcome> runMethods(List<String> tests) {
        return run(tests.stream().map(t -> (DiscoverySelector) selectMethod(t)).toList());
    }

    private static String describe(Throwable t) {
        String m = t.getClass().getSimpleName() + ": " + t.getMessage();
        m = m.replaceAll("\\s+", " ").strip();
        return m.length() <= 500 ? m : m.substring(0, 497) + "...";
    }

    // --- what the suite requires ---------------------------------------------------------------

    /**
     * Every result id the pinned suite requires of this core, in manifest and file order: each
     * vector's id, then its suffixed results (docs/14 §4's conventions).
     */
    static List<String> expectedIds(Path vectorsDir, VectorHarness.Walk walk) throws IOException {
        List<String> ids = new ArrayList<>();
        for (VectorHarness.FileWalk f : walk.files()) {
            String family = f.path().substring(0, f.path().indexOf('/'));
            for (JsonNode v : VectorHarness.read(vectorsDir.resolve(f.path())).path("vectors")) {
                String id = v.path("id").asText();
                ids.add(id);
                if (family.equals("envelope")) {
                    ids.add(id + "#decrypt");
                } else if (family.equals("blind-index") && !v.has("assertion")) {
                    ids.add(id + "#pipeline");
                }
            }
        }
        return ids;
    }

    // --- assembling ----------------------------------------------------------------------------

    /** The report, and every problem found while assembling it. */
    record Assembled(ObjectNode report, List<String> problems) {}

    /**
     * Builds the report from what ran. {@code harness} is every outcome of {@link #HARNESS};
     * {@code outOfBand} maps each entry's id to its tests' outcomes, and {@code pinnedRuns} each
     * {@link #PINNED_TESTS} key to its tests' outcomes.
     */
    static Assembled assemble(JsonNode manifest, List<String> expected, List<Outcome> harness,
            Map<String, List<Outcome>> outOfBand, List<OutOfBand> entries,
            Map<String, List<Outcome>> pinnedRuns, ObjectNode implementation,
            ObjectNode environment) {
        List<String> problems = new ArrayList<>();
        Set<String> wanted = new HashSet<>(expected);
        Map<String, Outcome> byId = new LinkedHashMap<>();
        for (Outcome o : harness) {
            if (!o.test()) {
                problems.add("container failed: " + o.name() + ": " + o.reason());
            } else if (wanted.contains(o.name())) {
                if (byId.putIfAbsent(o.name(), o) != null) {
                    problems.add("two tests report result id " + o.name());
                }
            } else if (o.name().contains("/")) {
                problems.add("a test reports " + o.name() + ", which the suite does not require");
            } else if (o.status() != Status.PASS) {
                problems.add("harness check " + o.name() + ": " + o.status() + ": " + o.reason());
            }
        }

        ObjectNode r = JSON.createObjectNode();
        r.put("schema", SCHEMA);
        r.set("implementation", implementation);
        r.put("vector_suite_version", manifest.path("vector_suite_version").asText());
        r.put("spec_version", manifest.path("spec_version").asText());
        ObjectNode levels = r.putObject("claimed_levels");
        r.putArray("suites_supported").add("0xFF01");
        r.put("provisional_suites", true);
        r.set("environment", environment);
        ObjectNode pinned = r.putObject("pinned_decisions");
        PINNED_DECISIONS.forEach(pinned::put);
        PINNED_TESTS.forEach((key, named) -> {
            String unmet = unmet(named, pinnedRuns.getOrDefault(key, List.of()));
            if (unmet != null) {
                problems.add("pinned_decisions." + key + " is not backed: " + unmet);
            }
        });
        ArrayNode notes = r.putArray("harness_notes");
        HARNESS_NOTES.forEach(notes::add);

        int pass = 0;
        int fail = 0;
        int skipped = 0;
        ArrayNode results = r.putArray("results");
        for (String id : expected) {
            Outcome o = byId.get(id);
            ObjectNode e = results.addObject().put("id", id);
            if (o == null) {
                e.put("status", "fail").put("reason", "not run: no test produced this result");
                fail++;
            } else if (o.status() == Status.PASS) {
                e.put("status", "pass");
                pass++;
            } else if (o.status() == Status.SKIPPED) {
                e.put("status", "skipped").put("reason", String.valueOf(o.reason()));
                skipped++;
            } else {
                e.put("status", "fail").put("reason", String.valueOf(o.reason()));
                fail++;
            }
        }

        ArrayNode heldOut = r.putArray("held_out");
        for (JsonNode h : manifest.path("held_out")) {
            heldOut.addObject().put("path", h.path("path").asText()).put("status", "not-run")
                    .put("reason", h.path("reason").asText("held out by MANIFEST.json; a"
                            + " conformance run iterates files only (docs/14 §4)"));
        }

        ArrayNode oob = r.putArray("out_of_band");
        boolean oobPass = true;
        for (OutOfBand entry : entries) {
            String unmet = unmet(entry.tests(), outOfBand.getOrDefault(entry.id(), List.of()));
            ObjectNode e = oob.addObject().put("id", entry.id());
            if (unmet == null) {
                e.put("status", "pass");
            } else {
                oobPass = false;
                e.put("status", "fail").put("reason", unmet);
            }
            e.put("basis", entry.basis()).put("method", entry.method());
        }

        r.put("async_companions", false);
        levels.put("L0", fail == 0 && skipped == 0 && oobPass && problems.isEmpty());
        r.putObject("summary").put("pass", pass).put("fail", fail).put("skipped", skipped)
                .put("held_out", heldOut.size());
        return new Assembled(r, problems);
    }

    /**
     * Null when every one of the {@code named} tests ran and passed and nothing else failed in
     * {@code ran}; otherwise why not.
     */
    static String unmet(List<String> named, List<Outcome> ran) {
        long tests = ran.stream().filter(Outcome::test).count();
        List<String> failing = ran.stream().filter(o -> o.status() != Status.PASS)
                .map(o -> o.name() + ": " + o.status() + ": " + o.reason()).toList();
        return tests == named.size() && failing.isEmpty() ? null
                : tests + " of " + named.size() + " named tests ran; " + failing;
    }

    /**
     * Withdraws the L0 claim when the run found any problem, including those found after
     * {@link #assemble}: the {@code vectors/schema/} check and every {@link #validate} violation.
     * The printed report is the artifact CI uploads, so it must not claim a level the run did not
     * earn (#219 review). A withdrawn claim never adds a violation, so validation need not run
     * again.
     */
    static void finish(ObjectNode report, List<String> problems) {
        if (!problems.isEmpty()) {
            ((ObjectNode) report.path("claimed_levels")).put("L0", false);
        }
    }

    /**
     * Everything the run does after {@link #assemble}: the {@code vectors/schema/} check, the
     * assembly's own problems, every {@link #validate} violation, then {@link #finish}. {@code
     * main} calls this and nothing else between assembling and printing, so a test of it is a test
     * of what {@code main} prints (#219 re-review).
     *
     * @return every problem, in the order found
     */
    static List<String> conclude(Path vectors, JsonNode manifest, List<String> expected,
            Assembled a) {
        List<String> problems = new ArrayList<>();
        if (Files.exists(vectors.resolve("schema"))) {
            problems.add("vectors/schema/ exists and this harness does not validate against it"
                    + " (docs/08 §5 item 2); the harness note says it does not exist");
        }
        problems.addAll(a.problems());
        validate(a.report(), manifest, expected).forEach(v -> problems.add("invalid: " + v));
        finish(a.report(), problems);
        return problems;
    }

    // --- validating ----------------------------------------------------------------------------

    /**
     * docs/14 §4 and docs/27 §9 gate D, checked on the document itself: what a reader relies on
     * holds, whatever produced it. Returns every violation; none means the report validates.
     */
    static List<String> validate(JsonNode r, JsonNode manifest, List<String> expected) {
        List<String> v = new ArrayList<>();
        if (!SCHEMA.equals(r.path("schema").asText())) {
            v.add("schema is not " + SCHEMA);
        }
        for (String f : List.of("name", "version", "commit", "language")) {
            if (r.path("implementation").path(f).asText("").isBlank()) {
                v.add("implementation." + f + " is missing");
            }
        }
        if (!manifest.path("vector_suite_version").asText().equals(
                r.path("vector_suite_version").asText(null))) {
            v.add("vector_suite_version is not the manifest's");
        }
        if (!r.path("claimed_levels").path("L0").isBoolean()) {
            v.add("claimed_levels.L0 is not a boolean");
        }
        boolean provisional = false;
        for (JsonNode s : r.path("suites_supported")) {
            int id = Integer.decode(s.asText());
            provisional |= id >= 0xFF00 && id <= 0xFFFF;
        }
        if (r.path("suites_supported").isEmpty() || !r.path("provisional_suites").isBoolean()
                || r.path("provisional_suites").asBoolean() != provisional) {
            v.add("provisional_suites does not follow suites_supported (spec §4.8)");
        }
        for (String f : List.of("runtime", "os", "crypto_backend", "unicode_platform",
                "unicode_tables")) {
            if (r.path("environment").path(f).asText("").isBlank()) {
                v.add("environment." + f + " is missing");
            }
        }
        List<String> keys = new ArrayList<>(MANDATORY_PINNED);
        keys.addAll(PINNED_TESTS.keySet());
        for (String k : keys) {
            if (r.path("pinned_decisions").path(k).asText("").isBlank()) {
                v.add("pinned_decisions." + k + " is missing");
            }
        }
        if (!r.path("harness_notes").isArray()) {
            v.add("harness_notes is not a list");
        }

        List<String> ids = new ArrayList<>();
        int[] counts = new int[3];
        for (JsonNode e : r.path("results")) {
            String id = e.path("id").asText();
            ids.add(id);
            String status = e.path("status").asText();
            switch (status) {
                case "pass" -> counts[0]++;
                case "fail" -> counts[1]++;
                case "skipped" -> counts[2]++;
                default -> v.add(id + ": status '" + status + "' is not pass, fail or skipped");
            }
            if (!status.equals("pass") && e.path("reason").asText("").isBlank()) {
                v.add(id + ": a " + status + " result carries no reason");
            }
            if (id.endsWith("#async")) {
                v.add(id + ": an #async result, and async_companions is false");
            }
        }
        if (new HashSet<>(ids).size() != ids.size()) {
            v.add("results carry a duplicate id");
        }
        if (!ids.equals(expected)) {
            v.add("results are not exactly the ids the suite requires");
        }

        List<String> held = new ArrayList<>();
        manifest.path("held_out").forEach(h -> held.add(h.path("path").asText()));
        List<String> reported = new ArrayList<>();
        for (JsonNode h : r.path("held_out")) {
            reported.add(h.path("path").asText());
            if (!"not-run".equals(h.path("status").asText())
                    || h.path("reason").asText("").isBlank()) {
                v.add("held_out " + h.path("path") + " is not not-run with a reason");
            }
        }
        if (!r.path("held_out").isArray() || !reported.equals(held)) {
            v.add("held_out does not mirror the manifest");
        }

        List<String> oobIds = new ArrayList<>();
        boolean oobPass = true;
        for (JsonNode o : r.path("out_of_band")) {
            oobIds.add(o.path("id").asText());
            String status = o.path("status").asText();
            if (!Set.of("pass", "fail", "not-run").contains(status)) {
                v.add(o.path("id") + ": out-of-band status '" + status + "'");
            }
            oobPass &= status.equals("pass");
            if (!Set.of("direct", "seam", "representability").contains(
                    o.path("basis").asText())) {
                v.add(o.path("id") + ": basis is not direct, seam or representability");
            }
            if (o.path("method").asText("").isBlank()) {
                v.add(o.path("id") + ": no method");
            }
        }
        if (!oobIds.equals(OUT_OF_BAND_IDS)) {
            v.add("out_of_band is not exactly " + OUT_OF_BAND_IDS);
        }

        if (!r.path("async_companions").isBoolean() || r.path("async_companions").asBoolean()) {
            v.add("async_companions is not false (docs/27 §4: no companions)");
        }
        JsonNode s = r.path("summary");
        if (s.path("pass").asInt(-1) != counts[0] || s.path("fail").asInt(-1) != counts[1]
                || s.path("skipped").asInt(-1) != counts[2]
                || s.path("held_out").asInt(-1) != held.size()) {
            v.add("summary does not count the results and held_out");
        }
        if (r.path("claimed_levels").path("L0").asBoolean() && (counts[1] > 0 || !oobPass)) {
            v.add("L0 is claimed with a failing result or out-of-band entry (docs/14 §4)");
        }
        return v;
    }

    // --- the fixed text --------------------------------------------------------------------------

    /**
     * docs/14 §4's six keys, and two of this core's own: {@code platform-byte-buffer-max} (docs/27
     * §6.5) and {@code index-role-use-budget}, which {@link #PINNED_TESTS} backs (#225).
     */
    static final Map<String, String> PINNED_DECISIONS = pinned();

    private static Map<String, String> pinned() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("decrypt-order", "the operand (null: INVALID_ARGUMENT) -> recognition"
                + " (UNKNOWN_FORMAT_VERSION for the reserved fmt_ver; a non-envelope is"
                + " NOT_CIPHERTEXT in strict, and returned as-is, the same array, in permissive"
                + " and readonly) -> LENGTH_EXCEEDED (implied plaintext length >= 2^31, before any"
                + " field past the three recognition bytes is read) -> SUITE_NOT_ALLOWED -> the"
                + " context (INVALID_ARGUMENT) -> KEY_UNAVAILABLE -> per candidate key: the"
                + " commitment, then, only once it verifies, the tag (TAG_INVALID) ->"
                + " COMMITMENT_INVALID when no candidate's commitment verifies. docs/27 §4.");
        m.put("aad-mismatch", "never raised. On the 0xFF01 path a wrong context changes"
                + " record_key, so it fails the commitment exactly as a wrong key does, and"
                + " surfaces as COMMITMENT_INVALID (spec §4.6, §6.3; docs/09 §3.2 step 7; G5)."
                + " 0xFF02 is not built.");
        m.put("api-boundary-order", "encrypt: MODE_VIOLATION (readonly) -> SUITE_PROVISIONAL"
                + " (write suite provisional and unarmed) -> the operand (null: INVALID_ARGUMENT;"
                + " longer than 2^31-1 bytes: LENGTH_EXCEEDED) -> the context (INVALID_ARGUMENT)"
                + " -> key acquisition (KEY_UNAVAILABLE). rotate: MODE_VIOLATION ->"
                + " SUITE_PROVISIONAL -> the operand as decrypt reads it, except that a"
                + " non-envelope is NOT_CIPHERTEXT in every read mode (spec §11.1). Tested by"
                + " ApiBoundaryOrderTest. docs/27 §4.");
        m.put("unimplemented-registered-suite", "0xFF02 is registered and not built (G7)."
                + " Naming it in allowedSuites or as writeSuite is a ConfigurationError at build()"
                + " that names G7. A 0xFF02 envelope is still recognized (isCiphertext is true),"
                + " and decrypting one is SUITE_NOT_ALLOWED. docs/27 §4.");
        m.put("commitment-construction", "spec §4.6 [PROVISIONAL, G1]: commitment ="
                + " HKDF-SHA-512(ikm = record_key, salt = empty, so RFC 5869's 64 zero bytes,"
                + " passed explicitly because SecretKeySpec refuses an empty key; info ="
                + " \"fieldseal-commit-v1\"; length = 32). On decrypt it is recomputed per"
                + " candidate and compared with MessageDigest.isEqual before the AEAD is opened."
                + " docs/27 §5.2, §5.3.");
        m.put("key-material-ownership", "provider-owned (docs/09 §8.1): the core validates what"
                + " a KeyProvider returns and never writes to it, and a test with a provider that"
                + " keeps its own arrays shows them unchanged (KeyMaterialOwnershipTest). Erasure"
                + " steps performed, by Arrays.fill in a finally on buffers the core owns:"
                + " record_key on both paths, the index key, the normalized value (always the"
                + " core's own copy), the untruncated IDF output, the Argon2id salt and"
                + " BouncyCastle's two copies it can reach (Builder.clear, Argon2Parameters.clear),"
                + " the HKDF PRK and expand blocks, the commitment recomputed on decrypt, rotate's"
                + " intermediate plaintext, and the AEAD output on every exit that does not return"
                + " it. Not erasable, and not erased: what a String holds, SecretKeySpec's copy of"
                + " each key, Cipher and Mac internals, BouncyCastle's per-call salt copy, and the"
                + " DEK copies a provider returns, which are the provider's. That record_key is"
                + " erased is tested; that the index key, the normalized value and the salt are is"
                + " not observable (docs/27 §8, S5). No mlock and no swap protection. None of"
                + " this is a guarantee (spec §5.5). docs/27 §5.4.");
        m.put("platform-byte-buffer-max", "2^31-3 = 2,147,483,645 bytes: the largest byte[]"
                + " HotSpot allocates on Temurin 21.0.12 (G1, -Xmx6g), on Windows x64 and on CI's"
                + " ubuntu-24.04 runner, measured by BufferMaxProbe on 2026-09-24 and not by this"
                + " run. The platform binds before spec §3.5's bound on every JVM, since no Java"
                + " array reaches 2^31 elements. docs/27 §6.1.");
        m.put("index-role-use-budget", "none (docs/09 §8.3): max-uses counts DEK-role"
                + " encryption_key returns only, and an index-role fetch spends nothing; max-age"
                + " and the capacity LRU apply to both roles. The role is read from the cache key"
                + " on every take (DekCache.takeForEncrypt, #224). Proven end to end by"
                + " EnvelopeProviderTest.theIndexRoleHasNoUseBudget: under maxUses = 2, a blind"
                + " index is derived maxUses + 1 times; then, as the positive control, the DEK is"
                + " use-evicted after two encryptions and the third is KEY_UNAVAILABLE, while the"
                + " index key still derives; max-age still retires it. This report runs that test"
                + " and fails when it is missing or not passing (#225).");
        return Collections.unmodifiableMap(m);
    }

    static final List<String> HARNESS_NOTES = List.of(
            "Every result is the outcome of one JUnit dynamic test, named by the result id, of the"
                    + " build's own vector tests (KdfVectorsTest, ContextVectorsTest,"
                    + " CommitmentVectorsTest, EnvelopeVectorsTest, ClientVectorsTest,"
                    + " BlindIndexVectorsTest), run again for this report. The ids required are"
                    + " computed from MANIFEST.files, so a vector no test ran is a failed result.",
            "docs/08 §5 item 2 (schema validation) is not performed: vectors/schema/ does not"
                    + " exist. Before any vector runs, each listed file's length and SHA-256 are"
                    + " checked against MANIFEST.json, with the docs/08 §4 wrapper and every id's"
                    + " grammar and uniqueness.",
            "Suffixes: <id>#decrypt is an envelope/ vector's decrypt direction, through the public"
                    + " decrypt. <id>#pipeline is a blind-index/ primitive vector through the"
                    + " public blindIndex, over text and over bytes, with a row_id on the caller's"
                    + " context (docs/08 §5 item 11). An envelope/ vector's own id is its encrypt"
                    + " direction, through encrypt_with_materials (docs/08 §6), armed by"
                    + " FIELDSEAL_TEST_MODE=1 for this run.",
            "stored.hex (docs/08 §4.4) is not asserted: this core returns the binary form only"
                    + " (docs/09 §3.3). stored.binary and stored.octets are asserted wherever a"
                    + " vector carries them.",
            "Python and Node can produce a valid envelope larger than any JVM array: the largest"
                    + " is 2^31+110 bytes, for a (2^31-1)-byte plaintext, and a JVM cannot receive"
                    + " it. On HotSpot 21 the largest plaintext this core can encrypt is"
                    + " (2^31-3)-111 = 2,147,483,534 bytes; above it, an OutOfMemoryError, which"
                    + " spec §3.5 makes conformant below the bound (docs/27 §6.1).",
            "async_companions is false: this core ships no asynchronous companions (docs/27 §4,"
                    + " G9), so there is no #async pass.");

    // --- the environment -----------------------------------------------------------------------

    static ObjectNode implementation(Path vectorsDir) {
        ObjectNode i = JSON.createObjectNode();
        i.put("name", "java-core");
        i.put("version", System.getProperty("fieldseal.version", "unknown"));
        i.put("commit", commit(vectorsDir));
        i.put("language", "java");
        return i;
    }

    private static String commit(Path dir) {
        String sha = System.getenv("GITHUB_SHA");
        if (sha != null && !sha.isBlank()) {
            return sha;
        }
        try {
            Process p = new ProcessBuilder("git", "rev-parse", "HEAD").directory(dir.toFile())
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.US_ASCII)
                    .strip();
            if (p.waitFor(10, TimeUnit.SECONDS) && p.exitValue() == 0
                    && out.matches("[0-9a-f]{40}")) {
                return out;
            }
        } catch (IOException e) {
            // no git: fall through
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return "unknown";
    }

    static ObjectNode environment() {
        ObjectNode e = JSON.createObjectNode();
        e.put("runtime", System.getProperty("java.vendor") + " "
                + System.getProperty("java.vm.name") + " " + System.getProperty("java.runtime.version"));
        e.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version") + " "
                + System.getProperty("os.arch"));
        var sunJce = Security.getProvider("SunJCE");
        e.put("crypto_backend", "SunJCE " + (sunJce == null ? "(absent)" : sunJce.getVersionStr())
                + " (AES-256-GCM, HMAC-SHA-512; HKDF written over Mac); BouncyCastle "
                + new org.bouncycastle.jce.provider.BouncyCastleProvider().getVersionStr()
                + " (Argon2id only, not registered as a JCA provider)");
        e.put("unicode_platform", "JDK " + System.getProperty("java.version")
                + " java.lang.Character and java.text.Normalizer tables (not used for"
                + " nfc-casefold-v1)");
        e.put("unicode_tables", "vendored UCD " + Fieldseal.UNICODE_VERSION
                + " (NFC + CaseFolding C+F), generated by tools/ucd-gen");
        return e;
    }

    // --- main ----------------------------------------------------------------------------------

    /** {@code ./gradlew -q vectors}: the report on stdout, problems on stderr. */
    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("usage: ConformanceReport <vectors-dir>");
            System.exit(2);
        }
        Path vectors = Path.of(args[0]).toAbsolutePath().normalize();
        VectorHarness.Walk walk = VectorHarness.walk(vectors);
        if (!walk.problems().isEmpty()) {
            // docs/08 §5 item 2: a malformed suite fails loudly and runs nothing.
            walk.problems().forEach(p -> System.err.println("PROBLEM " + p));
            System.exit(1);
        }
        JsonNode manifest = VectorHarness.read(vectors.resolve("MANIFEST.json"));
        List<String> expected = expectedIds(vectors, walk);

        // What the tests print is theirs, not the report's: stdout carries the JSON alone.
        PrintStream stdout = System.out;
        List<Outcome> harness;
        Map<String, List<Outcome>> oob = new LinkedHashMap<>();
        Map<String, List<Outcome>> pins = new LinkedHashMap<>();
        System.setOut(System.err);
        try {
            harness = run(HARNESS.stream().map(c -> (DiscoverySelector) selectClass(c)).toList());
            for (OutOfBand entry : OUT_OF_BAND) {
                oob.put(entry.id(), runMethods(entry.tests()));
            }
            PINNED_TESTS.forEach((key, tests) -> pins.put(key, runMethods(tests)));
        } finally {
            System.setOut(stdout);
        }

        Assembled a = assemble(manifest, expected, harness, oob, OUT_OF_BAND, pins,
                implementation(vectors), environment());
        List<String> problems = conclude(vectors, manifest, expected, a);
        stdout.println(JSON.writeValueAsString(a.report()));
        stdout.flush();
        problems.forEach(p -> System.err.println("PROBLEM " + p));
        JsonNode s = a.report().path("summary");
        System.err.printf("vector suite %s: %d results, %d pass, %d fail, %d skipped; %d"
                        + " out-of-band; L0 %s%n", manifest.path("vector_suite_version").asText(),
                expected.size(), s.path("pass").asInt(), s.path("fail").asInt(),
                s.path("skipped").asInt(), a.report().path("out_of_band").size(),
                a.report().path("claimed_levels").path("L0").asBoolean());
        if (!problems.isEmpty() || s.path("fail").asInt() > 0 || s.path("skipped").asInt() > 0
                || !a.report().path("claimed_levels").path("L0").asBoolean()) {
            System.exit(1);
        }
    }
}
