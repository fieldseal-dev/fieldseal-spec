package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.files;
import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.capabilities.SuiteFiles.slug;
import static dev.fieldseal.core.capabilities.SuiteFiles.vectors;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.ReadMode;
import dev.fieldseal.core.errors.FieldsealError;
import dev.fieldseal.core.errors.SuiteProvisionalError;
import dev.fieldseal.core.internal.registry.Registry;
import dev.fieldseal.core.keyprovider.EnvelopeHeader;
import dev.fieldseal.core.keyprovider.KeyMaterial;
import dev.fieldseal.core.keyprovider.KeyProvider;
import dev.fieldseal.core.keyprovider.KeyRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * {@code errors/} and the decrypt direction of {@code envelope/}, through the public client
 * (S4b). Each vector's {@code config} builds a {@link Fieldseal}, and a provider that knows only
 * the vector's {@code key_id} and {@code tenant_dek} answers its key lookups (docs/08 §4.6). The
 * read-mode mapping, the allow-list, the key lookup, the commitment and the tag are the client's
 * now, not a restatement in this test.
 *
 * <p>{@code blind_index} vectors wait for S5, where the operation arrives; {@link #DEFERRED} pins
 * how many, per file, so a suite change that moves one fails here.
 */
class ClientVectorsTest {

    /** Per errors/ file: {vectors run, vectors deferred to S5}. */
    private static final Map<String, int[]> ERRORS = new LinkedHashMap<>();

    static {
        ERRORS.put("errors/format.json", new int[] {41, 0});
        ERRORS.put("errors/crypto.json", new int[] {12, 0});
        ERRORS.put("errors/policy.json", new int[] {14, 2});
    }

    /**
     * The unarmed vectors need the process unarmed: the variable arms every client (spec §4.8),
     * and the harness has no business reading around it. Only the byte-exact {@code 1} arms, so
     * only that value stops the run.
     */
    @BeforeAll
    static void theEnvironmentDoesNotArm() {
        assertNotEquals("1", System.getenv(SuiteProvisionalError.ARMING_VARIABLE),
                SuiteProvisionalError.ARMING_VARIABLE + "=1 arms every client; the unarmed vectors"
                        + " cannot run under it");
    }

    /** Answers with the vector's key only when asked for the vector's key_id. */
    private record VectorKeys(byte[] dek, byte[] keyId) implements KeyProvider {
        @Override
        public KeyMaterial encryptionKey(KeyRequest request) {
            return new KeyMaterial(dek.clone(), keyId.clone());
        }

        @Override
        public List<byte[]> decryptionKeys(EnvelopeHeader header) {
            return Arrays.equals(header.keyId(), keyId) ? List.of(dek.clone()) : List.of();
        }
    }

    private static FieldContext context(JsonNode c) {
        assertEquals("encrypt", c.path("purpose").asText(), "a value vector's purpose");
        return new FieldContext(hex(c.path("table_uuid")), hex(c.path("column_uuid")),
                c.path("tenant_id").isNull() ? null : hex(c.path("tenant_id")),
                c.path("row_id").isNull() ? null : hex(c.path("row_id")));
    }

    private static Fieldseal client(JsonNode v) {
        JsonNode cfg = v.path("config");
        assertEquals(Registry.all().stream().map(s -> s.id()).collect(Collectors.toSet()),
                ids(cfg.path("registered_suites")), "registered_suites is this core's registry");
        return Fieldseal.builder()
                .keyProvider(new VectorKeys(hex(v.path("tenant_dek")), hex(v.path("key_id"))))
                .allowedSuites(ids(cfg.path("allowed_suites")))
                .writeSuite(Integer.decode(cfg.path("write_suite").asText()))
                .readMode(ReadMode.valueOf(cfg.path("read_mode").asText().toUpperCase()))
                .armProvisionalSuites(cfg.path("arm_provisional_suites").asBoolean())
                .onWarning(w -> { })
                .build();
    }

    private static Set<Integer> ids(JsonNode list) {
        Set<Integer> out = new TreeSet<>();
        list.forEach(n -> out.add(Integer.decode(n.asText())));
        return out;
    }

    @TestFactory
    Stream<DynamicTest> errorsFamily() {
        List<String> listed = files().stream().map(VectorHarness.FileWalk::path)
                .filter(p -> p.startsWith("errors/")).toList();
        assertEquals(ERRORS.keySet(), Set.copyOf(listed),
                "errors/ in MANIFEST.files is not the set of files this test pins");
        List<DynamicTest> tests = new ArrayList<>();
        for (String path : listed) {
            int[] seen = new int[2];
            for (JsonNode v : vectors(path)) {
                if (v.path("operation").asText().equals("blind_index")) {
                    seen[1]++;
                    continue;
                }
                seen[0]++;
                tests.add(DynamicTest.dynamicTest(slug(v), () -> run(v)));
            }
            assertEquals(Arrays.toString(ERRORS.get(path)), Arrays.toString(seen),
                    path + ": {run, deferred} counts moved");
        }
        return tests.stream();
    }

    private static void run(JsonNode v) {
        byte[] input = hex(v.path("input"));
        JsonNode e = v.path("expected");
        String op = v.path("operation").asText();
        Fieldseal fs = client(v);
        if (op.equals("is_ciphertext")) {
            // No context: recognition is a function of the bytes and the registry (spec §3.4).
            assertEquals(e.path("is_ciphertext").asBoolean(), fs.isCiphertext(input));
            return;
        }
        FieldContext ctx = context(v.path("context"));
        byte[] out;
        try {
            out = switch (op) {
                case "decrypt" -> fs.decrypt(input, ctx);
                case "encrypt" -> fs.encrypt(input, ctx);
                case "rotate" -> fs.rotate(input, ctx);
                default -> throw new AssertionError("unrecognised operation '" + op + "'");
            };
        } catch (FieldsealError err) {
            if (!e.has("error")) {
                fail("expected " + e + ", got " + err.code() + ": " + err.getMessage());
            }
            assertEquals(e.path("error").asText(), err.code(), err.getMessage());
            return;
        }
        if (e.has("error")) {
            fail("expected " + e.path("error").asText() + ", got a result");
        } else if (e.has("plaintext")) {
            assertEquals(e.path("plaintext").asText(), hex(out));
        } else if (e.has("value")) {
            assertEquals(e.path("value").asText(), hex(out));
            assertSame(input, out, "pass-through returns the input itself (spec §10.3)");
        } else {
            fail("unrecognised expectation " + e);
        }
    }

    /** envelope/ read back through the public decrypt, under a strict client. */
    @Test
    void envelopeFamilyDecryptsThroughTheClient() {
        List<JsonNode> vs = vectors("envelope/ff01.json");
        assertEquals(9, vs.size());
        for (JsonNode v : vs) {
            Fieldseal fs = Fieldseal.builder()
                    .keyProvider(new VectorKeys(hex(v.path("tenant_dek")), hex(v.path("key_id"))))
                    .allowedSuites(Set.of(0xFF01)).writeSuite(0xFF01).onWarning(w -> { }).build();
            assertArrayEquals(hex(v.path("plaintext")),
                    fs.decrypt(hex(v.path("expected").path("envelope")), context(v.path("context"))),
                    v.path("id").asText());
        }
    }
}
