package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.files;
import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.capabilities.SuiteFiles.vectors;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.KeyProviders;
import dev.fieldseal.core.testing.FieldsealTesting;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * {@code envelope/} in both directions through the public surface (docs/08 §4.1, §5 item 4; S6).
 * The encrypt direction is {@code encrypt_with_materials} with the vector's {@code msg_seed} and
 * nonce, which is the client's own pipeline with the entropy fixed (docs/08 §6); the decrypt
 * direction, reported as {@code <id>#decrypt}, is the public {@code decrypt} of the pinned bytes.
 * The key provider holds the vector's {@code tenant_dek} under its {@code key_id}, so each result
 * also shows that the client asks for, and writes, the provider's {@code key_id}.
 *
 * <p>{@code EnvelopeCryptoVectorsTest} keeps the intermediates ({@code canonical_context}, the
 * AAD, {@code record_key}), which the client does not expose.
 */
class EnvelopeVectorsTest {

    private static final Map<String, Integer> PINNED = Map.of("envelope/ff01.json", 9);

    /** Not a key the vectors use: spec §8 wants the index key to differ from the DEK. */
    private static final byte[] UNUSED_INDEX_KEY = new byte[] {0x49};

    @TestFactory
    Stream<DynamicTest> envelopeFamily() {
        List<String> listed = files().stream().map(VectorHarness.FileWalk::path)
                .filter(p -> p.startsWith("envelope/")).toList();
        assertEquals(PINNED.keySet(), Set.copyOf(listed),
                "envelope/ in MANIFEST.files is not the set of files this test pins");
        List<DynamicTest> tests = new ArrayList<>();
        for (String path : listed) {
            List<JsonNode> vs = vectors(path);
            assertEquals(PINNED.get(path).intValue(), vs.size(), path + ": vector count moved");
            for (JsonNode v : vs) {
                String id = v.path("id").asText();
                tests.add(DynamicTest.dynamicTest(id, () -> encrypt(v)));
                tests.add(DynamicTest.dynamicTest(id + "#decrypt", () -> decrypt(v)));
            }
        }
        return tests.stream();
    }

    private static void encrypt(JsonNode v) {
        JsonNode e = v.path("expected");
        byte[] env = FieldsealTesting.encryptWithMaterials(client(v), hex(v.path("plaintext")),
                context(v.path("context")), hex(v.path("msg_seed")), hex(v.path("nonce")));
        assertEquals(e.path("envelope").asText(), hex(env), "envelope");
        assertEquals(e.path("envelope_bytes").asInt(), env.length, "envelope_bytes");
    }

    private static void decrypt(JsonNode v) {
        assertEquals(v.path("plaintext").asText(), hex(client(v).decrypt(
                hex(v.path("expected").path("envelope")), context(v.path("context")))),
                "plaintext");
    }

    /** A strict client under the vector's suite, which it arms: the suite is provisional. */
    private static Fieldseal client(JsonNode v) {
        int suite = Integer.decode(v.path("suite_id").asText());
        byte[] dek = hex(v.path("tenant_dek"));
        if (Arrays.equals(dek, UNUSED_INDEX_KEY)) {
            throw new IllegalStateException("the placeholder index key equals the vector's DEK");
        }
        return Fieldseal.builder()
                .keyProvider(KeyProviders.staticKeys(dek, UNUSED_INDEX_KEY, hex(v.path("key_id"))))
                .allowedSuites(Set.of(suite)).writeSuite(suite).armProvisionalSuites(true)
                .onWarning(w -> { }).build();
    }

    private static FieldContext context(JsonNode c) {
        assertEquals("encrypt", c.path("purpose").asText(), "a value vector's purpose");
        return new FieldContext(hex(c.path("table_uuid")), hex(c.path("column_uuid")),
                c.path("tenant_id").isNull() ? null : hex(c.path("tenant_id")),
                c.path("row_id").isNull() ? null : hex(c.path("row_id")));
    }
}
