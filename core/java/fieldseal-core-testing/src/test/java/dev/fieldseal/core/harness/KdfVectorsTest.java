package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.capabilities.SuiteFiles.vectors;
import static dev.fieldseal.core.harness.PrimitiveVectors.context;
import static dev.fieldseal.core.harness.PrimitiveVectors.suiteId;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.internal.context.CanonicalContext;
import dev.fieldseal.core.internal.kdf.KeyDerivation;
import dev.fieldseal.core.internal.registry.Registry;
import dev.fieldseal.core.internal.registry.Suite;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * {@code kdf/} (docs/08 §4.2) through the core's {@code record_key} (spec §5.3) and
 * {@code index_key} (spec §7.2). Each value vector's {@code salt} and {@code info} are asserted
 * as well as the key, so a mismatch names the input that differs; {@code info} is
 * {@code canonical_context}, built by the core from the vector's context object. The S2 audit
 * ran the value vectors from the file's own {@code info}; the two {@code distinct} vectors give a
 * context instead, and run here for the first time (docs/27 §5.2).
 */
class KdfVectorsTest {

    private static final Map<String, int[]> PINNED = Map.of(
            "kdf/record-key.json", new int[] {4, 1},
            "kdf/index-key.json", new int[] {5, 1});

    @TestFactory
    Stream<DynamicTest> recordAndIndexKeys() {
        Map<String, String> indexKeys = new LinkedHashMap<>();
        vectors("kdf/index-key.json").stream().filter(v -> !v.has("assertion"))
                .forEach(v -> indexKeys.put(v.path("id").asText(),
                        v.path("expected").path("index_key").asText()));
        return PrimitiveVectors.run(PrimitiveVectors.family("kdf", PINNED),
                v -> value(v, indexKeys), KdfVectorsTest::pair);
    }

    private static boolean isRecordKey(JsonNode v) {
        return v.path("id").asText().startsWith("kdf/record-key/");
    }

    private static void value(JsonNode v, Map<String, String> indexKeys) {
        Suite suite = suite(v);
        JsonNode e = v.path("expected");
        if (isRecordKey(v)) {
            byte[] keyId = hex(v.path("key_id"));
            byte[] msgSeed = hex(v.path("msg_seed"));
            byte[] cc = CanonicalContext.encode(context(suite.id(), v.path("context")));
            assertEquals(e.path("salt").asText(), hex(KeyDerivation.recordKeySalt(keyId, msgSeed)),
                    "salt");
            assertEquals(e.path("info").asText(), hex(cc), "info");
            assertEquals(e.path("record_key").asText(), hex(KeyDerivation.recordKey(suite,
                    hex(v.path("tenant_dek")), keyId, msgSeed, cc)), "record_key");
        } else {
            byte[] cc = CanonicalContext.encodeForIndexKey(context(suite.id(), v.path("context")));
            assertEquals(e.path("salt").asText(), hex(KeyDerivation.indexSalt()), "salt");
            assertEquals(e.path("info").asText(), hex(cc), "info");
            String key = hex(KeyDerivation.indexKey(hex(v.path("tenant_index_key")), cc));
            assertEquals(e.path("index_key").asText(), key, "index_key");
            if (v.has("same_as")) {
                String other = v.path("same_as").asText();
                assertTrue(indexKeys.containsKey(other), "same_as names no value vector: " + other);
                assertEquals(indexKeys.get(other), key, "same_as " + other);
            }
        }
    }

    private static byte[][] pair(JsonNode v) {
        Suite suite = suite(v);
        JsonNode in = v.path("inputs");
        if (isRecordKey(v)) {
            byte[] dek = hex(in.path("tenant_dek"));
            byte[] keyId = hex(in.path("key_id"));
            byte[] cc = CanonicalContext.encode(context(suite.id(), in.path("context")));
            return new byte[][] {
                KeyDerivation.recordKey(suite, dek, keyId, hex(in.path("msg_seed_a")), cc),
                KeyDerivation.recordKey(suite, dek, keyId, hex(in.path("msg_seed_b")), cc)
            };
        }
        byte[] tik = hex(in.path("tenant_index_key"));
        return new byte[][] {
            KeyDerivation.indexKey(tik,
                    CanonicalContext.encodeForIndexKey(context(suite.id(), in.path("context_a")))),
            KeyDerivation.indexKey(tik,
                    CanonicalContext.encodeForIndexKey(context(suite.id(), in.path("context_b"))))
        };
    }

    private static Suite suite(JsonNode v) {
        return Registry.lookup(suiteId(v)).orElseThrow(
                () -> new AssertionError("unregistered suite " + v.path("suite_id")));
    }
}
