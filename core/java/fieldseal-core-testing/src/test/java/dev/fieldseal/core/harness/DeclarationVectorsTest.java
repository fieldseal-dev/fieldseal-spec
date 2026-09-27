package dev.fieldseal.core.harness;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

/**
 * {@link DeclarationVectors}'s malformed-vector guards, on synthetic vectors: the pinned suite has
 * no {@code argon2id} declaration and no malformed number, so without these nothing would show
 * that the harness refuses them rather than defaulting (docs/08 §4.4, #222 review).
 */
class DeclarationVectorsTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** An accepted declaration, correct until a field is changed. */
    private static ObjectNode vector(Consumer<ObjectNode> change) {
        ObjectNode v = JSON.createObjectNode().put("id", "context/canonical/synthetic")
                .put("assertion", "declaration").put("suite_id", "0xFF01");
        ObjectNode d = v.putObject("inputs").putObject("declaration")
                .put("table_uuid", "3f2504e04f8911d39a0c0305e82c3301")
                .put("column_uuid", "7d4448409dc011d1b2455ffdce74fad2")
                .put("index_id", "email-eq").put("idf", "hmac-sha512")
                .put("normalize", "identity").put("truncate_bits", 16)
                .put("projected_population", 1048576).put("skewed", false)
                .put("on_unindexable", "refuse");
        d.putObject("idf_params");
        d.putNull("cardinality_override");
        v.putObject("expected").put("declaration", "accepted");
        change.accept(d);
        return v;
    }

    private static void assertMalformed(String fragment, Consumer<ObjectNode> change) {
        AssertionFailedError e = assertThrows(AssertionFailedError.class,
                () -> DeclarationVectors.run(vector(change)));
        assertTrue(e.getMessage().contains(fragment), e.getMessage());
    }

    @Test
    void theBaseVectorIsAccepted() {
        assertDoesNotThrow(() -> DeclarationVectors.run(vector(d -> { })));
        assertDoesNotThrow(() -> DeclarationVectors.run(vector(d -> {
            d.put("idf", "argon2id");
            d.putObject("idf_params").put("version", 19).put("time_cost", 3)
                    .put("memory_kib", 32768).put("parallelism", 1).put("output_len", 64);
        })));
    }

    @Test
    void argon2idWithoutItsCostIsMalformedNotTheMinima() {
        assertMalformed("without time_cost and memory_kib", d -> d.put("idf", "argon2id"));
        assertMalformed("without time_cost and memory_kib", d -> {
            d.put("idf", "argon2id");
            d.putObject("idf_params").put("time_cost", 3);
        });
    }

    @Test
    void argon2idPinnedFieldsAreSpecs() {
        assertMalformed("parallelism is spec §7.3's", d -> {
            d.put("idf", "argon2id");
            d.putObject("idf_params").put("time_cost", 3).put("memory_kib", 32768)
                    .put("parallelism", 4);
        });
    }

    @Test
    void hmacWithParamsIsMalformedNotARefusal() {
        assertMalformed("empty idf_params", d -> d.putObject("idf_params").put("time_cost", 3));
    }

    @Test
    void aFractionalNumberIsMalformedNotTruncated() {
        assertMalformed("projected_population is an integer",
                d -> d.put("projected_population", 1048576.5));
        assertMalformed("truncate_bits is an integer", d -> d.put("truncate_bits", 16.0));
    }
}
