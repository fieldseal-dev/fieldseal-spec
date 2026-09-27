package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.IndexDeclaration;
import dev.fieldseal.core.IndexDeclaration.Argon2Params;
import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.core.IndexDeclaration.OnUnindexable;
import dev.fieldseal.core.IndexDeclaration.ReviewedOverride;
import dev.fieldseal.core.KeyProviders;
import dev.fieldseal.core.errors.ConfigurationError;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * docs/08 §4's {@code declaration} shape (suite {@code 0.10.0-provisional}; #210, #211): a rule a
 * core enforces when an index is declared, not when a value is derived. The vector's declaration
 * is handed to a client at construction. {@code refused} passes only as this core's {@link
 * ConfigurationError}: any other exception fails, a §9 {@code FieldsealError} included, because it
 * means the declaration was refused for the wrong reason. {@code accepted} passes only if
 * construction succeeds and the client reports the index back.
 *
 * <p>Every field is read from the vector and none is defaulted (docs/08 §1 item 3): a declaration
 * missing one is malformed, and the vector fails rather than taking this core's default.
 */
final class DeclarationVectors {

    /** docs/08 §4: the complete docs/09 §7 {@code IndexDeclaration}. */
    private static final Set<String> FIELDS = new TreeSet<>(List.of("table_uuid", "column_uuid",
            "index_id", "idf", "idf_params", "normalize", "truncate_bits", "projected_population",
            "skewed", "cardinality_override", "on_unindexable"));

    private static final byte[] DEK = new byte[32];
    private static final byte[] INDEX_KEY = {1};
    private static final byte[] KEY_ID = new byte[16];

    private DeclarationVectors() {}

    static void run(JsonNode v) {
        JsonNode d = v.path("inputs").path("declaration");
        Set<String> present = new TreeSet<>();
        d.fieldNames().forEachRemaining(present::add);
        assertEquals(FIELDS, present, "the declaration's fields (docs/08 §4: none defaulted)");
        String want = v.path("expected").path("declaration").asText();
        assertEquals(1, v.path("expected").size(), "expected names no error code (docs/08 §4)");
        assertTrue(want.equals("refused") || want.equals("accepted"),
                "expected.declaration is refused or accepted, not '" + want + "'");

        IndexDeclaration declaration = declaration(d);
        Fieldseal.Builder client = Fieldseal.builder()
                .keyProvider(KeyProviders.staticKeys(DEK, INDEX_KEY, KEY_ID))
                .allowedSuites(Set.of(Integer.decode(v.path("suite_id").asText())))
                .writeSuite(Integer.decode(v.path("suite_id").asText()))
                .indexes(List.of(declaration))
                .onWarning(w -> { });
        Fieldseal built;
        try {
            built = client.build();
        } catch (ConfigurationError refused) {
            if (want.equals("accepted")) {
                fail("the declaration was refused: " + refused.getMessage());
            }
            return;
        } catch (RuntimeException other) {
            fail("refused, but not as a configuration error: " + other, other);
            return;
        }
        if (want.equals("refused")) {
            fail("the declaration was accepted");
        }
        assertEquals(1, built.indexes().size(), "the client reports the accepted index back");
        assertTrue(built.indexes().containsKey(Fieldseal.indexRegistryKey(hex(d.path("table_uuid")),
                hex(d.path("column_uuid")), d.path("index_id").asText())), "registry key");
    }

    /** The vector's declaration, field for field, through the public builder. */
    private static IndexDeclaration declaration(JsonNode d) {
        IndexDeclaration.Builder b = IndexDeclaration.builder(hex(d.path("table_uuid")),
                        hex(d.path("column_uuid")))
                .indexId(text(d, "index_id"))
                .idf(byId(Idf.values(), Idf::id, text(d, "idf")))
                .normalize(byId(Normalizer.values(), Normalizer::id, text(d, "normalize")))
                .truncateBits(integer(d, "truncate_bits"))
                .projectedPopulation(d.path("projected_population").asLong())
                .onUnindexable(byId(OnUnindexable.values(), OnUnindexable::id,
                        text(d, "on_unindexable")));
        assertTrue(d.path("projected_population").canConvertToLong(), "projected_population");
        assertTrue(d.path("skewed").isBoolean(), "skewed is a boolean");
        b.skewed(d.path("skewed").asBoolean());
        JsonNode o = d.path("cardinality_override");
        if (!o.isNull()) {
            b.cardinalityOverride(new ReviewedOverride(text(o, "reason"), text(o, "approved_by"),
                    LocalDate.parse(text(o, "date"))));
        }
        JsonNode p = d.path("idf_params");
        assertTrue(p.isObject(), "idf_params is an object");
        if (p.has("time_cost") || p.has("memory_kib")) {
            b.argon2(new Argon2Params(integer(p, "time_cost"), integer(p, "memory_kib")));
        }
        return b.build();
    }

    private static String text(JsonNode n, String field) {
        assertTrue(n.path(field).isTextual(), field + " is a string");
        return n.path(field).asText();
    }

    private static int integer(JsonNode n, String field) {
        assertTrue(n.path(field).canConvertToInt(), field + " is an integer");
        return n.path(field).asInt();
    }

    private static <E> E byId(E[] values, java.util.function.Function<E, String> id, String want) {
        return Arrays.stream(values).filter(e -> id.apply(e).equals(want)).findFirst()
                .orElseThrow(() -> new AssertionError("no such identifier '" + want + "'"));
    }
}
