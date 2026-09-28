package dev.fieldseal.core.harness;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.IndexDeclaration;
import dev.fieldseal.core.IndexDeclaration.Argon2Params;
import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.core.IndexDeclaration.OnUnindexable;
import dev.fieldseal.core.IndexDeclaration.ReviewedOverride;
import dev.fieldseal.core.KeyProviders;
import dev.fieldseal.core.ReadMode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * What the cross producer ({@link CrossProduce}) and consumer ({@link CrossConsume}) share: the
 * dynamic half of docs/08 §4.7, run as docs/14 §3's N×N job (docs/27 §8, S7). Both read the
 * shared inputs, {@code cross/corpus.json} and {@code keys/test-keys.json}, only after their
 * length and SHA-256 match {@code MANIFEST.support}, and both build clients through the public
 * builder with the static provider over a {@code key_ref}'s keys. Neither touches the testing
 * artifact: the producer encrypts through production {@code encrypt}, which takes no nonce or
 * seed ({@code PublicSurfaceTest}).
 *
 * <p>A malformed input is an {@link IllegalArgumentException} with a message that names what is
 * wrong. The consumer records it as that case's failure; it is never a skip.
 */
final class Cross {

    static final String V1 = "fieldseal-vectors/cross/v1";
    static final String V2 = "fieldseal-vectors/cross/v2";

    /** Spec §3.1: {@code msg_seed} follows the 1 + 2 + 16 header bytes, then the nonce. */
    static final int SEED_AT = 19;
    static final int NONCE_AT = 51;
    static final int NONCE_END = 63;

    static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(SerializationFeature.INDENT_OUTPUT);

    private static final HexFormat HEX = HexFormat.of();
    private static final Pattern SUITE = Pattern.compile("0x[0-9A-Fa-f]{4}");
    private static final Set<String> CONTEXT = Set.of("table_uuid", "column_uuid", "tenant_id",
            "row_id", "purpose");
    private static final Set<String> DECLARATION_REQUIRED = Set.of("index_id", "idf",
            "idf_params", "normalize", "truncate_bits", "projected_population", "on_unindexable");
    private static final Set<String> DECLARATION_OPTIONAL = Set.of("skewed",
            "cardinality_override", "unindexable_override");

    /** One {@code key_ref} of {@code keys/test-keys.json}. */
    record Key(String ref, int suite, byte[] keyId, byte[] dek, byte[] indexKey) {}

    private Cross() {}

    // --- the shared inputs ---------------------------------------------------------------------

    /** A {@code MANIFEST.support} file, parsed only once its length and SHA-256 match. */
    static JsonNode support(Path vectors, String path) throws IOException {
        JsonNode manifest = JSON.readTree(vectors.resolve("MANIFEST.json").toFile());
        JsonNode entry = null;
        for (JsonNode e : manifest.path("support")) {
            if (path.equals(e.path("path").asText())) {
                entry = e;
            }
        }
        if (entry == null) {
            throw new IllegalArgumentException(path + " is not in MANIFEST.support");
        }
        byte[] bytes = Files.readAllBytes(vectors.resolve(path));
        String sha = HEX.formatHex(sha256(bytes));
        if (bytes.length != entry.path("bytes").asLong(-1)
                || !sha.equals(entry.path("sha256").asText())) {
            throw new IllegalArgumentException(path + ": " + bytes.length + " bytes, sha256 " + sha
                    + "; MANIFEST.support says " + entry.path("bytes") + ", "
                    + entry.path("sha256"));
        }
        JsonNode doc = JSON.readTree(bytes);
        String version = manifest.path("vector_suite_version").asText();
        if (!version.equals(doc.path("vector_suite_version").asText())) {
            throw new IllegalArgumentException(path + " is suite "
                    + doc.path("vector_suite_version") + ", the manifest is " + version);
        }
        return doc;
    }

    /** {@code keys/test-keys.json}, by {@code key_ref} (docs/08 §4.7). */
    static Map<String, Key> keys(Path vectors) throws IOException {
        JsonNode doc = support(vectors, "keys/test-keys.json");
        expect(doc, "schema", "fieldseal-vectors/keys/v1");
        Map<String, Key> keys = new LinkedHashMap<>();
        doc.path("keys").properties().forEach(e -> {
            JsonNode k = e.getValue();
            keys.put(e.getKey(), new Key(e.getKey(), suite(text(k, "suite_id")),
                    hex(k, "key_id"), hex(k, "tenant_dek"), hex(k, "tenant_index_key")));
        });
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("keys/test-keys.json has no keys");
        }
        return Map.copyOf(keys);
    }

    static Key key(Map<String, Key> keys, JsonNode c) {
        String ref = text(c, "key_ref");
        Key k = keys.get(ref);
        if (k == null) {
            throw new IllegalArgumentException("key_ref '" + ref
                    + "' is not in keys/test-keys.json");
        }
        return k;
    }

    // --- clients -------------------------------------------------------------------------------

    /**
     * A strict client over one {@code key_ref}, allowing and writing {@code suite} only, which it
     * arms (spec §4.8): every registered suite is provisional. Strict, so that a document whose
     * envelope is not one is {@code NOT_CIPHERTEXT} rather than handed back as its own plaintext.
     */
    static Fieldseal client(Key k, int suite, List<IndexDeclaration> indexes,
            Consumer<String> warn) {
        if (k.suite() != suite) {
            throw new IllegalArgumentException("key_ref '" + k.ref() + "' is for suite "
                    + String.format("0x%04X", k.suite()) + ", the document is "
                    + String.format("0x%04X", suite));
        }
        return Fieldseal.builder()
                .keyProvider(KeyProviders.staticKeys(k.dek(), k.indexKey(), k.keyId()))
                .allowedSuites(Set.of(suite)).writeSuite(suite).armProvisionalSuites(true)
                .readMode(ReadMode.STRICT).indexes(indexes).onWarning(warn).build();
    }

    // --- the case fields -----------------------------------------------------------------------

    /**
     * A case's {@code context}: exactly docs/08 §4.7's five fields, {@code tenant_id} and {@code
     * row_id} null or hex. A field this reader does not know is refused: a context field changes
     * the AAD, so one read past would be a context this consumer did not check.
     */
    static FieldContext context(JsonNode c, String purpose) {
        JsonNode ctx = c.path("context");
        if (!ctx.isObject()) {
            throw new IllegalArgumentException("context is not an object");
        }
        Set<String> fields = fields(ctx);
        if (!fields.equals(CONTEXT)) {
            throw new IllegalArgumentException("context fields " + fields + ", expected "
                    + new TreeSet<>(CONTEXT));
        }
        if (!purpose.equals(text(ctx, "purpose"))) {
            throw new IllegalArgumentException("context.purpose is '" + ctx.path("purpose").asText()
                    + "', expected '" + purpose + "'");
        }
        return new FieldContext(hex(ctx, "table_uuid"), hex(ctx, "column_uuid"),
                nullableHex(ctx, "tenant_id"), nullableHex(ctx, "row_id"));
    }

    /**
     * An index case's {@code declaration} (docs/08 §4.7, the index half) on the case's table and
     * column, field by field through the public builder, with nothing defaulted. An unknown field
     * is refused, for the reason {@link #context} gives: it may be one that changes the bytes.
     */
    static IndexDeclaration declaration(JsonNode d, FieldContext ctx) {
        if (!d.isObject()) {
            throw new IllegalArgumentException("declaration is not an object");
        }
        Set<String> fields = fields(d);
        Set<String> missing = new TreeSet<>(DECLARATION_REQUIRED);
        missing.removeAll(fields);
        Set<String> unknown = new TreeSet<>(fields);
        unknown.removeAll(DECLARATION_REQUIRED);
        unknown.removeAll(DECLARATION_OPTIONAL);
        if (!missing.isEmpty() || !unknown.isEmpty()) {
            throw new IllegalArgumentException("declaration: missing " + missing + ", unknown "
                    + unknown);
        }
        String idf = text(d, "idf");
        IndexDeclaration.Builder b = IndexDeclaration.builder(ctx.tableUuid(), ctx.columnUuid())
                .indexId(text(d, "index_id"))
                .idf(byId(Idf.values(), Idf::id, idf))
                .normalize(byId(Normalizer.values(), Normalizer::id, text(d, "normalize")))
                .truncateBits(integer(d, "truncate_bits"))
                .projectedPopulation(longInteger(d, "projected_population"))
                .onUnindexable(byId(OnUnindexable.values(), OnUnindexable::id,
                        text(d, "on_unindexable")));
        JsonNode params = d.path("idf_params");
        if (!params.isObject()) {
            throw new IllegalArgumentException("idf_params is not an object");
        }
        switch (idf) {
            case "hmac-sha512" -> {
                if (!params.isEmpty()) {
                    throw new IllegalArgumentException("hmac-sha512 with idf_params " + params);
                }
            }
            case "argon2id" -> {
                if (!fields(params).equals(Set.of("time_cost", "memory_kib"))) {
                    throw new IllegalArgumentException("argon2id idf_params " + fields(params)
                            + ", expected [memory_kib, time_cost]");
                }
                b.argon2(new Argon2Params(integer(params, "time_cost"),
                        integer(params, "memory_kib")));
            }
            default -> throw new IllegalArgumentException("unknown idf '" + idf + "'");
        }
        if (d.has("skewed")) {
            if (!d.path("skewed").isBoolean()) {
                throw new IllegalArgumentException("skewed is not a boolean");
            }
            b.skewed(d.path("skewed").asBoolean());
        }
        if (d.has("cardinality_override") && !d.path("cardinality_override").isNull()) {
            b.cardinalityOverride(override(d.path("cardinality_override")));
        }
        if (d.has("unindexable_override") && !d.path("unindexable_override").isNull()) {
            b.unindexableOverride(override(d.path("unindexable_override")));
        }
        return b.build();
    }

    private static ReviewedOverride override(JsonNode o) {
        if (!fields(o).equals(Set.of("reason", "approved_by", "date"))) {
            throw new IllegalArgumentException("an override's fields are " + fields(o)
                    + ", expected [approved_by, date, reason]");
        }
        return new ReviewedOverride(text(o, "reason"), text(o, "approved_by"),
                LocalDate.parse(text(o, "date")));
    }

    // --- JSON ----------------------------------------------------------------------------------

    static int suite(String s) {
        if (!SUITE.matcher(s).matches()) {
            throw new IllegalArgumentException("suite_id '" + s
                    + "' is not 0x followed by four hex digits");
        }
        return Integer.parseInt(s.substring(2), 16);
    }

    static Set<String> fields(JsonNode n) {
        Set<String> out = new TreeSet<>();
        n.fieldNames().forEachRemaining(out::add);
        return out;
    }

    static void expect(JsonNode n, String field, String want) {
        if (!want.equals(n.path(field).asText(null))) {
            throw new IllegalArgumentException(field + " is " + n.path(field) + ", expected "
                    + want);
        }
    }

    static String text(JsonNode n, String field) {
        if (!n.path(field).isTextual()) {
            throw new IllegalArgumentException(field + " is not a string");
        }
        return n.path(field).asText();
    }

    static byte[] hex(JsonNode n, String field) {
        String s = text(n, field);
        try {
            return HEX.parseHex(s);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(field + " is not hex", e);
        }
    }

    static String hex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    private static byte[] nullableHex(JsonNode n, String field) {
        return n.path(field).isNull() ? null : hex(n, field);
    }

    private static int integer(JsonNode n, String field) {
        if (!n.path(field).isIntegralNumber() || !n.path(field).canConvertToInt()) {
            throw new IllegalArgumentException(field + " is not an int");
        }
        return n.path(field).asInt();
    }

    private static long longInteger(JsonNode n, String field) {
        if (!n.path(field).isIntegralNumber() || !n.path(field).canConvertToLong()) {
            throw new IllegalArgumentException(field + " is not a long");
        }
        return n.path(field).asLong();
    }

    private static <E> E byId(E[] values, Function<E, String> id, String want) {
        return Arrays.stream(values).filter(e -> id.apply(e).equals(want)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("no such identifier '" + want
                        + "'"));
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every JDK provides SHA-256", e);
        }
    }
}
