package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.files;
import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.capabilities.SuiteFiles.id;
import static dev.fieldseal.core.capabilities.SuiteFiles.vectors;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.IndexDeclaration;
import dev.fieldseal.core.IndexDeclaration.Argon2Params;
import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.core.IndexDeclaration.OnUnindexable;
import dev.fieldseal.core.IndexDeclaration.ReviewedOverride;
import dev.fieldseal.core.KeyProviders;
import dev.fieldseal.core.errors.InvalidArgumentError;
import dev.fieldseal.core.internal.blindindex.Normalizers;
import dev.fieldseal.core.internal.context.CanonicalContext;
import dev.fieldseal.core.internal.kdf.Hkdf;
import dev.fieldseal.core.internal.kdf.KeyDerivation;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * {@code blind-index/} (docs/08 §4.4), both files, every shape, at every cost point the Argon2id
 * file pins (docs/27 §8, S5 exit).
 *
 * <p>A primitive vector is checked twice. First stage by stage, from its normative inputs: the
 * index key from its provenance, the normalizer from the preimage, the Argon2id salt, {@code raw},
 * {@code index} and {@code stored}. Then as {@code #pipeline}: through the public client, from the
 * tenant index key and the declaration alone, with a {@code row_id} on the caller's context so
 * that the client's own drop is on the path (docs/08 §5 item 11), and over both text and bytes.
 * The assertion shapes run through the client too, which is where {@code on_unindexable} lives.
 */
class BlindIndexVectorsTest {

    /** Per file, per shape: how many vectors. A shape this test does not know fails the file. */
    private static final Map<String, Map<String, Integer>> PINNED = new LinkedHashMap<>();

    static {
        PINNED.put("blind-index/argon2id.json", new TreeMap<>(Map.of("primitive", 12, "equal", 6,
                "unindexable-marker", 2, "unindexable-bucket", 1, "refuse", 2)));
        // Since suite 0.10.0-provisional, spec §7.6's gate as six declaration vectors (#211),
        // in this file only: the gate never reads the IDF (docs/08 §4.4).
        PINNED.put("blind-index/hmac-sha512.json", new TreeMap<>(Map.of("primitive", 11,
                "equal", 6, "unindexable-marker", 1, "unindexable-bucket", 1, "refuse", 2,
                "declaration", 6)));
    }

    private static final byte[] DEK = bytes("000102030405060708090a0b0c0d0e0f"
            + "101112131415161718191a1b1c1d1e1f");
    private static final byte[] KEY_ID = bytes("0123456789abcdef0123456789abcdef");
    private static final byte[] ROW = "row-42".getBytes(StandardCharsets.US_ASCII);
    private static final ReviewedOverride REVIEWED =
            new ReviewedOverride("vector harness", "docs/08 §4.4", LocalDate.of(2026, 9, 27));

    private static byte[] bytes(String s) {
        return java.util.HexFormat.of().parseHex(s);
    }

    @TestFactory
    Stream<DynamicTest> blindIndexFamily() {
        List<String> listed = files().stream().map(VectorHarness.FileWalk::path)
                .filter(p -> p.startsWith("blind-index/")).toList();
        assertEquals(PINNED.keySet(), Set.copyOf(listed),
                "blind-index/ in MANIFEST.files is not the set of files this test pins");
        List<DynamicTest> tests = new ArrayList<>();
        for (String path : listed) {
            Map<String, Integer> seen = new TreeMap<>();
            for (JsonNode v : vectors(path)) {
                String shape = v.has("assertion") ? v.path("assertion").asText() : "primitive";
                seen.merge(shape, 1, Integer::sum);
                switch (shape) {
                    case "primitive" -> {
                        tests.add(DynamicTest.dynamicTest(id(v), () -> primitive(v)));
                        tests.add(DynamicTest.dynamicTest(id(v) + "#pipeline",
                                () -> pipeline(v)));
                    }
                    case "equal" -> tests.add(DynamicTest.dynamicTest(id(v), () -> equal(v)));
                    case "unindexable-marker" ->
                            tests.add(DynamicTest.dynamicTest(id(v), () -> marker(v)));
                    case "unindexable-bucket" ->
                            tests.add(DynamicTest.dynamicTest(id(v), () -> bucket(v)));
                    case "refuse" -> tests.add(DynamicTest.dynamicTest(id(v), () -> refuse(v)));
                    case "declaration" -> tests.add(DynamicTest.dynamicTest(id(v),
                            () -> DeclarationVectors.run(v)));
                    default -> tests.add(DynamicTest.dynamicTest(id(v), () -> fail(
                            "unrecognised assertion kind '" + shape + "' (docs/08 §4: fail,"
                                    + " never skip)")));
                }
            }
            assertEquals(PINNED.get(path), seen, path + ": per-shape counts moved");
        }
        return tests.stream();
    }

    // --- the shapes ------------------------------------------------------------------------------

    private static void primitive(JsonNode v) {
        dev.fieldseal.core.internal.blindindex.Idf.Params p = params(v);
        byte[] indexKey = hex(v.path("index_key"));
        // The index key from its provenance (spec §7.2), which is what #pipeline relies on.
        assertEquals(v.path("index_key").asText(), hex(KeyDerivation.indexKey(
                hex(v.path("tenant_index_key")), CanonicalContext.encodeForIndexKey(
                        PrimitiveVectors.context(PrimitiveVectors.suiteId(v),
                                v.path("context"))))), "index_key");
        assertEquals("index:" + v.path("index_id").asText(),
                v.path("context").path("purpose").asText(), "purpose names index_id");
        // The named normalizer over the preimage gives the normative plaintext (docs/08 §4.4).
        byte[] plaintext = hex(v.path("plaintext"));
        assertEquals(v.path("plaintext").asText(), hex(normalizer(v.path("normalize"))
                .normalize(v.path("plaintext_preimage").asText())), "plaintext");
        if (p instanceof dev.fieldseal.core.internal.blindindex.Idf.Params.Argon2id) {
            assertEquals(v.path("idf_params").path("salt").asText(),
                    hex(dev.fieldseal.core.internal.blindindex.Idf.argon2Salt(indexKey,
                            Hkdf::derive)), "salt");
        }
        byte[] raw = dev.fieldseal.core.internal.blindindex.Idf.raw(p, indexKey, plaintext,
                Hkdf::derive);
        JsonNode e = v.path("expected");
        assertEquals(e.path("raw").asText(), hex(raw), "raw");
        byte[] index = dev.fieldseal.core.internal.blindindex.Idf.truncate(raw,
                v.path("truncate_bits").asInt());
        assertEquals(e.path("index").asText(), hex(index), "index");
        stored(e, index, v.path("truncate_bits").asInt());
    }

    /** The public client, from the tenant index key and the declaration alone. */
    private static void pipeline(JsonNode v) {
        Fieldseal fs = client(v, OnUnindexable.REFUSE);
        FieldContext ctx = callerContext(v.path("context")).forIndex(v.path("index_id").asText());
        String preimage = v.path("plaintext_preimage").asText();
        String expected = v.path("expected").path("index").asText();
        assertEquals(expected, hex(fs.blindIndex(preimage, ctx)), "text");
        assertEquals(expected, hex(fs.blindIndex(preimage.getBytes(StandardCharsets.UTF_8), ctx)),
                "bytes");
        stored(v.path("expected"), fs.blindIndex(preimage, ctx), v.path("truncate_bits").asInt());
    }

    /** Two preimages, recomputed; their equality is {@code must_be_equal} (docs/08 §4). */
    private static void equal(JsonNode v) {
        JsonNode in = v.path("inputs");
        Normalizer n = normalizer(in.path("normalize"));
        byte[] key = hex(in.path("index_key"));
        int bits = in.path("truncate_bits").asInt();
        byte[] a = index(in, key, n.normalize(in.path("plaintext_preimage_a").asText()), bits);
        byte[] b = index(in, key, n.normalize(in.path("plaintext_preimage_b").asText()), bits);
        JsonNode e = v.path("expected");
        assertEquals(e.path("index_a").asText(), hex(a), "index_a");
        assertEquals(e.path("index_b").asText(), hex(b), "index_b");
        assertTrue(e.path("must_be_equal").isBoolean(), "must_be_equal is not a boolean");
        assertEquals(e.path("must_be_equal").asBoolean(), Arrays.equals(a, b), "must_be_equal");
    }

    /** docs/09 §7.2's marker, as a primitive and through {@code unindexableMarker}. */
    private static void marker(JsonNode v) {
        JsonNode in = v.path("inputs");
        assertEquals(in.path("reserved_preimage").asText(), hex(Normalizers.reservedPreimage()),
                "reserved_preimage");
        String expected = v.path("expected").path("index").asText();
        int bits = in.path("truncate_bits").asInt();
        assertEquals(expected, hex(index(in, hex(in.path("index_key")),
                Normalizers.reservedPreimage(), bits)), "primitive");
        Fieldseal fs = client(in, OnUnindexable.REFUSE);
        FieldContext ctx = callerContext(in.path("context")).forIndex(in.path("index_id").asText());
        byte[] marker = fs.unindexableMarker(ctx);
        assertEquals(expected, hex(marker), "unindexableMarker");
        stored(v.path("expected"), marker, bits);
    }

    /** Under {@code bucket} the refused value derives the marker; under {@code refuse}, it raises. */
    private static void bucket(JsonNode v) {
        JsonNode in = v.path("inputs");
        assertEquals("bucket", in.path("on_unindexable").asText());
        String preimage = in.path("plaintext_preimage").asText();
        int unassigned = Integer.parseInt(in.path("unassigned_code_point").asText().substring(2),
                16);
        assertEquals(unassigned, Fieldseal.firstUnassigned(preimage).orElseThrow().codePoint(),
                "the preimage's first unassigned code point");
        FieldContext ctx = callerContext(in.path("context")).forIndex(in.path("index_id").asText());
        Fieldseal bucketed = client(in, OnUnindexable.BUCKET);
        byte[] index = bucketed.blindIndex(preimage, ctx);
        JsonNode e = v.path("expected");
        assertEquals(e.path("index").asText(), hex(index), "index");
        assertTrue(e.path("equals_marker").asBoolean());
        assertArrayEquals(bucketed.unindexableMarker(ctx), index, "equals_marker");
        assertArrayEquals(index, bucketed.blindIndex(preimage.getBytes(StandardCharsets.UTF_8),
                ctx), "bytes");
        InvalidArgumentError refused = assertThrows(InvalidArgumentError.class,
                () -> client(in, OnUnindexable.REFUSE).blindIndex(preimage, ctx));
        assertEquals(e.path("on_unindexable_refuse").asText(), refused.code());
    }

    /** The preimage, as bytes, is refused; the two refuse vectors of a file are refused apart. */
    private static void refuse(JsonNode v) {
        JsonNode in = v.path("inputs");
        assertEquals("refuse", in.path("on_unindexable").asText());
        FieldContext ctx = callerContext(in.path("context")).forIndex(in.path("index_id").asText());
        InvalidArgumentError e = assertThrows(InvalidArgumentError.class,
                () -> client(in, OnUnindexable.REFUSE).blindIndex(hex(in.path("preimage")), ctx));
        assertEquals(v.path("expected").path("refuse").asText(), e.code());
    }

    /**
     * docs/08 §5 item 9's second half, on the bytes path: the two {@code refuse} preimages are
     * refused with diagnoses that differ, and that name the malformed bytes.
     */
    @Test
    void theTwoRefusePreimagesAreRefusedDistinguishably() {
        for (String path : PINNED.keySet()) {
            List<String> messages = new ArrayList<>();
            for (JsonNode v : vectors(path)) {
                if (!"refuse".equals(v.path("assertion").asText())) {
                    continue;
                }
                JsonNode in = v.path("inputs");
                FieldContext ctx = callerContext(in.path("context"))
                        .forIndex(in.path("index_id").asText());
                messages.add(assertThrows(InvalidArgumentError.class,
                        () -> client(in, OnUnindexable.REFUSE).blindIndex(hex(in.path("preimage")),
                                ctx)).getMessage());
            }
            assertEquals(2, messages.size(), path);
            assertNotEquals(messages.get(0), messages.get(1), path);
            assertTrue(messages.get(0).contains("EDA080") && messages.get(1).contains("EDB080"),
                    messages.toString());
        }
    }

    // --- helpers -------------------------------------------------------------------------------

    private static void stored(JsonNode e, byte[] index, int bits) {
        JsonNode s = e.path("stored");
        assertEquals(s.path("binary").asText(), hex(index), "stored.binary");
        assertEquals(s.path("octets").asInt(), index.length, "stored.octets");
        assertEquals((bits + 7) / 8, index.length, "stored.octets is ⌈b/8⌉");
        // stored.hex: this core returns binary only (docs/09 §3.3), so there is no hex form to
        // compare. The report says so in harness_notes; it is never counted as passed.
    }

    private static byte[] index(JsonNode in, byte[] key, byte[] normalized, int bits) {
        return dev.fieldseal.core.internal.blindindex.Idf.blindIndex(params(in), key, normalized,
                bits, Hkdf::derive);
    }

    /**
     * docs/08 §4.4: the cost comes from {@code idf_params}, never from a default; a missing
     * {@code time_cost} or {@code memory_kib} is malformed, and the pinned fields must be §7.3's.
     */
    private static dev.fieldseal.core.internal.blindindex.Idf.Params params(JsonNode in) {
        JsonNode p = in.path("idf_params");
        assertTrue(p.isObject(), "idf_params is missing: malformed (docs/08 §4.4)");
        return switch (in.path("idf").asText()) {
            case "hmac-sha512" -> {
                assertEquals(0, p.size(), "hmac-sha512 carries empty idf_params");
                yield new dev.fieldseal.core.internal.blindindex.Idf.Params.HmacSha512();
            }
            case "argon2id" -> {
                assertTrue(p.has("time_cost") && p.has("memory_kib"),
                        "argon2id idf_params without time_cost and memory_kib: malformed");
                for (String[] pin : new String[][] {{"version", "19"}, {"parallelism", "1"},
                    {"output_len", "64"}}) {
                    if (p.has(pin[0])) {
                        assertEquals(pin[1], p.path(pin[0]).asText(), pin[0] + " is spec §7.3's");
                    }
                }
                yield new dev.fieldseal.core.internal.blindindex.Idf.Params.Argon2id(
                        p.path("time_cost").asInt(), p.path("memory_kib").asInt());
            }
            default -> throw new AssertionError("unknown idf " + in.path("idf"));
        };
    }

    private static Normalizer normalizer(JsonNode id) {
        for (Normalizer n : Normalizer.values()) {
            if (n.id().equals(id.asText())) {
                return n;
            }
        }
        throw new AssertionError("unknown normalizer " + id);
    }

    /** A client declaring the vector's index, with the vector's tenant index key. */
    private static Fieldseal client(JsonNode in, OnUnindexable policy) {
        JsonNode c = in.path("context");
        int bits = in.path("truncate_bits").asInt();
        IndexDeclaration.Builder d = IndexDeclaration.builder(hex(c.path("table_uuid")),
                        hex(c.path("column_uuid")))
                .indexId(in.path("index_id").asText())
                .normalize(normalizer(in.path("normalize")))
                .truncateBits(bits)
                // The vectors carry no P; 2^(b+1) is the smallest in spec §7.4's band.
                .projectedPopulation(1L << (bits + 1))
                .onUnindexable(policy);
        if (policy == OnUnindexable.BUCKET) {
            d.unindexableOverride(REVIEWED);
        }
        var p = params(in);
        if (p instanceof dev.fieldseal.core.internal.blindindex.Idf.Params.Argon2id a) {
            d.idf(Idf.ARGON2ID).argon2(new Argon2Params(a.timeCost(), a.memoryKib()));
        } else {
            d.idf(Idf.HMAC_SHA512);
        }
        return Fieldseal.builder()
                .keyProvider(KeyProviders.staticKeys(DEK, hex(in.path("tenant_index_key")), KEY_ID))
                .allowedSuites(Set.of(0xFF01)).writeSuite(0xFF01)
                .indexes(List.of(d.build()))
                .onWarning(w -> { })
                .build();
    }

    /** The vector's derivation context as a caller holds it: with a row, which the core drops. */
    private static FieldContext callerContext(JsonNode c) {
        assertTrue(c.path("row_id").isNull(), "an index derivation context has no row_id");
        return new FieldContext(hex(c.path("table_uuid")), hex(c.path("column_uuid")),
                c.path("tenant_id").isNull() ? null : hex(c.path("tenant_id")), ROW);
    }
}
