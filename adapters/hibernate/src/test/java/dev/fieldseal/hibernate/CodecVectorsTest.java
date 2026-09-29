package dev.fieldseal.hibernate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * The {@code codec/} family (docs/08 §4.8), from {@code MANIFEST.adapter_files}, through the
 * adapter's real codec: the class both the write path and the index path call.
 *
 * <p><b>What Java can represent</b> decides the skips (docs/08 §5 item 7): a calendar date
 * ({@code LocalDate}), instants finer than a microsecond ({@code Instant}), and naive datetimes
 * ({@code LocalDateTime}). It has no need for spec §3.6's UTC-midnight date convention and no
 * millisecond-only instant, so the four vectors behind those two capabilities are skipped, the
 * same four as the Django adapter's.
 *
 * <p><b>Inputs Java's types cannot hold.</b> {@code BigDecimal} cannot hold NaN or ±Infinity, so
 * the {@code decimal} write vectors for them hand the codec the literal's text instead: a value
 * of the wrong type for a {@code BigDecimal} attribute, which the codec refuses. The refusal is
 * the codec's, through the same check a write path would reach; that the platform could never
 * produce the value in a {@code BigDecimal} attribute is stated here rather than counted twice.
 */
class CodecVectorsTest {

    static final Set<String> CAPABILITIES =
            Set.of("calendar-date", "microsecond-instants", "naive-datetimes");

    static JsonNode suite() throws Exception {
        JsonNode manifest = TestSupport.JSON.readTree(
                Files.readString(TestSupport.VECTORS.resolve("MANIFEST.json")));
        JsonNode entry = null;
        for (JsonNode e : manifest.get("adapter_files")) {
            if (e.get("path").asText().equals("codec/logical-types.json")) {
                entry = e;
            }
        }
        assertTrue(entry != null, "codec/logical-types.json is in MANIFEST.adapter_files");
        byte[] raw = Files.readAllBytes(TestSupport.VECTORS.resolve(entry.get("path").asText()));
        assertEquals(entry.get("bytes").asLong(), raw.length);
        assertEquals(entry.get("sha256").asText(), HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(raw)));
        JsonNode file = TestSupport.JSON.readTree(raw);
        assertEquals("pinned", file.get("status").asText());
        assertEquals(manifest.get("vector_suite_version").asText(),
                file.get("vector_suite_version").asText());
        return file;
    }

    static boolean held(JsonNode v) {
        for (JsonNode c : v.get("requires")) {
            if (!CAPABILITIES.contains(c.asText())) {
                return false;
            }
        }
        return true;
    }

    @Test
    void skipsOnlyForACapabilityJavaLacks() throws Exception {
        int skipped = 0;
        for (JsonNode v : suite().get("vectors")) {
            if (!held(v)) {
                skipped++;
            }
        }
        assertEquals(4, skipped);
    }

    @TestFactory
    Stream<DynamicTest> codec() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : suite().get("vectors")) {
            String id = v.get("id").asText();
            tests.add(DynamicTest.dynamicTest("codec[" + id + "]", () -> {
                Assumptions.assumeTrue(held(v), "capability not held: " + v.get("requires"));
                run(v);
            }));
        }
        return tests.stream();
    }

    static Codec codecFor(String type) {
        Class<?> t = switch (type) {
            case "string" -> String.class;
            case "bytes" -> byte[].class;
            case "int" -> BigInteger.class;
            case "decimal" -> BigDecimal.class;
            case "float" -> Double.class;
            case "boolean" -> Boolean.class;
            case "date" -> LocalDate.class;
            case "datetime" -> OffsetDateTime.class;
            default -> throw new IllegalArgumentException(type);
        };
        return Codec.of(t, "vector." + type);
    }

    static void run(JsonNode v) {
        String type = v.get("logical_type").asText();
        Codec codec = codecFor(type);
        JsonNode expected = v.get("expected");
        boolean refused = expected.has("refused");
        if (v.get("direction").asText().equals("write")) {
            Object value = value(type, v.get("input"));
            if (refused) {
                assertThrows(FieldsealNotSupportedException.class, () -> codec.render(value));
            } else {
                assertArrayEquals(HexFormat.of().parseHex(expected.get("plaintext").asText()),
                        codec.render(value));
            }
        } else {
            byte[] plaintext = HexFormat.of().parseHex(v.get("plaintext").asText());
            if (refused) {
                assertThrows(FieldsealNotSupportedException.class, () -> codec.parse(plaintext));
            } else {
                same(type, value(type, expected.get("value")), codec.parse(plaintext));
            }
        }
    }

    /** A literal as the Java value an application would hand the adapter (docs/08 §4.8). */
    static Object value(String type, JsonNode lit) {
        switch (type) {
            case "string": {
                if (lit.has("utf16")) {
                    ByteBuffer b = ByteBuffer.wrap(HexFormat.of().parseHex(lit.get("utf16").asText()));
                    StringBuilder s = new StringBuilder();
                    while (b.hasRemaining()) {
                        s.append(b.getChar());
                    }
                    return s.toString();
                }
                return lit.get("text").asText();
            }
            case "bytes":
                return HexFormat.of().parseHex(lit.get("hex").asText());
            case "int":
                return new BigInteger(lit.get("decimal").asText());
            case "decimal": {
                String text = lit.get("decimal").asText();
                try {
                    return new BigDecimal(text);
                } catch (NumberFormatException e) {
                    return text; // NaN, ±Infinity: see the class comment
                }
            }
            case "float":
                return Double.longBitsToDouble(Long.parseUnsignedLong(
                        lit.get("binary64").asText(), 16));
            case "boolean":
                return lit.get("boolean").asBoolean();
            case "date":
                if (lit.has("naive")) {
                    return LocalDateTime.parse(lit.get("naive").asText());
                }
                return LocalDate.parse(lit.get("date").asText());
            case "datetime":
                if (lit.has("naive")) {
                    return LocalDateTime.parse(lit.get("naive").asText());
                }
                return OffsetDateTime.parse(lit.get("instant").asText());
            default:
                throw new IllegalArgumentException(type);
        }
    }

    static void same(String type, Object want, Object got) {
        switch (type) {
            case "bytes" -> assertArrayEquals((byte[]) want, (byte[]) got);
            case "decimal" -> {
                assertEquals(0, ((BigDecimal) want).compareTo((BigDecimal) got));
                assertEquals(((BigDecimal) want).toPlainString(),
                        ((BigDecimal) got).toPlainString(), "read back as its canonical form");
            }
            case "float" -> assertEquals(Double.doubleToRawLongBits((Double) want),
                    Double.doubleToRawLongBits((Double) got));
            case "datetime" -> assertEquals(((OffsetDateTime) want).toInstant(),
                    ((OffsetDateTime) got).toInstant());
            default -> assertEquals(want, got);
        }
    }

    // ---- what the family does not reach: the platform's own types --------------------------

    @Test
    void anIntReadIsBoundedByTheAttributesType() {
        byte[] big = "9223372036854775808".getBytes(StandardCharsets.US_ASCII);
        assertThrows(FieldsealNotSupportedException.class,
                () -> Codec.of(Long.class, "x").parse(big));
        assertEquals(new BigInteger("9223372036854775808"), Codec.of(BigInteger.class, "x")
                .parse(big));
        assertThrows(FieldsealNotSupportedException.class,
                () -> Codec.of(int.class, "x").parse("2147483648".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(-32768, ((Short) Codec.of(Short.class, "x")
                .parse("-32768".getBytes(StandardCharsets.US_ASCII))).intValue());
        assertThrows(FieldsealNotSupportedException.class,
                () -> Codec.of(short.class, "x").parse("32768".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void anInstantAttributeRendersLikeAnOffsetOne() {
        Codec i = Codec.of(Instant.class, "x");
        assertArrayEquals("2026-09-08T12:00:00.000000Z".getBytes(StandardCharsets.US_ASCII),
                i.render(Instant.parse("2026-09-08T12:00:00Z")));
        assertEquals(Instant.parse("2026-09-08T12:00:00.123456Z"),
                i.parse("2026-09-08T12:00:00.123456Z".getBytes(StandardCharsets.US_ASCII)));
        assertThrows(FieldsealNotSupportedException.class,
                () -> i.render(Instant.parse("2026-09-08T12:00:00.000000001Z")));
    }

    @Test
    void theWrongJavaTypeIsRefused() {
        assertThrows(FieldsealNotSupportedException.class,
                () -> Codec.of(Long.class, "x").render(1));
        assertThrows(FieldsealNotSupportedException.class,
                () -> Codec.of(String.class, "x").render(new byte[0]));
    }

    /** ECMAScript's Number::toString, where Double.toString differs (the smallest subnormal). */
    @Test
    void floatRenderingIsEcmaScriptsNotTheJdks() {
        assertEquals("4.9E-324", Double.toString(Double.MIN_VALUE));
        assertEquals("5e-324", Codec.ecmaScriptToString(Double.MIN_VALUE));
        assertEquals("1.7976931348623157e+308", Codec.ecmaScriptToString(Double.MAX_VALUE));
        assertEquals("100000000000000000000", Codec.ecmaScriptToString(1e20));
        assertEquals("1e+21", Codec.ecmaScriptToString(1e21));
        assertEquals("0.000001", Codec.ecmaScriptToString(1e-6));
        assertEquals("1e-7", Codec.ecmaScriptToString(1e-7));
        assertEquals("0.1", Codec.ecmaScriptToString(0.1));
        assertEquals("-0", Codec.ecmaScriptToString(-0.0));
        assertEquals("123.456", Codec.ecmaScriptToString(123.456));
    }
}
