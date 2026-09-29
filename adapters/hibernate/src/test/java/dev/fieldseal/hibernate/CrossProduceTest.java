package dev.fieldseal.hibernate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.IndexDeclaration;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The producer's document, consumed here by a client built independently from {@code
 * vectors/keys/} and from each case's own declaration (docs/29 §8). The consumers in the other
 * languages run in CI's cross job.
 */
class CrossProduceTest {

    static byte[] hex(JsonNode n) {
        return n == null || n.isNull() ? null : HexFormat.of().parseHex(n.asText());
    }

    static FieldContext context(JsonNode c) {
        FieldContext ctx = FieldContext.of(hex(c.get("table_uuid")), hex(c.get("column_uuid")));
        if (hex(c.get("tenant_id")) != null) {
            ctx = ctx.withTenant(hex(c.get("tenant_id")));
        }
        return ctx;
    }

    @Test
    void everyCaseIsReadableFromTheSharedKeyAlone() {
        ObjectNode doc = CrossProduce.produce();
        assertEquals("fieldseal-vectors/cross/v2", doc.get("schema").asText());
        assertEquals("hibernate", doc.get("producer").get("implementation").asText());
        Fieldseal client = TestSupport.independentClient();
        int tenantBound = 0;
        for (JsonNode c : doc.get("cases")) {
            assertEquals(TestSupport.KEY_REF, c.get("key_ref").asText());
            assertEquals("encrypt", c.get("context").get("purpose").asText());
            byte[] pt = client.decrypt(hex(c.get("envelope")), context(c.get("context")));
            assertArrayEquals(hex(c.get("plaintext")), pt, c.get("id").asText());
            if (!c.get("context").get("tenant_id").isNull()) {
                tenantBound++;
            }
        }
        assertTrue(tenantBound >= 1, "docs/08 §4.7: at least one tenant-bound case");
    }

    @Test
    void everyIndexCaseIsRederivedFromItsOwnDeclaration() {
        ObjectNode doc = CrossProduce.produce();
        boolean marker = false;
        for (JsonNode c : doc.get("index_cases")) {
            JsonNode d = c.get("declaration");
            JsonNode ctx = c.get("context");
            assertEquals("index:" + d.get("index_id").asText(), ctx.get("purpose").asText());
            IndexDeclaration.Builder b = IndexDeclaration.builder(hex(ctx.get("table_uuid")),
                            hex(ctx.get("column_uuid")))
                    .indexId(d.get("index_id").asText())
                    .idf(IndexDeclaration.Idf.HMAC_SHA512)
                    .normalize(IndexDeclaration.Normalizer.NFC_CASEFOLD_V1)
                    .truncateBits(d.get("truncate_bits").asInt())
                    .projectedPopulation(d.get("projected_population").asLong());
            assertEquals("hmac-sha512", d.get("idf").asText());
            assertEquals("nfc-casefold-v1", d.get("normalize").asText());
            if (d.get("on_unindexable").asText().equals("bucket")) {
                JsonNode o = d.get("unindexable_override");
                b.onUnindexable(IndexDeclaration.OnUnindexable.BUCKET).unindexableOverride(
                        new IndexDeclaration.ReviewedOverride(o.get("reason").asText(),
                                o.get("approved_by").asText(),
                                LocalDate.parse(o.get("date").asText())));
            }
            Fieldseal.Builder fb = Fieldseal.builder();
            TestSupport.configurer().configure(fb);
            Fieldseal client = fb.indexes(List.of(b.build())).build();
            FieldContext fc = context(ctx).forIndex(d.get("index_id").asText());
            byte[] want = c.has("value_marker") ? client.unindexableMarker(fc)
                    : client.blindIndex(c.get("value_text").asText(), fc);
            marker |= c.has("value_marker");
            assertArrayEquals(want, hex(c.get("index")), c.get("id").asText());
        }
        assertTrue(marker, "the bucket-marker case is present");
    }

    /** Two runs disagree on every envelope: a producer on a fixed seed would pass the rest. */
    @Test
    void twoRunsDisagreeOnEveryEnvelope() {
        Set<String> first = new HashSet<>();
        for (JsonNode c : CrossProduce.produce().get("cases")) {
            first.add(c.get("envelope").asText());
        }
        for (JsonNode c : CrossProduce.produce().get("cases")) {
            assertTrue(!first.contains(c.get("envelope").asText()), c.get("id").asText());
        }
        assertNotEquals(0, first.size());
    }
}
