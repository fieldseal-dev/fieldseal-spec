package dev.fieldseal.core;

import static dev.fieldseal.core.Fixtures.COLUMN;
import static dev.fieldseal.core.Fixtures.TABLE;
import static dev.fieldseal.core.Fixtures.builder;
import static dev.fieldseal.core.Fixtures.ctx;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.IndexDeclaration.Argon2Params;
import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.core.IndexDeclaration.OnUnindexable;
import dev.fieldseal.core.IndexDeclaration.ReviewedOverride;
import dev.fieldseal.core.errors.ConfigurationError;
import dev.fieldseal.core.errors.InvalidArgumentError;
import dev.fieldseal.core.errors.KeyUnavailableError;
import dev.fieldseal.core.keyprovider.KeyRequest;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/**
 * The client's blind-index surface (docs/09 §2, §3.3, §7; docs/27 §4): declaration validation and
 * its resolved form, the order {@code blindIndex} refuses in, {@code on_unindexable}, the modes
 * that do not gate it, index-role {@code warm}, and what reaches the provider.
 */
class BlindIndexClientTest {

    private static final ReviewedOverride REVIEWED =
            new ReviewedOverride("a reviewed reason", "security", LocalDate.of(2026, 9, 27));

    /** An hmac-sha512 email index at P = 100,000, b = 15: inside spec §7.4's band. */
    private static IndexDeclaration.Builder email() {
        return IndexDeclaration.builder(TABLE, COLUMN).indexId("email-eq").idf(Idf.HMAC_SHA512)
                .normalize(Normalizer.NFC_CASEFOLD_V1).truncateBits(15)
                .projectedPopulation(100_000);
    }

    private static Fieldseal client(Fixtures.SpyProvider p, IndexDeclaration... ds) {
        return builder(p).indexes(List.of(ds)).build();
    }

    private static ConfigurationError refusedDeclaration(UnaryOperator<IndexDeclaration.Builder> f) {
        IndexDeclaration d = f.apply(email()).build();
        ConfigurationError e = assertThrows(ConfigurationError.class,
                () -> Fieldseal.validateIndexDeclaration(d));
        // The builder refuses with the same rule, so a client cannot be built around it.
        assertThrows(ConfigurationError.class,
                () -> client(new Fixtures.SpyProvider(), d));
        return e;
    }

    // --- validation -------------------------------------------------------------------------------

    @Test
    void defaultsAreResolvedInTheValidatedForm() {
        ValidatedIndex v = Fieldseal.validateIndexDeclaration(IndexDeclaration.builder(TABLE,
                COLUMN).idf(Idf.ARGON2ID).normalize(Normalizer.NFC_CASEFOLD_V1).truncateBits(15)
                .projectedPopulation(100_000).build());
        assertEquals("exact", v.indexId());
        assertEquals(new Argon2Params(3, 32768), v.argon2(), "spec §7.3's minima, filled in");
        assertEquals(OnUnindexable.REFUSE, v.onUnindexable());
        assertEquals("index:exact", v.purpose());
        assertNull(Fieldseal.validateIndexDeclaration(email().build()).argon2(),
                "hmac-sha512 has no cost");
    }

    /** #62: a raised cost is a different index, and the validated forms say so. */
    @Test
    void aRaisedCostValidatesToADifferentIndex() {
        IndexDeclaration.Builder base = email().idf(Idf.ARGON2ID);
        ValidatedIndex min = Fieldseal.validateIndexDeclaration(base.build());
        ValidatedIndex raised = Fieldseal.validateIndexDeclaration(
                base.argon2(new Argon2Params(4, 32768)).build());
        assertNotEquals(min, raised);
        assertEquals(min, Fieldseal.validateIndexDeclaration(
                base.argon2(new Argon2Params(3, 32768)).build()), "explicit minima = defaulted");
    }

    /** spec §6.1: the index-id grammar, at declaration (docs/08 §4.3's four refusals). */
    @Test
    void theIndexIdGrammarIsCheckedAtDeclaration() {
        for (String bad : new String[] {"Exact", "é", "", "a".repeat(33)}) {
            ConfigurationError e = refusedDeclaration(b -> b.indexId(bad));
            assertTrue(e.getMessage().contains("§6.1"), e.getMessage());
        }
        Fieldseal.validateIndexDeclaration(email().indexId("a".repeat(32)).build());
    }

    @Test
    void theArgon2CostIsCheckedAtDeclaration() {
        refusedDeclaration(b -> b.argon2(new Argon2Params(3, 32768)));
        refusedDeclaration(b -> b.idf(Idf.ARGON2ID).argon2(new Argon2Params(2, 32768)));
        refusedDeclaration(b -> b.idf(Idf.ARGON2ID).argon2(new Argon2Params(3, 32767)));
        ConfigurationError e = refusedDeclaration(b -> b.idf(Idf.ARGON2ID)
                .argon2(new Argon2Params(3, (1 << 24) + 1)));
        assertTrue(e.getMessage().contains("BouncyCastle"), e.getMessage());
    }

    /** spec §7.4: 2^(b+1) <= P < 2^(2b), and P >= 16, at each edge. */
    @Test
    void theTruncationBandIsExact() {
        Fieldseal.validateIndexDeclaration(email().projectedPopulation(1L << 16).build());
        refusedDeclaration(b -> b.projectedPopulation((1L << 16) - 1));
        Fieldseal.validateIndexDeclaration(email().projectedPopulation((1L << 30) - 1).build());
        refusedDeclaration(b -> b.projectedPopulation(1L << 30));
        refusedDeclaration(b -> b.projectedPopulation(15).truncateBits(2)
                .cardinalityOverride(REVIEWED));
        refusedDeclaration(b -> b.truncateBits(0));
        refusedDeclaration(b -> b.truncateBits(513));
        // b = 61 needs P >= 2^62: the largest band a long can hold.
        Fieldseal.validateIndexDeclaration(email().truncateBits(61).projectedPopulation(1L << 62)
                .build());
        refusedDeclaration(b -> b.truncateBits(62).projectedPopulation(Long.MAX_VALUE));
    }

    /** spec §7.6: below 2^10 distinct values needs a reviewed override, and it is logged. */
    @Test
    void theCardinalityGateNeedsAReviewedOverrideAndLogsIt() {
        IndexDeclaration.Builder small = email().truncateBits(6).projectedPopulation(1000);
        ConfigurationError e = refusedDeclaration(b -> b.truncateBits(6).projectedPopulation(1000));
        assertTrue(e.getMessage().contains("§7.6"), e.getMessage());
        refusedDeclaration(b -> b.truncateBits(6).projectedPopulation(1000)
                .cardinalityOverride(new ReviewedOverride(" ", "security", LocalDate.now())));
        refusedDeclaration(b -> b.truncateBits(6).projectedPopulation(1000)
                .cardinalityOverride(new ReviewedOverride("why", "security", null)));
        List<String> warnings = new ArrayList<>();
        builder(new Fixtures.SpyProvider()).onWarning(warnings::add)
                .indexes(List.of(small.cardinalityOverride(REVIEWED).build())).build();
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("§7.6") && warnings.get(0).contains("a reviewed reason")
                && warnings.get(0).contains("security"), warnings.get(0));
        Fieldseal.validateIndexDeclaration(email().truncateBits(6).projectedPopulation(1024).build());
    }

    /** docs/09 §7.2: bucket needs its override, and a normalizer that can refuse. */
    @Test
    void bucketNeedsAnOverrideAndARefusingNormalizer() {
        refusedDeclaration(b -> b.onUnindexable(OnUnindexable.BUCKET));
        for (Normalizer n : new Normalizer[] {Normalizer.IDENTITY, Normalizer.DIGITS_ONLY_V1}) {
            refusedDeclaration(b -> b.normalize(n).onUnindexable(OnUnindexable.BUCKET)
                    .unindexableOverride(REVIEWED));
        }
        List<String> warnings = new ArrayList<>();
        builder(new Fixtures.SpyProvider()).onWarning(warnings::add).indexes(List.of(
                email().onUnindexable(OnUnindexable.BUCKET).unindexableOverride(REVIEWED).build()))
                .build();
        assertEquals(1, warnings.size(), "the override is logged");
    }

    @Test
    void missingFieldsAndDuplicatesAreRefused() {
        refusedDeclaration(b -> b.idf(null));
        refusedDeclaration(b -> b.normalize(null));
        assertThrows(ConfigurationError.class, () -> Fieldseal.validateIndexDeclaration(
                IndexDeclaration.builder(new byte[15], COLUMN).idf(Idf.HMAC_SHA512)
                        .normalize(Normalizer.IDENTITY).truncateBits(15)
                        .projectedPopulation(100_000).build()));
        assertThrows(ConfigurationError.class, () -> client(new Fixtures.SpyProvider(),
                email().build(), email().truncateBits(14).build()));
        assertThrows(ConfigurationError.class, () -> builder(new Fixtures.SpyProvider())
                .indexes(null).build());
        List<IndexDeclaration> withNull = new ArrayList<>();
        withNull.add(null);
        assertThrows(ConfigurationError.class, () -> builder(new Fixtures.SpyProvider())
                .indexes(withNull).build());
    }

    // --- reflection -------------------------------------------------------------------------------

    @Test
    void indexesReportsTheValidatedRegistryAndCannotBeChanged() {
        IndexDeclaration d = email().build();
        Fieldseal fs = client(new Fixtures.SpyProvider(), d);
        Map<String, ValidatedIndex> ix = fs.indexes();
        String key = Fieldseal.indexRegistryKey(TABLE, COLUMN, "email-eq");
        assertEquals(Map.of(key, Fieldseal.validateIndexDeclaration(d)), ix);
        assertThrows(UnsupportedOperationException.class, ix::clear);
        ix.get(key).tableUuid()[0] ^= 1;
        assertArrayEquals(TABLE, fs.indexes().get(key).tableUuid(), "arrays are copied out");
    }

    // --- blindIndex --------------------------------------------------------------------------------

    @Test
    void theRefusalOrderAtTheBoundary() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        Fieldseal fs = client(p, email().build());
        FieldContext ix = ctx().forIndex("email-eq");
        assertThrows(InvalidArgumentError.class, () -> fs.blindIndex((String) null, null));
        assertThrows(InvalidArgumentError.class, () -> fs.blindIndex("v", null));
        assertThrows(InvalidArgumentError.class, () -> fs.blindIndex("v", ctx()),
                "a value context names no index");
        assertThrows(ConfigurationError.class, () -> fs.blindIndex("v", ctx().forIndex("other")),
                "never a default IDF (docs/09 §3.3 step 2)");
        assertEquals(List.of(), p.calls, "nothing above reached the provider");
        p.failWith = new IllegalStateException("kms down");
        assertThrows(KeyUnavailableError.class, () -> fs.blindIndex("a͸", ix),
                "key acquisition precedes normalization");
        p.failWith = null;
        assertThrows(InvalidArgumentError.class, () -> fs.blindIndex("a͸", ix));
    }

    @Test
    void theIndexKeyRequestCarriesTheDeclaredPurposeAndNoRow() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        Fieldseal fs = client(p, email().build());
        byte[] a = fs.blindIndex("Ada@Example.com", ctx().withRow(new byte[] {1})
                .forIndex("email-eq"));
        KeyRequest r = (KeyRequest) p.calls.get(0);
        assertEquals("index:email-eq", r.purpose());
        assertNull(r.rowId(), "the index key is not per row (spec §7.2)");
        assertArrayEquals(a, fs.blindIndex("ada@example.com", ctx().forIndex("email-eq")),
                "the row is dropped and the normalizer folds");
        assertEquals(2, a.length, "⌈15/8⌉ bytes (spec §7.11)");
        assertEquals(0, a[1] & 1, "the trailing bit is zero");
    }

    @Test
    void aValueOperationRefusesAnIndexContext() {
        Fieldseal fs = client(new Fixtures.SpyProvider(), email().build());
        FieldContext ix = ctx().forIndex("email-eq");
        byte[] env = fs.encrypt(new byte[] {1}, ctx());
        assertThrows(InvalidArgumentError.class, () -> fs.encrypt(new byte[] {1}, ix));
        assertThrows(InvalidArgumentError.class, () -> fs.decrypt(env, ix));
        assertThrows(InvalidArgumentError.class, () -> fs.rotate(env, ix));
        assertThrows(InvalidArgumentError.class, () -> ctx().forIndex("Exact"),
                "the grammar holds on the context too");
    }

    /** spec §10.3 and §4.8: a query's index is not a write, so neither mode nor arming gates it. */
    @Test
    void readonlyAndUnarmedClientsDeriveIndexes() {
        Fieldseal armed = client(new Fixtures.SpyProvider(), email().build());
        byte[] expected = armed.blindIndex("ada@example.com", ctx().forIndex("email-eq"));
        Fieldseal readonly = builder(new Fixtures.SpyProvider()).readMode(ReadMode.READONLY)
                .armProvisionalSuites(false).indexes(List.of(email().build())).build();
        assertArrayEquals(expected, readonly.blindIndex("ada@example.com",
                ctx().forIndex("email-eq")));
        assertArrayEquals(armed.unindexableMarker(ctx().forIndex("email-eq")),
                readonly.unindexableMarker(ctx().forIndex("email-eq")));
    }

    @Test
    void bucketReturnsTheMarkerForEveryRefusedForm() {
        Fieldseal fs = client(new Fixtures.SpyProvider(), email()
                .onUnindexable(OnUnindexable.BUCKET).unindexableOverride(REVIEWED).build());
        FieldContext ix = ctx().forIndex("email-eq");
        byte[] marker = fs.unindexableMarker(ix);
        assertArrayEquals(marker, fs.blindIndex("a͸", ix), "unassigned");
        assertArrayEquals(marker, fs.blindIndex("a\uD800", ix), "lone surrogate");
        assertArrayEquals(marker, fs.blindIndex(new byte[] {'a', (byte) 0xC0}, ix),
                "malformed UTF-8");
        assertNotEquals(java.util.HexFormat.of().formatHex(marker),
                java.util.HexFormat.of().formatHex(fs.blindIndex("a", ix)));
    }

    /** docs/09/7.1/lone-surrogate-refusal, through the public text path (docs/27 §6.5). */
    @Test
    void twoLoneSurrogatesAreRefusedDistinguishably() {
        Fieldseal fs = client(new Fixtures.SpyProvider(), email().build());
        FieldContext ix = ctx().forIndex("email-eq");
        String high = assertThrows(InvalidArgumentError.class,
                () -> fs.blindIndex("a\uD800b", ix)).getMessage();
        String low = assertThrows(InvalidArgumentError.class,
                () -> fs.blindIndex("a\uDC00b", ix)).getMessage();
        assertNotEquals(high, low);
        assertTrue(high.contains("U+D800") && low.contains("U+DC00"), high + " / " + low);
    }

    /** Each normalizer derives, and indexes on one column are keyed apart (spec §7.2). */
    @Test
    void indexesOnOneColumnDeriveUnderTheirOwnKeys() {
        Fieldseal fs = client(new Fixtures.SpyProvider(), email().build(),
                email().indexId("raw").normalize(Normalizer.IDENTITY).build(),
                email().indexId("digits").normalize(Normalizer.DIGITS_ONLY_V1).build());
        String v = "12345";
        byte[] a = fs.blindIndex(v, ctx().forIndex("email-eq"));
        byte[] b = fs.blindIndex(v, ctx().forIndex("raw"));
        byte[] c = fs.blindIndex(v, ctx().forIndex("digits"));
        assertTrue(!java.util.Arrays.equals(a, b) || !java.util.Arrays.equals(b, c),
                "three keys over one normalized value");
        assertArrayEquals(c, fs.blindIndex("1-2-3-4-5", ctx().forIndex("digits")));
        assertArrayEquals(b, fs.blindIndex(v.getBytes(StandardCharsets.US_ASCII),
                ctx().forIndex("raw")));
    }

    @Test
    void theStaticHelpers() {
        assertEquals(new Unassigned(0x0378, 2),
                Fieldseal.firstUnassigned("😀a͸").orElseThrow());
        assertTrue(Fieldseal.firstUnassigned("ada").isEmpty());
        assertEquals(dev.fieldseal.core.internal.blindindex.Normalizers.UNICODE_VERSION,
                Fieldseal.UNICODE_VERSION, "one pin, not two");
        assertArrayEquals("ada".getBytes(StandardCharsets.US_ASCII),
                Normalizer.NFC_CASEFOLD_V1.normalize("ADA"));
        assertThrows(InvalidArgumentError.class, () -> Normalizer.NFC_CASEFOLD_V1.normalize("͸"));
    }

    // --- warm --------------------------------------------------------------------------------------

    @Test
    void warmRequestsTheIndexRoleForEveryIndexOnTheColumn() {
        List<KeyRequest> seen = new ArrayList<>();
        Fixtures.SpyProvider p = new Fixtures.SpyProvider() {
            @Override
            public java.util.concurrent.CompletableFuture<Void> warm(
                    java.util.Collection<KeyRequest> requests) {
                seen.addAll(requests);
                return java.util.concurrent.CompletableFuture.completedFuture(null);
            }
        };
        Fieldseal fs = client(p, email().build(), email().indexId("raw")
                .normalize(Normalizer.IDENTITY).build(),
                IndexDeclaration.builder(TABLE, Fixtures.bytes(16, 0x33)).idf(Idf.HMAC_SHA512)
                        .normalize(Normalizer.IDENTITY).truncateBits(15)
                        .projectedPopulation(100_000).build());
        fs.warm(List.of(ctx())).join();
        assertEquals(List.of("encrypt", "index:email-eq", "index:raw"),
                seen.stream().map(KeyRequest::purpose).toList(),
                "the DEK, then this column's two indexes, not the other column's");
    }
}
