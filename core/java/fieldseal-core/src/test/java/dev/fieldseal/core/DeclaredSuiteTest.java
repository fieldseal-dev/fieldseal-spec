package dev.fieldseal.core;

import static dev.fieldseal.core.Fixtures.COLUMN;
import static dev.fieldseal.core.Fixtures.TABLE;
import static dev.fieldseal.core.Fixtures.TENANT;
import static dev.fieldseal.core.Fixtures.builder;
import static dev.fieldseal.core.Fixtures.ctx;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.ConfigurationError;
import dev.fieldseal.core.internal.blindindex.Idf;
import dev.fieldseal.core.internal.context.CanonicalContext;
import dev.fieldseal.core.internal.context.ContextFields;
import dev.fieldseal.core.internal.kdf.Hkdf;
import dev.fieldseal.core.internal.kdf.KeyDerivation;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * spec §7.2 (#213): an index declaration names its own suite, and the index context's {@code
 * suite_id} is that suite, never the write suite. The key provider's {@code KeyRequest} carries no
 * suite (it does not choose a key), so what a derivation's context carried is shown by comparing
 * the result with an independent derivation under each suite.
 */
class DeclaredSuiteTest {

    private static final String PLAINTEXT = "alice@example.com";

    private static Fieldseal client(Fixtures.SpyProvider p, int declared) {
        return builder(p).indexes(List.of(Fixtures.emailIndex().suiteId(declared).build()))
                .build();
    }

    /** The index bytes under {@code suite}'s context, from the spy provider's index key. */
    private static byte[] expected(int suite, String text) {
        byte[] key = KeyDerivation.indexKey(Fixtures.INDEX_KEY, CanonicalContext.encodeForIndexKey(
                new ContextFields(suite, TABLE, COLUMN, TENANT, null, "index:email-eq")));
        return Idf.blindIndex(new Idf.Params.HmacSha512(), key,
                text.getBytes(StandardCharsets.UTF_8), 15, Hkdf::derive);
    }

    @Test
    void aDeclarationNamingNoSuiteIsRefusedAndNotDefaultedFromTheWriteSuite() {
        // Fixtures.emailIndex() sets the suite, so build one without it. Absent is representable
        // (a null Integer), and it is refused at validation, not at compile time.
        IndexDeclaration d = IndexDeclaration.builder(TABLE, COLUMN).indexId("email-eq")
                .idf(IndexDeclaration.Idf.HMAC_SHA512)
                .normalize(IndexDeclaration.Normalizer.NFC_CASEFOLD_V1).truncateBits(15)
                .projectedPopulation(100_000).build();
        assertEquals(null, d.suiteId());
        ConfigurationError e = assertThrows(ConfigurationError.class,
                () -> Fieldseal.validateIndexDeclaration(d));
        assertTrue(e.getMessage().contains("suiteId is required"), e.getMessage());
        assertThrows(ConfigurationError.class,
                () -> builder(new Fixtures.SpyProvider()).indexes(List.of(d)).build());
    }

    @Test
    void anUnregisteredSuiteIsRefused() {
        for (int bad : new int[] {0x0001, 0x0002, 0, 0xFFFF}) {
            ConfigurationError e = assertThrows(ConfigurationError.class,
                    () -> Fieldseal.validateIndexDeclaration(
                            Fixtures.emailIndex().suiteId(bad).build()), String.valueOf(bad));
            assertTrue(e.getMessage().contains("not a registered suite"), e.getMessage());
            assertThrows(ConfigurationError.class,
                    () -> client(new Fixtures.SpyProvider(), bad));
        }
        assertThrows(ConfigurationError.class, () -> Fieldseal.validateIndexDeclaration(
                Fixtures.emailIndex().suiteId(-1).build()));
    }

    @Test
    void ff02IsAcceptedOnAnFf01OnlyClientAndDerivesDifferentBytes() {
        Fieldseal ff01 = client(new Fixtures.SpyProvider(), 0xFF01);
        Fieldseal ff02 = client(new Fixtures.SpyProvider(), 0xFF02);
        assertEquals(0xFF01, ff02.writeSuite());
        assertEquals(Set.of(0xFF01), ff02.allowedSuites());
        FieldContext ix = ctx().forIndex("email-eq");
        byte[] a = ff01.blindIndex(PLAINTEXT, ix);
        byte[] b = ff02.blindIndex(PLAINTEXT, ix);
        assertNotEquals(HexFormat.of().formatHex(a), HexFormat.of().formatHex(b));
        assertArrayEquals(expected(0xFF01, PLAINTEXT), a);
        assertArrayEquals(expected(0xFF02, PLAINTEXT), b);
        assertArrayEquals(b, ff02.blindIndex(PLAINTEXT.getBytes(StandardCharsets.UTF_8), ix),
                "the bytes path too");
    }

    @Test
    void theMarkerAndBlindIndexCarryTheDeclaredSuite() {
        Fieldseal fs = client(new Fixtures.SpyProvider(), 0xFF02);
        FieldContext ix = ctx().forIndex("email-eq");
        byte[] key = KeyDerivation.indexKey(Fixtures.INDEX_KEY,
                CanonicalContext.encodeForIndexKey(new ContextFields(0xFF02, TABLE, COLUMN,
                        TENANT, null, "index:email-eq")));
        byte[] marker = Idf.blindIndex(new Idf.Params.HmacSha512(), key,
                dev.fieldseal.core.internal.blindindex.Normalizers.reservedPreimage(), 15,
                Hkdf::derive);
        assertArrayEquals(marker, fs.unindexableMarker(ix));
        assertFalse(java.util.Arrays.equals(client(new Fixtures.SpyProvider(), 0xFF01)
                .unindexableMarker(ix), marker));
    }

    @Test
    void theIndexPathAsksTheProviderForTheSameKeyWhateverTheDeclaredSuite() {
        Fixtures.SpyProvider a = new Fixtures.SpyProvider();
        Fixtures.SpyProvider b = new Fixtures.SpyProvider();
        client(a, 0xFF01).blindIndex(PLAINTEXT, ctx().forIndex("email-eq"));
        client(b, 0xFF02).blindIndex(PLAINTEXT, ctx().forIndex("email-eq"));
        assertEquals(a.calls, b.calls, "a KeyRequest holds no suite, so no request depends on it");
        client(b, 0xFF02).warm(List.of(ctx())).join();
    }

    @Test
    void theReflectedDeclarationCarriesTheSuiteAndEqualityCoversIt() {
        Fieldseal fs = client(new Fixtures.SpyProvider(), 0xFF02);
        ValidatedIndex v = fs.indexes().get(Fieldseal.indexRegistryKey(TABLE, COLUMN, "email-eq"));
        assertEquals(0xFF02, v.suiteId());
        ValidatedIndex v1 = Fieldseal.validateIndexDeclaration(
                Fixtures.emailIndex().suiteId(0xFF01).build());
        assertEquals(v, Fieldseal.validateIndexDeclaration(
                Fixtures.emailIndex().suiteId(0xFF02).build()));
        assertNotEquals(v1, v, "declarations differing only in suite are different indexes");
        assertNotEquals(v1.hashCode(), v.hashCode());
        assertNotEquals(Fixtures.emailIndex().suiteId(0xFF01).build(),
                Fixtures.emailIndex().suiteId(0xFF02).build());
        assertTrue(v.toString().contains("0xFF02"), v.toString());
    }
}
