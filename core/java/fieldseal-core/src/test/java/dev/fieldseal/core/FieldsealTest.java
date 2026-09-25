package dev.fieldseal.core;

import static dev.fieldseal.core.Fixtures.builder;
import static dev.fieldseal.core.Fixtures.ctx;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.CommitmentInvalidError;
import dev.fieldseal.core.errors.ConfigurationError;
import dev.fieldseal.core.errors.FieldsealError;
import dev.fieldseal.core.errors.KeyUnavailableError;
import dev.fieldseal.core.errors.NotCiphertextError;
import dev.fieldseal.core.errors.SuiteNotAllowedError;
import dev.fieldseal.core.errors.SuiteProvisionalError;
import dev.fieldseal.core.errors.TagInvalidError;
import dev.fieldseal.core.internal.envelope.SyntheticOperand;
import dev.fieldseal.core.internal.registry.Registry;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The client end to end: round trips, read modes, configuration, arming and warnings. */
class FieldsealTest {

    private static final byte[] PT = "123-45-6789".getBytes(StandardCharsets.US_ASCII);

    @Test
    void roundTripsWithEachShippedLocalProvider() {
        for (var p : List.of(KeyProviders.staticKeys(Fixtures.DEK, Fixtures.INDEX_KEY,
                Fixtures.KEY_ID), KeyProviders.derived(Fixtures.bytes(32, 9)))) {
            Fieldseal fs = builder(p).build();
            byte[] env = fs.encrypt(PT, ctx());
            assertEquals(PT.length + 111, env.length);
            assertTrue(fs.isCiphertext(env));
            assertArrayEquals(PT, fs.decrypt(env, ctx()));
            byte[] again = fs.encrypt(PT, ctx());
            assertNotEquals(java.util.HexFormat.of().formatHex(env),
                    java.util.HexFormat.of().formatHex(again), "fresh seed and nonce per write");
        }
    }

    @Test
    void rotateWritesAFreshEnvelopeOfTheSamePlaintext() {
        Fieldseal fs = builder(new Fixtures.SpyProvider()).build();
        byte[] env = fs.encrypt(PT, ctx());
        byte[] rotated = fs.rotate(env, ctx());
        assertFalse(java.util.Arrays.equals(env, rotated));
        assertArrayEquals(PT, fs.decrypt(rotated, ctx()));
    }

    @Test
    void aDifferentContextFailsTheCommitment() {
        Fieldseal fs = builder(new Fixtures.SpyProvider()).build();
        byte[] env = fs.encrypt(PT, ctx());
        for (FieldContext other : List.of(ctx().withTenant(new byte[0]), ctx().withTenant(null),
                ctx().withRow(new byte[] {1}), FieldContext.of(Fixtures.COLUMN, Fixtures.TABLE)
                        .withTenant(Fixtures.TENANT))) {
            assertThrows(CommitmentInvalidError.class, () -> fs.decrypt(env, other), "" + other);
        }
    }

    @Test
    void aFlippedCiphertextBitIsTagInvalid() {
        Fieldseal fs = builder(new Fixtures.SpyProvider()).build();
        byte[] env = fs.encrypt(PT, ctx());
        env[63] ^= 1;
        assertThrows(TagInvalidError.class, () -> fs.decrypt(env, ctx()));
    }

    @Test
    void readModesOnNonEnvelopeInput() {
        byte[] plain = "not an envelope".getBytes(StandardCharsets.US_ASCII);
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        assertThrows(NotCiphertextError.class, () -> builder(p).build().decrypt(plain, ctx()));
        for (ReadMode m : List.of(ReadMode.PERMISSIVE, ReadMode.READONLY)) {
            Fieldseal fs = builder(p).readMode(m).build();
            assertSame(plain, fs.decrypt(plain, ctx()), m + " returns the input as-is");
            if (m != ReadMode.READONLY) {
                assertThrows(NotCiphertextError.class, () -> fs.rotate(plain, ctx()), m + "");
            }
        }
    }

    @Test
    void readonlyDecryptsWhatAnotherClientWrote() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        byte[] env = builder(p).build().encrypt(PT, ctx());
        assertArrayEquals(PT, builder(p).readMode(ReadMode.READONLY).build().decrypt(env, ctx()));
    }

    /** decrypt needs no arming (spec §4.8): an unarmed client reads what an armed one wrote. */
    @Test
    void anUnarmedClientDecryptsButDoesNotWrite() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        byte[] env = builder(p).build().encrypt(PT, ctx());
        Fieldseal unarmed = builder(p).armProvisionalSuites(false).build();
        assertArrayEquals(PT, unarmed.decrypt(env, ctx()));
        assertThrows(SuiteProvisionalError.class, () -> unarmed.encrypt(PT, ctx()));
        assertThrows(SuiteProvisionalError.class, () -> unarmed.rotate(env, ctx()));
    }

    /** spec §4.8: exactly "1" arms; either mechanism is enough; both are read at build. */
    @Test
    void armingIsByteExactAndEitherMechanismArms() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        for (String v : new String[] {"1"}) {
            assertTrue(builder(p).armProvisionalSuites(false)
                    .environment(Map.of(SuiteProvisionalError.ARMING_VARIABLE, v)::get).build()
                    .provisionalArmed());
        }
        for (String v : new String[] {"", "0", "true", "yes", "TRUE", " 1", "1 ", "1\n", "01"}) {
            assertFalse(builder(p).armProvisionalSuites(false)
                    .environment(Map.of(SuiteProvisionalError.ARMING_VARIABLE, v)::get).build()
                    .provisionalArmed(), "'" + v + "' must not arm");
        }
        assertTrue(builder(p).armProvisionalSuites(true)
                .environment(Map.of(SuiteProvisionalError.ARMING_VARIABLE, "0")::get).build()
                .provisionalArmed(), "the in-code form arms whatever the variable says");
    }

    @Test
    void theProvisionalMessageNamesTheSuiteAndBothMechanisms() {
        Fieldseal fs = builder(new Fixtures.SpyProvider()).armProvisionalSuites(false).build();
        String m = assertThrows(SuiteProvisionalError.class, () -> fs.encrypt(PT, ctx()))
                .getMessage();
        assertTrue(m.contains("0xFF01") && m.contains("FIELDSEAL_ARM_PROVISIONAL_SUITES=1")
                && m.contains(Fieldseal.IN_CODE_ARMING), m);
    }

    /** The unimplemented-registered-suite pin: 0xFF02 is refused at construction, naming G7. */
    @Test
    void ff02IsRefusedAtConstructionButItsEnvelopesAreRecognized() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        for (var b : List.of(builder(p).allowedSuites(Set.of(0xFF01, 0xFF02)),
                builder(p).allowedSuites(Set.of(0xFF02)).writeSuite(0xFF02))) {
            String m = assertThrows(ConfigurationError.class, b::build).getMessage();
            assertTrue(m.contains("0xFF02") && m.contains("G7"), m);
        }
        byte[] ff02 = SyntheticOperand.header(Registry.FF02);
        byte[] env = java.util.Arrays.copyOf(ff02, ff02.length + 16 + 32);
        Fieldseal fs = builder(p).build();
        assertTrue(fs.isCiphertext(env));
        assertThrows(SuiteNotAllowedError.class, () -> fs.decrypt(env, ctx()));
        assertEquals(List.of(), p.calls, "refused before any key lookup");
    }

    @Test
    void constructionRefusals() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        List<Fieldseal.Builder> bad = List.of(
                builder(null),
                builder(p).allowedSuites(Set.of()),
                builder(p).allowedSuites(null),
                builder(p).allowedSuites(Set.of(0x0001)),
                builder(p).writeSuite(0x0001),
                builder(p).readMode(null),
                builder(p).cachePolicy(new CachePolicy(java.time.Duration.ofMinutes(1), 10, 10)),
                builder(KeyProviders.envelope(new Wrappers.Identity(), r -> List.of())));
        for (Fieldseal.Builder b : bad) {
            assertThrows(ConfigurationError.class, b::build);
        }
        assertThrows(ConfigurationError.class, () -> Fieldseal.builder().keyProvider(p)
                .allowedSuites(Set.of(0xFF01)).build(), "writeSuite has no default");
    }

    @Test
    void theShippedProvidersRefuseBadKeys() {
        assertThrows(ConfigurationError.class,
                () -> KeyProviders.staticKeys(Fixtures.DEK, Fixtures.DEK, Fixtures.KEY_ID));
        assertThrows(ConfigurationError.class,
                () -> KeyProviders.staticKeys(Fixtures.DEK, Fixtures.INDEX_KEY, new byte[15]));
        assertThrows(ConfigurationError.class,
                () -> KeyProviders.staticKeys(new byte[0], Fixtures.INDEX_KEY, Fixtures.KEY_ID));
        assertThrows(ConfigurationError.class, () -> KeyProviders.derived(new byte[31]));
    }

    @Test
    void theDerivedProviderSeparatesTenantsAndRoles() {
        var p = KeyProviders.derived(Fixtures.bytes(32, 9));
        var dekA = p.encryptionKey(new dev.fieldseal.core.keyprovider.KeyRequest(Fixtures.TABLE,
                Fixtures.COLUMN, new byte[] {1}, null, "encrypt"));
        var dekB = p.encryptionKey(new dev.fieldseal.core.keyprovider.KeyRequest(Fixtures.TABLE,
                Fixtures.COLUMN, new byte[] {2}, null, "encrypt"));
        var idxA = p.encryptionKey(new dev.fieldseal.core.keyprovider.KeyRequest(Fixtures.TABLE,
                Fixtures.COLUMN, new byte[] {1}, null, "index:exact"));
        var none = p.encryptionKey(new dev.fieldseal.core.keyprovider.KeyRequest(Fixtures.TABLE,
                Fixtures.COLUMN, null, null, "encrypt"));
        var empty = p.encryptionKey(new dev.fieldseal.core.keyprovider.KeyRequest(Fixtures.TABLE,
                Fixtures.COLUMN, new byte[0], null, "encrypt"));
        assertFalse(java.util.Arrays.equals(dekA.key(), dekB.key()));
        assertFalse(java.util.Arrays.equals(dekA.key(), idxA.key()), "index key is not the DEK");
        assertFalse(java.util.Arrays.equals(none.key(), empty.key()), "absent is not empty");
        Fieldseal fs = builder(p).build();
        byte[] env = fs.encrypt(PT, ctx());
        assertThrows(KeyUnavailableError.class,
                () -> fs.decrypt(env, ctx().withTenant(new byte[] {9})), "another tenant's key_id");
    }

    @Test
    void warningsGoToTheHook() {
        List<String> warnings = new ArrayList<>();
        var st = KeyProviders.staticKeys(Fixtures.DEK, Fixtures.INDEX_KEY, Fixtures.KEY_ID);
        builder(st).onWarning(warnings::add).build();
        assertEquals(1, warnings.size(), "static provider outside test configuration");
        warnings.clear();
        builder(st).onWarning(warnings::add)
                .environment(Map.of(Fieldseal.TEST_MODE_VARIABLE, "1")::get).build();
        assertEquals(0, warnings.size(), "FIELDSEAL_TEST_MODE=1 is test configuration");
        builder(new Fixtures.SpyProvider()).readMode(ReadMode.PERMISSIVE)
                .onWarning(warnings::add).build();
        builder(new Fixtures.SpyProvider()).readMode(ReadMode.READONLY)
                .onWarning(warnings::add).build();
        assertEquals(2, warnings.size(), "permissive and readonly warn (spec §10.3)");
    }

    /** docs/09 §2: resolved values, and a collection the caller cannot use to alter the client. */
    @Test
    void reflectionIsResolvedAndImmutable() {
        Fieldseal fs = builder(new Fixtures.SpyProvider()).build();
        assertEquals(ReadMode.STRICT, fs.readMode(), "the default, filled in");
        assertEquals(0xFF01, fs.writeSuite());
        assertEquals(Set.of(0xFF01), fs.allowedSuites());
        assertTrue(fs.provisionalArmed());
        assertThrows(UnsupportedOperationException.class, () -> fs.allowedSuites().add(0xFF02));
    }

    @Test
    void theContextCopiesItsArrays() {
        byte[] t = Fixtures.TABLE.clone();
        FieldContext c = FieldContext.of(t, Fixtures.COLUMN);
        t[0] ^= 1;
        c.tableUuid()[1] ^= 1;
        assertArrayEquals(Fixtures.TABLE, c.tableUuid());
        assertThrows(FieldsealError.class, () -> FieldContext.of(new byte[15], Fixtures.COLUMN));
    }

    @Test
    void providerFailuresAreKeyUnavailableWithTheCause() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        Fieldseal fs = builder(p).build();
        byte[] env = fs.encrypt(PT, ctx());
        IllegalStateException boom = new IllegalStateException("kms down");
        p.failWith = boom;
        assertSame(boom, assertThrows(KeyUnavailableError.class, () -> fs.encrypt(PT, ctx()))
                .getCause());
        assertSame(boom, assertThrows(KeyUnavailableError.class, () -> fs.decrypt(env, ctx()))
                .getCause());
        assertInstanceOf(KeyUnavailableError.class, assertThrows(KeyUnavailableError.class,
                () -> builder(new BadKeyIdProvider()).build().encrypt(PT, ctx())));
    }

    private static final class BadKeyIdProvider extends Fixtures.SpyProvider {
        @Override
        public dev.fieldseal.core.keyprovider.KeyMaterial encryptionKey(
                dev.fieldseal.core.keyprovider.KeyRequest request) {
            return new dev.fieldseal.core.keyprovider.KeyMaterial(dek, new byte[15]);
        }
    }
}
