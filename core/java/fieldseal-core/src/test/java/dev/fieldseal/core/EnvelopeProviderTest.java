package dev.fieldseal.core;

import static dev.fieldseal.core.Fixtures.builder;
import static dev.fieldseal.core.Fixtures.ctx;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.KeyUnavailableError;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/**
 * The envelope provider bound to a client's cache (docs/09 §8.2): the value path reads the cache
 * only, a miss fails closed, and the spec §5.5 limits evict.
 */
class EnvelopeProviderTest {

    private static final byte[] PT = {1, 2, 3};

    private final Wrappers.Identity kms = new Wrappers.Identity();
    private final Wrappers.Store store = new Wrappers.Store(kms);
    private final AtomicLong now = new AtomicLong();

    private Fieldseal client(long maxUses, Duration maxAge) {
        return builder(KeyProviders.envelope(kms, store))
                .cachePolicy(new CachePolicy(maxAge, maxUses, 100)).nanoClock(now::get).build();
    }

    @Test
    void failsClosedUntilWarmedAndNeverTouchesTheKmsOnTheValuePath() {
        Fieldseal fs = client(1000, Duration.ofMinutes(5));
        assertThrows(KeyUnavailableError.class, () -> fs.encrypt(PT, ctx()));
        fs.warm(List.of(ctx())).join();
        int lookups = store.lookups.get();
        int unwraps = kms.unwraps.get();
        assertEquals(2, unwraps, "both valid versions unwrapped");
        for (int i = 0; i < 10; i++) {
            assertArrayEquals(PT, fs.decrypt(fs.encrypt(PT, ctx()), ctx()));
        }
        assertEquals(lookups, store.lookups.get(), "the value path called the key store");
        assertEquals(unwraps, kms.unwraps.get(), "the value path called the KMS");
    }

    /** Writes use the active version; reads find an older valid one by the envelope's key_id. */
    @Test
    void writesUseTheActiveVersionAndReadsFindOlderOnes() {
        Fieldseal fs = client(1000, Duration.ofMinutes(5));
        fs.warm(List.of(ctx())).join();
        byte[] env = fs.encrypt(PT, ctx());
        assertArrayEquals(store.v1Id, java.util.Arrays.copyOfRange(env, 3, 19));
        Fieldseal v0Writer = builder(KeyProviders.staticKeys(store.v0, Fixtures.INDEX_KEY,
                store.v0Id)).build();
        byte[] old = v0Writer.encrypt(PT, ctx());
        assertArrayEquals(PT, fs.decrypt(old, ctx()));
    }

    /** spec §5.5 max-uses counts encryptions only (docs/09 §8.1), and the last one evicts. */
    @Test
    void maxUsesCountsEncryptionsOnly() {
        Fieldseal fs = client(2, Duration.ofMinutes(5));
        fs.warm(List.of(ctx())).join();
        byte[] env = fs.encrypt(PT, ctx());
        for (int i = 0; i < 5; i++) {
            fs.decrypt(env, ctx());
        }
        fs.encrypt(PT, ctx());
        assertThrows(KeyUnavailableError.class, () -> fs.encrypt(PT, ctx()), "third use");
        fs.warm(List.of(ctx())).join();
        fs.encrypt(PT, ctx());
    }

    @Test
    void maxAgeExpires() {
        Fieldseal fs = client(1000, Duration.ofSeconds(10));
        fs.warm(List.of(ctx())).join();
        byte[] env = fs.encrypt(PT, ctx());
        now.addAndGet(Duration.ofSeconds(10).toNanos());
        fs.encrypt(PT, ctx());
        now.addAndGet(1);
        assertThrows(KeyUnavailableError.class, () -> fs.encrypt(PT, ctx()));
        assertThrows(KeyUnavailableError.class, () -> fs.decrypt(env, ctx()));
    }

    /** docs/09 §3.6: a failed warm is reported and poisons nothing. */
    @Test
    void aFailedWarmIsReportedAndPoisonsNothing() {
        Fieldseal fs = client(1000, Duration.ofMinutes(5));
        kms.failWith = new IllegalStateException("kms down");
        CompletionException e = assertThrows(CompletionException.class,
                () -> fs.warm(List.of(ctx())).join());
        assertTrue(e.getCause() instanceof IllegalStateException, "" + e.getCause());
        assertThrows(KeyUnavailableError.class, () -> fs.encrypt(PT, ctx()));
        kms.failWith = null;
        fs.warm(List.of(ctx())).join();
        fs.encrypt(PT, ctx());
    }

    /** Review of #190: a version the store stops listing must stop decrypting. */
    @Test
    void aVersionTheStoreDropsStopsDecryptingAtTheNextWarm() {
        Fieldseal fs = client(1000, Duration.ofMinutes(5));
        fs.warm(List.of(ctx())).join();
        byte[] old = builder(KeyProviders.staticKeys(store.v0, Fixtures.INDEX_KEY, store.v0Id))
                .build().encrypt(PT, ctx());
        assertArrayEquals(PT, fs.decrypt(old, ctx()));
        store.deks = List.of(store.version(store.v1Id, store.v1));
        fs.warm(List.of(ctx())).join();
        // v0 is gone. The slot's remaining valid version is still a candidate (docs/09 §8.1: all
        // currently-valid versions), so the refusal is its commitment failing, not an empty list.
        assertThrows(dev.fieldseal.core.errors.CommitmentInvalidError.class,
                () -> fs.decrypt(old, ctx()));
        store.deks = List.of();
        fs.warm(List.of(ctx())).join();
        assertThrows(KeyUnavailableError.class, () -> fs.encrypt(PT, ctx()), "slot emptied");
    }

    /** Review of #190: a failed warm must not change which key writes go out under. */
    @Test
    void aFailedWarmKeepsTheActiveVersion() {
        Fieldseal fs = client(1000, Duration.ofMinutes(5));
        fs.warm(List.of(ctx())).join();
        var v2 = store.version(store.v2Id, store.v2);
        var v1 = store.version(store.v1Id, store.v1);
        store.deks = List.of(v2, v1);
        kms.failOnBlob = v1.blob();
        assertThrows(CompletionException.class, () -> fs.warm(List.of(ctx())).join());
        byte[] env = fs.encrypt(PT, ctx());
        assertArrayEquals(store.v1Id, java.util.Arrays.copyOfRange(env, 3, 19),
                "a failed warm switched writes to v2");
        kms.failOnBlob = null;
        fs.warm(List.of(ctx())).join();
        assertArrayEquals(store.v2Id,
                java.util.Arrays.copyOfRange(fs.encrypt(PT, ctx()), 3, 19));
    }

    /** Review of #190: a warm before expiry refreshes, so a schedule shorter than maxAge works. */
    @Test
    void aWarmBeforeExpiryRestartsTheAgeAndTheBudget() {
        Fieldseal fs = client(2, Duration.ofSeconds(10));
        fs.warm(List.of(ctx())).join();
        fs.encrypt(PT, ctx());
        now.addAndGet(Duration.ofSeconds(8).toNanos());
        fs.warm(List.of(ctx())).join();
        now.addAndGet(Duration.ofSeconds(8).toNanos());
        fs.encrypt(PT, ctx());
        fs.encrypt(PT, ctx());
    }

    /** Review of #190: warm reports every failure through its future and throws none. */
    @Test
    void warmNeverThrows() {
        Fieldseal fs = client(1000, Duration.ofMinutes(5));
        assertThrows(CompletionException.class, () -> fs.warm(null).join());
        java.util.List<FieldContext> withNull = new java.util.ArrayList<>();
        withNull.add(null);
        assertThrows(CompletionException.class, () -> fs.warm(withNull).join());
        fs.warm(List.of()).join();
    }

    @Test
    void anUnboundEnvelopeProviderServesNothing() {
        var unbound = KeyProviders.envelope(kms, store);
        assertThrows(KeyUnavailableError.class, () -> unbound.encryptionKey(
                new dev.fieldseal.core.keyprovider.KeyRequest(Fixtures.TABLE, Fixtures.COLUMN,
                        null, null, "encrypt")));
    }
}
