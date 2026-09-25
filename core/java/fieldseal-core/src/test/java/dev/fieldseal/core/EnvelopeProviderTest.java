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

    @Test
    void anUnboundEnvelopeProviderServesNothing() {
        var unbound = KeyProviders.envelope(kms, store);
        assertThrows(KeyUnavailableError.class, () -> unbound.encryptionKey(
                new dev.fieldseal.core.keyprovider.KeyRequest(Fixtures.TABLE, Fixtures.COLUMN,
                        null, null, "encrypt")));
    }
}
