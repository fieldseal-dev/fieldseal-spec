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
    private static final CachePolicy POLICY = new CachePolicy(Duration.ofMinutes(5), 1000, 100);

    private final Wrappers.Identity kms = new Wrappers.Identity();
    private final Wrappers.Store store = new Wrappers.Store(kms);
    private final AtomicLong now = new AtomicLong();

    private Fieldseal client(long maxUses, Duration maxAge) {
        return builder(KeyProviders.envelopeWithClock(kms, store,
                new CachePolicy(maxAge, maxUses, 100), EnvelopeProvider.WARM_POOL, now::get))
                .build();
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

    /**
     * #192 item 3: the provider {@code KeyProviders.envelope} returns is bound to its own cache
     * when it is made, so called directly it works. It used to refuse every call until a client
     * bound a copy of it.
     */
    @Test
    void theEnvelopeProviderWorksWhenCalledDirectly() {
        var keys = KeyProviders.envelope(kms, store, POLICY);
        var request = new dev.fieldseal.core.keyprovider.KeyRequest(Fixtures.TABLE,
                Fixtures.COLUMN, null, null, "encrypt");
        assertThrows(KeyUnavailableError.class, () -> keys.encryptionKey(request));
        keys.warm(List.of(request)).join();
        assertArrayEquals(store.v1Id, keys.encryptionKey(request).keyId());
    }

    /**
     * #192 item 3: clients built from one provider share its cache, so a key is unwrapped once
     * however many clients use it. Each used to bind a cache of its own.
     */
    @Test
    void clientsBuiltFromOneProviderShareItsCache() {
        var keys = KeyProviders.envelope(kms, store, POLICY);
        Fieldseal a = builder(keys).build();
        Fieldseal b = builder(keys).build();
        a.warm(List.of(ctx())).join();
        int unwraps = kms.unwraps.get();
        assertArrayEquals(PT, a.decrypt(b.encrypt(PT, ctx()), ctx()), "b did not see a's warm");
        assertEquals(unwraps, kms.unwraps.get());
    }

    private static FieldContext tenant(String t) {
        return FieldContext.of(Fixtures.TABLE, Fixtures.COLUMN)
                .withTenant(t.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    /** Review of #201: a key's max-uses budget counts every client's encryptions. */
    @Test
    void clientsSharingAProviderShareEachKeysUseBudget() {
        var keys = KeyProviders.envelope(kms, store,
                new CachePolicy(Duration.ofMinutes(5), 1, 100));
        Fieldseal a = builder(keys).build();
        Fieldseal b = builder(keys).build();
        a.warm(List.of(ctx())).join();
        a.encrypt(PT, ctx());
        assertThrows(KeyUnavailableError.class, () -> b.encrypt(PT, ctx()), "a spent it");
    }

    /** Review of #201: a client built with a provider of its own does not see another's warm. */
    @Test
    void aClientWithItsOwnProviderSeesNoOtherWarm() {
        Fieldseal a = builder(KeyProviders.envelope(kms, store, POLICY)).build();
        Fieldseal b = builder(KeyProviders.envelope(kms, store, POLICY)).build();
        a.warm(List.of(ctx())).join();
        assertThrows(KeyUnavailableError.class, () -> b.encrypt(PT, ctx()));
    }

    /**
     * Review of #201: in a shared cache, one client's warms can evict another's keys at capacity,
     * and the refusal says so rather than blaming age or uses.
     */
    @Test
    void anotherClientsWarmsCanEvictAKeyAndTheRefusalSaysSo() {
        var keys = KeyProviders.envelope(kms, store,
                new CachePolicy(Duration.ofMinutes(5), 1000, 2));
        Fieldseal a = builder(keys).build();
        Fieldseal b = builder(keys).build();
        a.warm(List.of(tenant("t1"))).join();
        a.encrypt(PT, tenant("t1"));
        b.warm(List.of(tenant("t2"))).join();
        var e = assertThrows(KeyUnavailableError.class, () -> a.encrypt(PT, tenant("t1")));
        assertTrue(String.valueOf(e.getMessage()).contains("evicted"), e.getMessage());
    }

    /** Review of #201: called directly, warm fails its future for an Error or a null collection. */
    @Test
    void aDirectWarmNeverThrows() {
        var request = new dev.fieldseal.core.keyprovider.KeyRequest(Fixtures.TABLE,
                Fixtures.COLUMN, null, null, "encrypt");
        var erroring = KeyProviders.envelope(kms, store, POLICY, r -> {
            throw new StackOverflowError("simulated");
        });
        var f = erroring.warm(List.of(request));
        CompletionException e = assertThrows(CompletionException.class, f::join);
        assertTrue(e.getCause() instanceof StackOverflowError, "" + e.getCause());
        var keys = KeyProviders.envelope(kms, store, POLICY);
        assertThrows(CompletionException.class, () -> keys.warm(null).join());
    }

    /** Review of #201: the seam every envelope provider is built through checks what it needs. */
    @Test
    void theEnvelopeSeamRefusesANullExecutorOrClock() {
        assertThrows(dev.fieldseal.core.errors.ConfigurationError.class,
                () -> KeyProviders.envelopeWithClock(kms, store, POLICY, null, now::get));
        assertThrows(dev.fieldseal.core.errors.ConfigurationError.class,
                () -> KeyProviders.envelopeWithClock(kms, store, POLICY,
                        EnvelopeProvider.WARM_POOL, null));
    }

    @Test
    void theEnvelopeFactoryRefusesMissingParts() {
        List<org.junit.jupiter.api.function.Executable> bad = List.of(
                () -> KeyProviders.envelope(null, store, POLICY),
                () -> KeyProviders.envelope(kms, null, POLICY),
                () -> KeyProviders.envelope(kms, store, null),
                () -> KeyProviders.envelope(kms, store, POLICY, null));
        for (var call : bad) {
            assertThrows(dev.fieldseal.core.errors.ConfigurationError.class, call);
        }
    }

    /** #192: {@code warm} runs its key-store and KMS calls on the executor it is given. */
    @Test
    void warmRunsOnTheGivenExecutor() {
        var tasks = new java.util.concurrent.atomic.AtomicInteger();
        Fieldseal fs = builder(KeyProviders.envelope(kms, store, POLICY, r -> {
            tasks.incrementAndGet();
            r.run();
        })).build();
        fs.warm(List.of(ctx())).join();
        assertEquals(1, tasks.get());
        assertEquals(1, store.lookups.get());
    }

    /**
     * #192: by default {@code warm} blocks on the KMS on a thread of the core's daemon pool, not
     * on the ForkJoin common pool, whose threads the application's other async work needs.
     */
    @Test
    void warmDefaultsToTheDaemonPoolNotTheCommonPool() {
        java.util.concurrent.atomic.AtomicReference<Thread> ran =
                new java.util.concurrent.atomic.AtomicReference<>();
        Fieldseal fs = builder(KeyProviders.envelope(kms, r -> {
            ran.set(Thread.currentThread());
            return store.keys(r);
        }, POLICY)).build();
        fs.warm(List.of(ctx())).join();
        Thread t = ran.get();
        assertTrue(!(t instanceof java.util.concurrent.ForkJoinWorkerThread), t.getName());
        assertTrue(t.isDaemon(), t.getName() + " would keep the JVM from exiting");
        assertTrue(t.getName().startsWith("fieldseal-warm"), t.getName());
    }

    /** An executor that refuses the task fails {@code warm}'s future; {@code warm} never throws. */
    @Test
    void aRejectingExecutorFailsTheFuture() {
        var keys = KeyProviders.envelope(kms, store, POLICY, r -> {
            throw new java.util.concurrent.RejectedExecutionException("full");
        });
        var viaClient = builder(keys).build().warm(List.of(ctx()));
        var direct = keys.warm(List.of(new dev.fieldseal.core.keyprovider.KeyRequest(
                Fixtures.TABLE, Fixtures.COLUMN, null, null, "encrypt")));
        for (var f : List.of(viaClient, direct)) {
            CompletionException e = assertThrows(CompletionException.class, f::join);
            assertTrue(e.getCause() instanceof java.util.concurrent.RejectedExecutionException,
                    "" + e.getCause());
        }
        assertEquals(0, store.lookups.get());
    }

    /**
     * Review of #199: the default pool is bounded, and every envelope provider shares its bound.
     * Two clients, each with a provider of its own, start twice the bound's worth of warms against a store that blocks; no more than the bound
     * are ever inside it at once.
     */
    @Test
    void theDefaultPoolIsBoundedAndSharedByEveryProvider() throws Exception {
        int bound = EnvelopeProvider.WARM_THREADS;
        var release = new java.util.concurrent.CountDownLatch(1);
        var inside = new java.util.concurrent.atomic.AtomicInteger();
        var peak = new java.util.concurrent.atomic.AtomicInteger();
        dev.fieldseal.core.keyprovider.WrappedKeyStore blocking = r -> {
            peak.accumulateAndGet(inside.incrementAndGet(), Math::max);
            try {
                release.await(5, java.util.concurrent.TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                inside.decrementAndGet();
            }
            return store.keys(r);
        };
        List<Fieldseal> clients = List.of(blockingClient(blocking), blockingClient(blocking));
        var warms = new java.util.ArrayList<java.util.concurrent.CompletableFuture<Void>>();
        try {
            for (int i = 0; i < 2 * bound; i++) {
                warms.add(clients.get(i % 2).warm(List.of(ctx())));
            }
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (inside.get() < bound && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            Thread.sleep(100);
            assertEquals(bound, peak.get(), "warms inside the store at once");
        } finally {
            release.countDown();
        }
        for (var w : warms) {
            w.get(5, java.util.concurrent.TimeUnit.SECONDS);
        }
    }

    /**
     * Review of #199: a warm thread is a daemon and does not inherit the creating thread's
     * inheritable thread-locals. A fresh pool, because the shared one's threads may predate the
     * thread-local this test sets.
     */
    @Test
    void theDefaultPoolsThreadsAreDaemonsAndInheritNoThreadLocals() throws Exception {
        var requestContext = new InheritableThreadLocal<String>();
        requestContext.set("request-scoped");
        try {
            var seen = new java.util.concurrent.CompletableFuture<Thread>();
            var value = new java.util.concurrent.atomic.AtomicReference<String>("unset");
            EnvelopeProvider.warmPool().execute(() -> {
                value.set(requestContext.get());
                seen.complete(Thread.currentThread());
            });
            Thread t = seen.get(5, java.util.concurrent.TimeUnit.SECONDS);
            assertTrue(t.isDaemon(), t.getName());
            assertEquals(null, value.get(), "the warm thread inherited the caller's context");
        } finally {
            requestContext.remove();
        }
    }

    private Fieldseal blockingClient(dev.fieldseal.core.keyprovider.WrappedKeyStore s) {
        return builder(KeyProviders.envelope(kms, s, POLICY)).build();
    }
}
