package dev.fieldseal.core.internal.cache;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.LongRange;
import org.junit.jupiter.api.Test;

/** spec §5.5 and docs/09 §8.3: the three limits, erasure on eviction, single-flight. */
class DekCacheTest {

    private static final DekCache.Slot SLOT = new DekCache.Slot("s", "t", DekCache.Role.DEK);
    private static final DekCache.Key K1 = new DekCache.Key(SLOT, "01");
    private static final DekCache.Key K2 = new DekCache.Key(SLOT, "02");
    private static final DekCache.Key OTHER =
            new DekCache.Key(new DekCache.Slot("s", "u", DekCache.Role.DEK), "01");
    private static final byte[] ID = new byte[16];

    private final AtomicLong now = new AtomicLong();

    private DekCache cache(long maxAge, long maxUses, int capacity) {
        return new DekCache(new DekCache.Limits(maxAge, maxUses, capacity), now::get);
    }

    private static byte[] key(int v) {
        byte[] k = new byte[32];
        java.util.Arrays.fill(k, (byte) v);
        return k;
    }

    @Test
    void maxUsesAllowsExactlyThatManyEncryptionsAndErasesOnTheLast() {
        DekCache c = cache(1_000, 3, 10);
        c.load(K1, ID, () -> key(7)).join();
        byte[] held = c.heldArray(K1);
        for (int i = 0; i < 3; i++) {
            assertArrayEquals(key(7), c.takeForEncrypt(K1).orElseThrow()[0]);
        }
        assertTrue(c.takeForEncrypt(K1).isEmpty());
        assertArrayEquals(new byte[32], held, "evicted key not erased");
        assertEquals(1, c.evictions(DekCache.Cause.USES));
    }

    /**
     * Ten reads, then the full encryption budget: if a read counted, the budget would be gone
     * before the second encryption.
     */
    @Test
    void readsDoNotCountAsUses() {
        DekCache c = cache(1_000, 2, 10);
        c.load(K1, ID, () -> key(7)).join();
        for (int i = 0; i < 10; i++) {
            assertEquals(1, c.candidates(SLOT).size());
        }
        assertTrue(c.takeForEncrypt(K1).isPresent(), "first encryption");
        assertTrue(c.takeForEncrypt(K1).isPresent(), "second encryption: reads spent the budget");
        assertTrue(c.takeForEncrypt(K1).isEmpty(), "third encryption");
    }

    @Test
    void maxAgeIsInclusiveThenEvicts() {
        DekCache c = cache(100, 1_000, 10);
        c.load(K1, ID, () -> key(7)).join();
        byte[] held = c.heldArray(K1);
        now.set(100);
        assertTrue(c.takeForEncrypt(K1).isPresent());
        now.set(101);
        assertTrue(c.takeForEncrypt(K1).isEmpty());
        assertTrue(c.candidates(SLOT).isEmpty());
        assertArrayEquals(new byte[32], held);
        assertEquals(1, c.evictions(DekCache.Cause.AGE));
    }

    @Test
    void capacityEvictsTheLeastRecentlyUsedAndErasesIt() {
        DekCache c = cache(1_000, 1_000, 1);
        c.load(K1, ID, () -> key(1)).join();
        byte[] held = c.heldArray(K1);
        c.load(K2, ID, () -> key(2)).join();
        assertEquals(1, c.size());
        assertTrue(c.takeForEncrypt(K1).isEmpty());
        assertTrue(c.takeForEncrypt(K2).isPresent());
        assertArrayEquals(new byte[32], held);
        assertEquals(1, c.evictions(DekCache.Cause.CAPACITY));
    }

    /**
     * #192: a read touches its own slot only, and leaves another tenant's aged-out key for that
     * tenant's next touch. A guard for the slot index, which must not start age-checking the
     * slots it no longer walks.
     */
    @Test
    void aReadTouchesOnlyItsOwnSlot() {
        DekCache c = cache(100, 1_000, 10);
        c.load(OTHER, ID, () -> key(9)).join();
        byte[] other = c.heldArray(OTHER);
        now.set(50);
        c.load(K1, ID, () -> key(1)).join();
        now.set(120);
        assertEquals(1, c.candidates(SLOT).size());
        assertEquals(0, c.evictions(DekCache.Cause.AGE), "the read reached another slot");
        assertArrayEquals(key(9), other);
    }

    /**
     * #192: a read walks its own slot's live keys and nothing else: not another slot's 64, and
     * not a key its slot has evicted.
     */
    @Test
    void aReadWalksOnlyItsOwnSlotsLiveKeys() {
        DekCache c = cache(1_000, 1_000, 100);
        c.load(K1, ID, () -> key(1)).join();
        c.load(K2, ID, () -> key(2)).join();
        for (int i = 0; i < 64; i++) {
            c.load(new DekCache.Key(OTHER.slot(), "v" + i), ID, () -> key(9)).join();
        }
        c.candidates(SLOT);
        assertEquals(2, c.lastWalked(), "a read walked other slots");
        c.retain(SLOT, java.util.Set.of("02"));
        c.candidates(SLOT);
        assertEquals(1, c.lastWalked(), "an evicted key stayed in its slot's index");
    }

    /**
     * #192: a read is a use for recency, though not for the use budget. Before the slot index,
     * a key that only ever decrypted kept its place and was the first to go at capacity.
     */
    @Test
    void aReadKeepsItsKeysRecentlyUsed() {
        DekCache c = cache(1_000, 1_000, 2);
        c.load(K1, ID, () -> key(1)).join();
        c.load(OTHER, ID, () -> key(9)).join();
        c.candidates(SLOT);
        c.load(new DekCache.Key(OTHER.slot(), "03"), ID, () -> key(3)).join();
        assertEquals(1, c.evictions(DekCache.Cause.CAPACITY));
        assertEquals(1, c.candidates(SLOT).size(), "the key just read was evicted first");
    }

    @Test
    void callersGetCopies() {
        DekCache c = cache(1_000, 1_000, 10);
        byte[] unwrapped = key(5);
        c.load(K1, ID, () -> unwrapped).join();
        java.util.Arrays.fill(unwrapped, (byte) 0);
        byte[] out = c.takeForEncrypt(K1).orElseThrow()[0];
        assertArrayEquals(key(5), out, "the cache kept the unwrapper's array");
        java.util.Arrays.fill(out, (byte) 0);
        assertArrayEquals(key(5), c.candidates(SLOT).get("01"), "a caller changed the cache");
    }

    /** docs/09 §8.3: N concurrent misses on one key cause one unwrap. */
    @Test
    void concurrentLoadsShareOneUnwrap() throws Exception {
        DekCache c = cache(1_000, 1_000, 10);
        AtomicInteger unwraps = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        int n = 16;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        try {
            List<CompletableFuture<CompletableFuture<Void>>> calls = new ArrayList<>();
            CountDownLatch started = new CountDownLatch(n);
            for (int i = 0; i < n; i++) {
                calls.add(CompletableFuture.supplyAsync(() -> {
                    started.countDown();
                    return c.load(K1, ID, () -> {
                        unwraps.incrementAndGet();
                        try {
                            release.await(5, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        return key(3);
                    });
                }, pool));
            }
            started.await(5, TimeUnit.SECONDS);
            Thread.sleep(100);
            release.countDown();
            for (var call : calls) {
                call.get(5, TimeUnit.SECONDS).get(5, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, unwraps.get());
    }

    /** docs/09 §3.6: a failed load caches nothing and the next load tries again. */
    @Test
    void aFailedLoadDoesNotPoison() {
        DekCache c = cache(1_000, 1_000, 10);
        CompletableFuture<Void> f = c.load(K1, ID, () -> {
            throw new IllegalStateException("kms down");
        });
        assertThrows(CompletionException.class, f::join);
        assertTrue(c.takeForEncrypt(K1).isEmpty());
        c.load(K1, ID, () -> key(4)).join();
        assertTrue(c.takeForEncrypt(K1).isPresent());
    }

    /** Review of #190: an Error in the unwrap must complete every joiner, not strand it. */
    @Test
    void anErrorInTheUnwrapCompletesEveryJoiner() throws Exception {
        DekCache c = cache(1_000, 1_000, 10);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            var owner = CompletableFuture.supplyAsync(() -> c.load(K1, ID, () -> {
                entered.countDown();
                try {
                    release.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                throw new StackOverflowError("simulated");
            }), pool);
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            CompletableFuture<Void> joined = c.load(K1, ID, () -> key(1));
            release.countDown();
            var e = assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> joined.get(5, TimeUnit.SECONDS));
            assertTrue(e.getCause() instanceof StackOverflowError, "" + e.getCause());
            assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> owner.get(5, TimeUnit.SECONDS).get(5, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
    }

    /** A load of a cached key replaces it: a new age, a new budget, the old array erased. */
    @Test
    void loadRefreshes() {
        DekCache c = cache(100, 2, 10);
        c.load(K1, ID, () -> key(1)).join();
        byte[] first = c.heldArray(K1);
        c.takeForEncrypt(K1);
        now.set(90);
        c.load(K1, ID, () -> key(2)).join();
        assertArrayEquals(new byte[32], first, "the replaced key was not erased");
        now.set(180);
        assertArrayEquals(key(2), c.takeForEncrypt(K1).orElseThrow()[0]);
        assertTrue(c.takeForEncrypt(K1).isPresent(), "the budget restarted");
    }

    @Test
    void retainEvictsAndErasesUnlistedVersions() {
        DekCache c = cache(1_000, 1_000, 10);
        c.load(K1, ID, () -> key(1)).join();
        c.load(K2, ID, () -> key(2)).join();
        byte[] dropped = c.heldArray(K1);
        c.retain(SLOT, java.util.Set.of("02"));
        assertEquals(java.util.Set.of("02"), c.candidates(SLOT).keySet());
        assertArrayEquals(new byte[32], dropped);
        assertEquals(1, c.evictions(DekCache.Cause.RETIRED));
    }

    @Property
    void limitsAcceptMaxUsesFromOneTo2To32(@ForAll @LongRange(min = 1, max = 1L << 32) long uses) {
        new DekCache.Limits(1, uses, 1);
    }

    @Test
    void limitsRefuseOutsideSpec55() {
        for (long uses : new long[] {0, -1, (1L << 32) + 1, Long.MAX_VALUE, Long.MIN_VALUE}) {
            assertThrows(IllegalArgumentException.class, () -> new DekCache.Limits(1, uses, 1));
        }
        assertThrows(IllegalArgumentException.class, () -> new DekCache.Limits(0, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new DekCache.Limits(1, 1, 0));
    }
}
