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
