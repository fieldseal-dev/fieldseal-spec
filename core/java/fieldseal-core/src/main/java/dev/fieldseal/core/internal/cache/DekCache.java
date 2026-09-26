package dev.fieldseal.core.internal.cache;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * The DEK cache (spec §5.5; docs/09 §8.3). Unwrapped keys are held here, and only here, between
 * {@code warm} and the value path.
 *
 * <ul>
 *   <li><b>Three limits, all enforced:</b> max-age, max-uses (a {@code long}, at most 2³²) and
 *       capacity with least-recently-used eviction. An entry past its age or out of uses is
 *       evicted when next touched; the last permitted use evicts it immediately.
 *   <li><b>Uses are encryptions.</b> {@link #takeForEncrypt} counts one; {@link #candidates},
 *       the read path, counts none (docs/09 §8.1). Both mark a key recently used.
 *   <li><b>One lock, held per slot's worth of work.</b> Entries are indexed by slot, so a read
 *       or a {@link #retain} touches its own slot's versions and no other tenant's (#192). The
 *       lock is still the whole cache's, so tenants still take turns for it; that falls short
 *       of docs/09 §8.3's "lock-free or fine-grained-locked reads", and docs/27 §5.5 says so.
 *   <li><b>Single-flight.</b> Concurrent {@link #load}s of one key share one unwrap; a failed
 *       load caches nothing and leaves no marker behind, so it cannot poison the cache (docs/09
 *       §3.6). Unwraps run outside the lock, so the value path never waits on another key's
 *       refresh.
 *   <li><b>Erasure.</b> The cache holds its own copy of each key and zeroes it on eviction.
 *       Callers get copies. What that achieves on a JVM is limited, and docs/27 §5.4 says how.
 * </ul>
 *
 * <p>Keys are {@link Key}s: a {@link Slot} (provider scope, tenant, role) and a key version.
 */
public final class DekCache {

    /** What a cached key is for (docs/09 §8.3). */
    public enum Role { DEK, INDEX }

    /** Why an entry left the cache. {@code RETIRED}: its store no longer lists it. */
    public enum Cause { AGE, USES, CAPACITY, RETIRED }

    /** One tenant's key for one role, under one provider scope; versions share a slot. */
    public record Slot(String scope, String tenant, Role role) {}

    /** One key version in a slot. {@code version} is the hex of its {@code key_id}. */
    public record Key(Slot slot, String version) {}

    /**
     * The spec §5.5 limits, validated here as preconditions: the public {@code CachePolicy}
     * refuses bad values first, with a configuration error.
     */
    public record Limits(long maxAgeNanos, long maxUses, int capacity) {

        public static final long MAX_USES_BOUND = 1L << 32;

        public Limits {
            if (maxAgeNanos <= 0 || maxUses < 1 || maxUses > MAX_USES_BOUND || capacity < 1) {
                throw new IllegalArgumentException("cache limits outside spec §5.5: maxAge "
                        + maxAgeNanos + " ns, maxUses " + maxUses + ", capacity " + capacity);
            }
        }
    }

    private static final class Entry {
        final byte[] key;
        final byte[] keyId;
        final long loadedAt;
        long uses;

        Entry(byte[] key, byte[] keyId, long loadedAt) {
            this.key = key;
            this.keyId = keyId;
            this.loadedAt = loadedAt;
        }
    }

    private final Limits limits;
    private final LongSupplier clock;
    private final Map<Cause, AtomicLong> evictions = new EnumMap<>(Cause.class);
    private final ConcurrentHashMap<Key, CompletableFuture<Void>> inFlight =
            new ConcurrentHashMap<>();
    /** Access-ordered, so the eldest entry is the least recently used. Guarded by itself. */
    private final LinkedHashMap<Key, Entry> entries = new LinkedHashMap<>(16, 0.75f, true);
    /** The keys of {@link #entries}, by slot, so a slot's work is its own size. Same lock. */
    private final Map<Slot, Set<Key>> bySlot = new HashMap<>();
    /** How many keys the last {@link #candidates} examined. Same lock. For a test only. */
    private int lastWalked;

    public DekCache(Limits limits, LongSupplier nanoClock) {
        this.limits = limits;
        this.clock = nanoClock;
        for (Cause c : Cause.values()) {
            evictions.put(c, new AtomicLong());
        }
    }

    /**
     * Unwraps {@code key} and caches it, replacing any entry it already has, so that a refresh
     * ahead of expiry restarts the key's age and use budget (docs/09 §3.6). A concurrent load of
     * the same key joins the one in flight rather than unwrapping again. The unwrapped array is
     * copied; the copy is the cache's own.
     *
     * @return a future that completes when the key is cached, or with whatever the unwrap threw,
     *     {@code Error}s included: a joiner is never left waiting
     */
    public CompletableFuture<Void> load(Key key, byte[] keyId, Supplier<byte[]> unwrap) {
        CompletableFuture<Void> mine = new CompletableFuture<>();
        CompletableFuture<Void> running = inFlight.putIfAbsent(key, mine);
        if (running != null) {
            return running;
        }
        try {
            byte[] material = unwrap.get();
            if (material == null || material.length == 0) {
                throw new IllegalStateException("the unwrap returned no key material");
            }
            put(key, material.clone(), keyId.clone());
            mine.complete(null);
        } catch (Throwable t) {
            // Throwable, not RuntimeException: an Error, or a checked exception a Wrapper threw
            // sneakily, must still complete the future every concurrent joiner is waiting on.
            mine.completeExceptionally(t);
        } finally {
            inFlight.remove(key, mine);
        }
        return mine;
    }

    /**
     * For an encryption: copies of the key and its {@code key_id}, counting one use. Empty when
     * the key is not cached, too old, or out of uses; the last two are evicted and erased.
     */
    public Optional<byte[][]> takeForEncrypt(Key key) {
        synchronized (entries) {
            Entry e = entries.get(key);
            if (e == null || !fresh(key, e)) {
                return Optional.empty();
            }
            e.uses++;
            byte[][] out = {e.key.clone(), e.keyId.clone()};
            if (e.uses >= limits.maxUses()) {
                evict(key, Cause.USES);
            }
            return Optional.of(out);
        }
    }

    /**
     * For a read: a copy of every fresh key in {@code slot}, by version. Counts no use, but marks
     * each key recently used, so a key that only decrypts is not the first to go at capacity.
     * Touches {@code slot}'s entries only.
     */
    public Map<String, byte[]> candidates(Slot slot) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        synchronized (entries) {
            lastWalked = 0;
            for (Key k : keysOf(slot)) {
                lastWalked++;
                Entry e = entries.get(k);
                if (e != null && fresh(k, e)) {
                    out.put(k.version(), e.key.clone());
                }
            }
        }
        return out;
    }

    /**
     * Evicts and erases every entry in {@code slot} whose version is not in {@code versions}: the
     * versions its store no longer lists, which must stop decrypting (docs/09 §8.1, "all
     * currently-valid versions").
     */
    public void retain(Slot slot, Set<String> versions) {
        synchronized (entries) {
            for (Key k : keysOf(slot)) {
                if (!versions.contains(k.version())) {
                    evict(k, Cause.RETIRED);
                }
            }
        }
    }

    /** Evictions so far for {@code cause}, for the metrics docs/09 §8.3 asks for. */
    public long evictions(Cause cause) {
        return evictions.get(cause).get();
    }

    public int size() {
        synchronized (entries) {
            return entries.size();
        }
    }

    /** How many keys the last {@link #candidates} examined. Package-private, for a test. */
    int lastWalked() {
        synchronized (entries) {
            return lastWalked;
        }
    }

    /**
     * The cache's own array for {@code key}, not a copy, or null. Package-private: it exists so
     * that a test can hold the array across an eviction and see it zeroed.
     */
    byte[] heldArray(Key key) {
        synchronized (entries) {
            Entry e = entries.get(key);
            return e == null ? null : e.key;
        }
    }

    /** Whether {@code e} is within its age; if not, it is evicted. Caller holds the lock. */
    private boolean fresh(Key key, Entry e) {
        if (clock.getAsLong() - e.loadedAt > limits.maxAgeNanos()) {
            evict(key, Cause.AGE);
            return false;
        }
        return true;
    }

    /** A snapshot of {@code slot}'s keys, in no promised order. Caller holds the lock. */
    private List<Key> keysOf(Slot slot) {
        Set<Key> keys = bySlot.get(slot);
        return keys == null ? List.of() : List.copyOf(keys);
    }

    private void put(Key key, byte[] material, byte[] keyId) {
        synchronized (entries) {
            Entry old = entries.put(key, new Entry(material, keyId, clock.getAsLong()));
            if (old != null) {
                Arrays.fill(old.key, (byte) 0);
            } else {
                bySlot.computeIfAbsent(key.slot(), s -> new HashSet<>()).add(key);
            }
            while (entries.size() > limits.capacity()) {
                evict(entries.keySet().iterator().next(), Cause.CAPACITY);
            }
        }
    }

    /** Removes and erases one entry. Caller holds the lock. */
    private void evict(Key key, Cause cause) {
        Entry e = entries.remove(key);
        if (e != null) {
            Set<Key> keys = bySlot.get(key.slot());
            if (keys != null && keys.remove(key) && keys.isEmpty()) {
                bySlot.remove(key.slot());
            }
            Arrays.fill(e.key, (byte) 0);
            evictions.get(cause).incrementAndGet();
        }
    }
}
