package dev.fieldseal.core;

import dev.fieldseal.core.errors.ConfigurationError;
import dev.fieldseal.core.internal.cache.DekCache;
import java.time.Duration;

/**
 * The DEK cache's limits (spec §5.5), required with the envelope key provider.
 *
 * <p><b>These are security parameters, not performance tuning.</b> Every unwrapped key in the
 * cache is plaintext key material in process memory, exposed to memory dumps, core files and
 * swap for as long as it stays (spec §5.5's honest limitation). {@code maxAge} is how long that
 * window lasts; {@code maxUses} caps how many values one cached key encrypts. Use the smallest
 * values your cost and latency allow.
 *
 * <p>There are no defaults: each limit is a decision the deployment makes and can state (docs/07
 * §7, 2026-09-25).
 *
 * @param maxAge how long an unwrapped key may be used after it was cached; greater than zero
 * @param maxUses how many encryptions one cached key may perform, from 1 to 2³²; a {@code long},
 *     because 2³² does not fit an {@code int}. Decryptions do not count (docs/09 §8.1)
 * @param capacity how many keys the cache holds before evicting the least recently used; at
 *     least 1
 */
public record CachePolicy(Duration maxAge, long maxUses, int capacity) {

    /** The spec §5.5 ceiling on {@code maxUses}: the cache's own, so the two cannot drift. */
    public static final long MAX_USES_BOUND = DekCache.Limits.MAX_USES_BOUND;

    /** @throws ConfigurationError if a limit is missing or outside spec §5.5 */
    public CachePolicy {
        if (maxAge == null || maxAge.isNegative() || maxAge.isZero()) {
            throw new ConfigurationError("cachePolicy.maxAge must be greater than zero, got "
                    + maxAge + " (spec §5.5)");
        }
        try {
            maxAge.toNanos();
        } catch (ArithmeticException e) {
            throw new ConfigurationError("cachePolicy.maxAge " + maxAge
                    + " is longer than this platform can measure");
        }
        if (maxUses < 1 || maxUses > MAX_USES_BOUND) {
            throw new ConfigurationError("cachePolicy.maxUses must be from 1 to 2^32, got "
                    + maxUses + " (spec §5.5)");
        }
        if (capacity < 1) {
            throw new ConfigurationError("cachePolicy.capacity must be at least 1, got "
                    + capacity);
        }
    }

    /** The cache's limits. Checked here first, as a configuration error, and again there. */
    DekCache.Limits toLimits() {
        return new DekCache.Limits(maxAge.toNanos(), maxUses, capacity);
    }
}
