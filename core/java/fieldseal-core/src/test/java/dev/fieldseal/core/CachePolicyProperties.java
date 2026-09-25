package dev.fieldseal.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.fieldseal.core.errors.ConfigurationError;
import java.time.Duration;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.LongRange;
import org.junit.jupiter.api.Test;

/**
 * docs/27 §7: {@code CachePolicy.maxUses} at its edges. 2³² is accepted; 2³²+1, 0 and negatives
 * are refused (spec §5.5), as a configuration error. There are no defaults to test: every limit is
 * required.
 */
class CachePolicyProperties {

    private static final Duration AGE = Duration.ofMinutes(1);

    @Property
    void acceptsOneTo2To32(@ForAll @LongRange(min = 1, max = 1L << 32) long uses) {
        assertEquals(uses, new CachePolicy(AGE, uses, 1).maxUses());
    }

    @Property
    void refusesAbove2To32(@ForAll @LongRange(min = (1L << 32) + 1) long uses) {
        assertThrows(ConfigurationError.class, () -> new CachePolicy(AGE, uses, 1));
    }

    @Property
    void refusesZeroAndNegatives(@ForAll @LongRange(min = Long.MIN_VALUE, max = 0) long uses) {
        assertThrows(ConfigurationError.class, () -> new CachePolicy(AGE, uses, 1));
    }

    @Test
    void theEdgesExactly() {
        new CachePolicy(AGE, 1L << 32, 1);
        new CachePolicy(AGE, 1, 1);
        for (long bad : new long[] {(1L << 32) + 1, 0, -1}) {
            assertThrows(ConfigurationError.class, () -> new CachePolicy(AGE, bad, 1));
        }
        assertThrows(ConfigurationError.class, () -> new CachePolicy(null, 1, 1));
        assertThrows(ConfigurationError.class, () -> new CachePolicy(Duration.ZERO, 1, 1));
        assertThrows(ConfigurationError.class, () -> new CachePolicy(Duration.ofNanos(-1), 1, 1));
        assertThrows(ConfigurationError.class, () -> new CachePolicy(AGE, 1, 0));
    }
}
