package dev.fieldseal.core.capabilities;

import java.lang.management.ManagementFactory;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * docs/27 §6.4, the platform-maximum probe: the largest {@code byte[]} this JVM allocates, found
 * by bisection to the exact byte, and the failure just above it. Informational. The core's
 * length bound rests on the type ({@code byte[].length} is an {@code int}), not on this figure,
 * and nothing gates on it. Run with {@code ./gradlew memoryProbe}, never by {@code build}.
 */
@Tag("memory")
class BufferMaxProbe {

    private static final int GIB = 1 << 30;

    /** Keeps each array reachable until its last byte is written, so it is really allocated. */
    private static volatile byte[] sink;

    /** The OutOfMemoryError's message, or null when {@code n} bytes were allocated. */
    private static String tryAllocate(int n) {
        try {
            byte[] a = new byte[n];
            a[n - 1] = 1;
            sink = a;
            return null;
        } catch (OutOfMemoryError e) {
            return String.valueOf(e.getMessage());
        } finally {
            sink = null;
        }
    }

    @Test
    void largestByteArray() {
        String floor = tryAllocate(GIB);
        String report;
        if (floor != null) {
            report = "ceiling not observed: 1 GiB already fails (" + floor + ")";
        } else if (tryAllocate(Integer.MAX_VALUE) == null) {
            report = "largest byte[] = Integer.MAX_VALUE = 2^31-1";
        } else {
            int lo = GIB; // succeeds
            int hi = Integer.MAX_VALUE; // fails
            while (hi - lo > 1) {
                int mid = lo + (hi - lo) / 2;
                if (tryAllocate(mid) == null) {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            String above = tryAllocate(lo + 1);
            long k = (1L << 31) - lo;
            report = String.format("largest byte[] = %d = 2^31-%d; at %d: \"%s\" (%s)", lo, k,
                    lo + 1, above,
                    above.contains("VM limit") ? "the VM's array limit" : "the heap, not the VM");
        }
        System.out.printf("BufferMaxProbe: %s%n  JVM %s %s (%s), GC %s, max heap %d MiB, flags %s%n",
                report, System.getProperty("java.vm.vendor"),
                System.getProperty("java.runtime.version"), System.getProperty("java.vm.name"),
                ManagementFactory.getGarbageCollectorMXBeans().stream()
                        .map(java.lang.management.GarbageCollectorMXBean::getName).toList(),
                Runtime.getRuntime().maxMemory() >> 20,
                ManagementFactory.getRuntimeMXBean().getInputArguments());
    }
}
