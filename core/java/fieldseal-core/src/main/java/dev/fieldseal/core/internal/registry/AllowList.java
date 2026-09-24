package dev.fieldseal.core.internal.registry;

import dev.fieldseal.core.errors.ConfigurationError;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * The decrypt-side allow-list (spec §4.3). It has no default: a client names its suites
 * explicitly (docs/09 §2), which is how a suite is retired without a downgrade window.
 *
 * <p>It governs authorization to decrypt, never recognition (spec §3.4): an envelope under a
 * registered suite that is not listed here is still an envelope, and is refused with
 * {@code SUITE_NOT_ALLOWED} after it has been recognized.
 */
public final class AllowList {

    private final Set<Integer> suites;

    private AllowList(Set<Integer> suites) {
        this.suites = suites;
    }

    /**
     * @throws ConfigurationError if {@code suiteIds} is empty or names an unregistered suite
     */
    public static AllowList of(Set<Integer> suiteIds) {
        if (suiteIds == null || suiteIds.isEmpty()) {
            throw new ConfigurationError(
                    "allowed_suites is required and must be non-empty; it has no default"
                            + " (docs/09 §2, spec §4.3)");
        }
        Set<Integer> copy = new TreeSet<>();
        for (Integer id : suiteIds) {
            if (id == null || Registry.lookup(id).isEmpty()) {
                throw new ConfigurationError("allowed_suites names "
                        + (id == null ? "null" : String.format("0x%04X", id))
                        + ", which is not a registered suite (spec §4.2)");
            }
            copy.add(id);
        }
        return new AllowList(Collections.unmodifiableSet(copy));
    }

    public boolean permits(int suiteId) {
        return suites.contains(suiteId);
    }

    /** An unmodifiable view in ascending id order, for configuration reflection (docs/09 §2). */
    public Set<Integer> suites() {
        return suites;
    }
}
