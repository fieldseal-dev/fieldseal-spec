package dev.fieldseal.core.internal.registry;

import java.util.List;
import java.util.Optional;

/**
 * The frozen suite table (spec §4.2; docs/09 §6). There is deliberately no registration API:
 * adding a suite is a code change in every core, plus vectors, plus a spec revision (docs/09 §6).
 *
 * <p>{@code 0xFF01} is built. {@code 0xFF02} is registered and unbuilt (docs/27 §10): it is
 * recognized as an envelope, because recognition follows the registry and not what this core can
 * perform (spec §3.4), but no client here can decrypt or write under it. {@code 0x0001} and
 * {@code 0x0002} are reserved and unassigned (spec §4.2), so they are not in the table and an
 * envelope naming them is not recognized.
 */
public final class Registry {

    public static final Suite FF01 = new Suite(0xFF01, "FLE-AES256GCM-HKDF-SHA512-PROVISIONAL",
            "AES-256-GCM", 32, 12, 16, 32, true);

    public static final Suite FF02 = new Suite(0xFF02,
            "FLE-XCHACHA20POLY1305-HKDF-SHA512-PROVISIONAL", "XChaCha20-Poly1305", 32, 24, 16, 32,
            false);

    private static final List<Suite> ALL = List.of(FF01, FF02);

    private Registry() {}

    /** Every registered suite, in {@code suite_id} order. */
    public static List<Suite> all() {
        return ALL;
    }

    public static Optional<Suite> lookup(int suiteId) {
        for (Suite s : ALL) {
            if (s.id() == suiteId) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }
}
