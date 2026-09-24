package dev.fieldseal.core.internal.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.ConfigurationError;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class RegistryTest {

    /** docs/09 §6's table and spec §4.2's names, row by row. */
    @Test
    void theTableIsDocs09Section6() {
        assertEquals(new Suite(0xFF01, "FLE-AES256GCM-HKDF-SHA512-PROVISIONAL", "AES-256-GCM",
                32, 12, 16, 32, true), Registry.FF01);
        assertEquals(new Suite(0xFF02, "FLE-XCHACHA20POLY1305-HKDF-SHA512-PROVISIONAL",
                "XChaCha20-Poly1305", 32, 24, 16, 32, false), Registry.FF02);
        assertEquals(List.of(Registry.FF01, Registry.FF02), Registry.all());
    }

    /** spec §4.2: 0x0001 and 0x0002 are reserved and unassigned, so not registered. */
    @Test
    void onlyTheTwoProvisionalSuitesAreRegistered() {
        assertTrue(Registry.lookup(0xFF01).isPresent());
        assertTrue(Registry.lookup(0xFF02).isPresent());
        for (int id : new int[] {0x0000, 0x0001, 0x0002, 0xFF00, 0xFF03, 0xFFFF}) {
            assertFalse(Registry.lookup(id).isPresent(), Integer.toHexString(id));
        }
    }

    /** spec §4.8: one masked comparison. */
    @Test
    void provisionalIsTheFf00Range() {
        assertTrue(Suite.isProvisional(0xFF00));
        assertTrue(Suite.isProvisional(0xFFFF));
        assertTrue(Registry.FF01.provisional());
        assertFalse(Suite.isProvisional(0x0001));
        assertFalse(Suite.isProvisional(0xFEFF));
    }

    @Test
    void theAllowListHasNoDefaultAndNamesOnlyRegisteredSuites() {
        assertThrows(ConfigurationError.class, () -> AllowList.of(Set.of()));
        assertThrows(ConfigurationError.class, () -> AllowList.of(null));
        assertThrows(ConfigurationError.class, () -> AllowList.of(Set.of(0xFF01, 0x0001)));
        Set<Integer> withNull = new HashSet<>();
        withNull.add(null);
        assertThrows(ConfigurationError.class, () -> AllowList.of(withNull));

        AllowList a = AllowList.of(Set.of(0xFF01));
        assertTrue(a.permits(0xFF01));
        assertFalse(a.permits(0xFF02));
        assertThrows(UnsupportedOperationException.class, () -> a.suites().add(0xFF02));
        assertEquals(List.of(0xFF01, 0xFF02),
                List.copyOf(AllowList.of(Set.of(0xFF02, 0xFF01)).suites()));
    }
}
