package dev.fieldseal.core.arch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.lang.module.ModuleDescriptor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * Pins the compiled module descriptor to docs/27 §3: three public packages, exported to
 * everyone, and the testing seam, exported to the testing module alone, and nothing else. The
 * internal packages are hidden by being absent from this list, so a stray {@code exports} line
 * would publish one silently; this test is what notices.
 */
class ModuleDescriptorTest {

    private static ModuleDescriptor descriptor() throws IOException {
        Path classes = Path.of(System.getProperty("fieldseal.mainClasses"));
        try (InputStream in = Files.newInputStream(classes.resolve("module-info.class"))) {
            return ModuleDescriptor.read(in);
        }
    }

    @Test
    void exportsExactlyThePublicPackages() throws IOException {
        ModuleDescriptor d = descriptor();
        assertEquals("dev.fieldseal.core", d.name());
        assertEquals(
                Set.of("dev.fieldseal.core", "dev.fieldseal.core.errors",
                        "dev.fieldseal.core.keyprovider"),
                d.exports().stream().filter(e -> !e.isQualified())
                        .map(ModuleDescriptor.Exports::source).collect(Collectors.toSet()));
        // S6: the one qualified export, the seam encrypt_with_materials enters (docs/08 §6).
        assertEquals(Set.of("dev.fieldseal.core.internal.testing -> [dev.fieldseal.core.testing]"),
                d.exports().stream().filter(ModuleDescriptor.Exports::isQualified)
                        .map(e -> e.source() + " -> " + e.targets().stream().sorted().toList())
                        .collect(Collectors.toSet()));
        assertTrue(d.opens().isEmpty(), "no package is open to reflection");
    }

    @Test
    void requiresTheJdkBaseAndBouncyCastleOnly() throws IOException {
        // docs/27 §2: one third-party runtime dependency, BouncyCastle, for Argon2id only (S5).
        assertEquals(Set.of("java.base", "org.bouncycastle.provider"),
                descriptor().requires().stream().map(ModuleDescriptor.Requires::name)
                        .collect(Collectors.toSet()));
    }
}
