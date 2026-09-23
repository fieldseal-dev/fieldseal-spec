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
 * everyone, and nothing else. The internal packages are hidden by being absent from this list,
 * so a stray {@code exports} line would publish one silently; this test is what notices.
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
                d.exports().stream().map(ModuleDescriptor.Exports::source).collect(Collectors.toSet()));
        // Qualified exports arrive at S6, with the testing seam (module-info.java).
        assertTrue(d.exports().stream().noneMatch(ModuleDescriptor.Exports::isQualified));
        assertTrue(d.opens().isEmpty(), "no package is open to reflection");
    }

    @Test
    void requiresNothingButTheJdkBase() throws IOException {
        // docs/27 §2: no third-party runtime dependency until BouncyCastle, for Argon2id only.
        assertEquals(Set.of("java.base"),
                descriptor().requires().stream().map(ModuleDescriptor.Requires::name)
                        .collect(Collectors.toSet()));
    }
}
