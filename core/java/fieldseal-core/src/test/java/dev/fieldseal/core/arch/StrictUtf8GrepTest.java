package dev.fieldseal.core.arch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * docs/27 §4: "{@code new String(bytes, UTF_8)} replaces malformed input silently and MUST NOT
 * appear in a value path; CI greps for it." This is that grep, over every main source file, so it
 * runs in the {@code java-core} job with everything else. Each pattern is a JDK decode that
 * substitutes U+FFFD rather than failing; the one strict decode this core has is a {@code
 * CharsetDecoder} set to {@code REPORT} (docs/09 §7.1 clause 5).
 */
class StrictUtf8GrepTest {

    private static final List<Pattern> LOSSY = List.of(
            // new String(bytes, UTF_8), new String(bytes, off, len, "UTF-8"), any charset name
            Pattern.compile("new\\s+String\\s*\\([^;]*,\\s*(StandardCharsets\\.)?(UTF_8|\"UTF-?8\"|"
                    + "Charset\\.forName)"),
            // Charset.decode substitutes too
            Pattern.compile("UTF_8\\s*\\.\\s*decode\\s*\\("));

    @Test
    void noMainSourceDecodesUtf8WithReplacement() throws IOException {
        Path root = Path.of("src", "main", "java");
        assertTrue(Files.isDirectory(root), "run from the fieldseal-core project: " + root);
        List<String> hits = new ArrayList<>();
        int files = 0;
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : s.filter(f -> f.toString().endsWith(".java")).toList()) {
                files++;
                List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
                for (int i = 0; i < lines.size(); i++) {
                    for (Pattern lossy : LOSSY) {
                        if (lossy.matcher(lines.get(i)).find()) {
                            hits.add(p + ":" + (i + 1) + ": " + lines.get(i).trim());
                        }
                    }
                }
            }
        }
        assertTrue(files > 40, "scanned only " + files + " files");
        assertEquals(List.of(), hits);
    }
}
