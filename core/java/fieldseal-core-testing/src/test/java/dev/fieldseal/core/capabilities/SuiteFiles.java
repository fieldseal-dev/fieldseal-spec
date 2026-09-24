package dev.fieldseal.core.capabilities;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.harness.VectorHarness;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Reads pinned vector files for the capability audit. The harness walk runs first, so no file is
 * read before its length and SHA-256 have been checked against the manifest (docs/08 §5 item 1).
 * The walk runs once, whatever its outcome, and each file is parsed once, through the harness's
 * own reader, so the audit sees exactly what the walk saw.
 */
public final class SuiteFiles {

    private static final HexFormat HEX = HexFormat.of();

    /** The walk's problems, or null until it has run. */
    private static List<String> walked;
    private static final Map<String, List<JsonNode>> PARSED = new HashMap<>();

    private SuiteFiles() {}

    private static Path vectorsDir() {
        return Path.of(System.getProperty("fieldseal.vectors"));
    }

    private static synchronized Path root() {
        if (walked == null) {
            try {
                walked = VectorHarness.walk(vectorsDir()).problems();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        assertEquals(List.of(), walked,
                "the pinned suite does not walk clean; no capability is checked against it");
        return vectorsDir();
    }

    /** Every vector in {@code path} (relative to vectors/), in file order. */
    public static synchronized List<JsonNode> vectors(String path) {
        List<JsonNode> cached = PARSED.get(path);
        if (cached != null) {
            return cached;
        }
        try {
            List<JsonNode> out = new ArrayList<>();
            VectorHarness.read(root().resolve(path)).path("vectors").forEach(out::add);
            if (out.isEmpty()) {
                throw new IllegalStateException(path + " has no vectors");
            }
            List<JsonNode> vectors = List.copyOf(out);
            PARSED.put(path, vectors);
            return vectors;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] hex(JsonNode node) {
        if (!node.isTextual()) {
            throw new IllegalArgumentException("expected a hex string, got " + node);
        }
        return HEX.parseHex(node.asText());
    }

    public static String hex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    public static String slug(JsonNode vector) {
        String id = vector.path("id").asText();
        return id.substring(id.lastIndexOf('/') + 1);
    }
}
