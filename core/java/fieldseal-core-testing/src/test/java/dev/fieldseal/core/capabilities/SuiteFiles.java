package dev.fieldseal.core.capabilities;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.fieldseal.core.harness.VectorHarness;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Reads pinned vector files for the capability audit. The harness walk runs first, so no file is
 * read before its length and SHA-256 have been checked against the manifest (docs/08 §5 item 1).
 */
final class SuiteFiles {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static Path verified;

    private SuiteFiles() {}

    private static synchronized Path root() {
        if (verified == null) {
            Path vectors = Path.of(System.getProperty("fieldseal.vectors"));
            try {
                assertEquals(List.of(), VectorHarness.walk(vectors).problems(),
                        "the pinned suite does not walk clean; no capability is checked against it");
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            verified = vectors;
        }
        return verified;
    }

    /** Every vector in {@code path} (relative to vectors/), in file order. */
    static List<JsonNode> vectors(String path) {
        try {
            List<JsonNode> out = new ArrayList<>();
            JSON.readTree(root().resolve(path).toFile()).path("vectors").forEach(out::add);
            if (out.isEmpty()) {
                throw new IllegalStateException(path + " has no vectors");
            }
            return out;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static byte[] hex(JsonNode node) {
        if (!node.isTextual()) {
            throw new IllegalArgumentException("expected a hex string, got " + node);
        }
        return HEX.parseHex(node.asText());
    }

    static String hex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    static String slug(JsonNode vector) {
        String id = vector.path("id").asText();
        return id.substring(id.lastIndexOf('/') + 1);
    }
}
