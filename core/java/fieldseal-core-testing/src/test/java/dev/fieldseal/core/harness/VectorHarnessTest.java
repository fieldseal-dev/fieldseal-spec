package dev.fieldseal.core.harness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VectorHarnessTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void thePinnedSuiteWalksClean() throws IOException {
        Path vectors = Path.of(System.getProperty("fieldseal.vectors"));
        VectorHarness.Walk walk = VectorHarness.walk(vectors);

        assertEquals(List.of(), walk.problems());
        String manifestVersion = JSON.readTree(vectors.resolve("MANIFEST.json").toFile())
                .path("vector_suite_version").asText();
        assertEquals(manifestVersion, walk.suiteVersion());
        assertEquals(JSON.readTree(vectors.resolve("MANIFEST.json").toFile()).path("files").size(),
                walk.files().size());
        assertTrue(walk.files().stream().allMatch(f -> f.vectors() > 0));
    }

    // The guards, each against a synthetic one-file suite that walks clean until one input is
    // broken. A guard nobody exercises is one a refactor can delete silently.

    @Test
    void aSyntheticSuiteWalksClean(@TempDir Path dir) throws IOException {
        Suite s = new Suite(dir);
        s.write();
        VectorHarness.Walk walk = VectorHarness.walk(dir);
        assertEquals(List.of(), walk.problems());
        assertEquals(2, walk.vectors());
    }

    @Test
    void aChangedByteFailsTheHash(@TempDir Path dir) throws IOException {
        Suite s = new Suite(dir);
        s.write();
        byte[] b = Files.readAllBytes(s.file());
        b[b.length - 2] ^= 0x01;
        Files.write(s.file(), b);
        assertProblem(dir, "kdf/demo.json: sha256");
    }

    @Test
    void aFileMissingFromDiskIsAProblem(@TempDir Path dir) throws IOException {
        Suite s = new Suite(dir);
        s.write();
        Files.delete(s.file());
        assertProblem(dir, "kdf/demo.json: listed in the manifest but missing");
    }

    @Test
    void heldOutIsRecordedButNeverOpened(@TempDir Path dir) throws IOException {
        Suite s = new Suite(dir);
        s.heldOut = "kdf/never-there.json"; // does not exist; opening it would be a problem
        s.write();
        VectorHarness.Walk walk = VectorHarness.walk(dir);
        assertEquals(List.of(), walk.problems());
        assertEquals(List.of("kdf/never-there.json"), walk.heldOut());
    }

    @Test
    void aFileBothListedAndHeldOutIsAProblem(@TempDir Path dir) throws IOException {
        Suite s = new Suite(dir);
        s.heldOut = "kdf/demo.json";
        s.write();
        assertProblem(dir, "kdf/demo.json: listed in both files and held_out");
    }

    @Test
    void aVersionMismatchIsAProblem(@TempDir Path dir) throws IOException {
        Suite s = new Suite(dir);
        s.fileVersion = "0.0.1";
        s.write();
        assertProblem(dir, "vector_suite_version is 0.0.1");
    }

    @Test
    void aHeldOutStatusInFilesIsAProblem(@TempDir Path dir) throws IOException {
        Suite s = new Suite(dir);
        s.status = "held-out";
        s.write();
        assertProblem(dir, "status is held-out");
    }

    @Test
    void aBadIdIsAProblem(@TempDir Path dir) throws IOException {
        Suite s = new Suite(dir);
        s.ids = List.of("kdf/demo/ok", "kdf/other/wrong-stem");
        s.write();
        assertProblem(dir, "id 'kdf/other/wrong-stem' is not kdf/demo/<slug>");
    }

    @Test
    void aDuplicateIdIsAProblem(@TempDir Path dir) throws IOException {
        Suite s = new Suite(dir);
        s.ids = List.of("kdf/demo/same", "kdf/demo/same");
        s.write();
        assertProblem(dir, "id 'kdf/demo/same' is not unique");
    }

    private static void assertProblem(Path dir, String fragment) throws IOException {
        List<String> problems = VectorHarness.walk(dir).problems();
        assertTrue(problems.stream().anyMatch(p -> p.contains(fragment)),
                "expected a problem containing '" + fragment + "', got " + problems);
    }

    /** A one-file suite, {@code kdf/demo.json}, correct until a field is changed. */
    private static final class Suite {
        final Path dir;
        String fileVersion = "9.9.9-test";
        String status = "pinned";
        String heldOut;
        List<String> ids = List.of("kdf/demo/first", "kdf/demo/second");

        Suite(Path dir) {
            this.dir = dir;
        }

        Path file() {
            return dir.resolve("kdf/demo.json");
        }

        void write() throws IOException {
            ObjectNode doc = JSON.createObjectNode()
                    .put("schema", "fieldseal-vectors/kdf/v1")
                    .put("vector_suite_version", fileVersion)
                    .put("group", "kdf")
                    .put("status", status);
            ArrayNode vs = doc.putArray("vectors");
            ids.forEach(id -> vs.addObject().put("id", id));
            doc.putArray("retired");
            byte[] bytes = JSON.writeValueAsString(doc).getBytes(StandardCharsets.UTF_8);
            Files.createDirectories(file().getParent());
            Files.write(file(), bytes);

            ObjectNode manifest = JSON.createObjectNode().put("vector_suite_version", "9.9.9-test");
            manifest.putArray("files").addObject()
                    .put("path", "kdf/demo.json")
                    .put("sha256", HexFormat.of().formatHex(sha256(bytes)))
                    .put("bytes", bytes.length);
            ArrayNode held = manifest.putArray("held_out");
            if (heldOut != null) {
                held.addObject().put("path", heldOut);
            }
            Files.writeString(dir.resolve("MANIFEST.json"), JSON.writeValueAsString(manifest));
        }

        private static byte[] sha256(byte[] b) {
            try {
                return MessageDigest.getInstance("SHA-256").digest(b);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
