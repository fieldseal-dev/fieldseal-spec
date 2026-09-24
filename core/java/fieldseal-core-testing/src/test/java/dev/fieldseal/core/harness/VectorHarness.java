package dev.fieldseal.core.harness;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The vector harness (docs/08 §5; docs/27 §7), at stage S1: it walks the pinned suite and
 * executes nothing.
 *
 * <p>What the walk does now, and keeps doing when vectors run (S3 onward):
 *
 * <ul>
 *   <li>reads {@code MANIFEST.json}, takes {@code vector_suite_version} from it rather than from
 *       a constant, and iterates {@code files} only, never {@code held_out} (docs/08 §5 item 1;
 *       docs/17 §4);
 *   <li>checks each listed file's byte length and SHA-256 before parsing it;
 *   <li>checks the common wrapper of docs/08 §4 (schema, group, suite version, {@code pinned}
 *       status); that every vector carries a unique, well-formed {@code id} and a non-empty
 *       {@code description} and {@code spec_ref}; and that every {@code retired} entry carries a
 *       well-formed {@code id} and a {@code reason}.
 * </ul>
 *
 * <p>What it does not do yet: run a vector, or emit the docs/14 §4 report (S6). docs/08 §5
 * item 2's schema validation has no input, since the repository has no {@code vectors/schema/}.
 * Any problem is fatal: a malformed suite fails loudly and is never skipped (docs/08 §5 item 2).
 */
public final class VectorHarness {

    /** docs/08 §4: {@code <family>/<file-stem>/<slug>}, slug {@code [a-z0-9-]{1,64}}. */
    private static final Pattern SLUG = Pattern.compile("[a-z0-9-]{1,64}");

    private static final ObjectMapper JSON =
            new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    /**
     * One listed file. {@code walked} is false when a problem stopped the walk before its
     * vectors were counted; {@code vectors} is then 0 and means nothing.
     */
    public record FileWalk(String path, int vectors, boolean walked) {
        static FileWalk failed(String path) {
            return new FileWalk(path, 0, false);
        }
    }

    /** The whole walk. It is clean when {@code problems} is empty. */
    public record Walk(
            String suiteVersion, List<FileWalk> files, List<String> heldOut, List<String> problems) {
        public int vectors() {
            return files.stream().mapToInt(FileWalk::vectors).sum();
        }
    }

    private VectorHarness() {}

    public static Walk walk(Path vectorsDir) throws IOException {
        Path root = vectorsDir.toAbsolutePath().normalize();
        JsonNode manifest = JSON.readTree(root.resolve("MANIFEST.json").toFile());
        List<String> problems = new ArrayList<>();

        String suiteVersion = manifest.path("vector_suite_version").asText("");
        if (suiteVersion.isEmpty()) {
            problems.add("MANIFEST.json: no vector_suite_version");
        }

        // Recorded, never opened: a held-out family counts toward nothing (docs/17 §4).
        List<String> heldOut = new ArrayList<>();
        manifest.path("held_out").forEach(h -> heldOut.add(h.path("path").asText()));

        JsonNode listed = manifest.path("files");
        if (!listed.isArray() || listed.isEmpty()) {
            problems.add("MANIFEST.json: files is missing or empty");
        }
        List<FileWalk> files = new ArrayList<>();
        Set<String> paths = new HashSet<>();
        Set<String> ids = new HashSet<>();
        for (JsonNode entry : listed) {
            String path = entry.path("path").asText("");
            if (!paths.add(path)) {
                problems.add(path + ": listed twice in files");
                continue;
            }
            if (heldOut.contains(path)) {
                problems.add(path + ": listed in both files and held_out");
                continue;
            }
            files.add(walkFile(root, path, entry, suiteVersion, ids, problems));
        }
        return new Walk(suiteVersion, List.copyOf(files), List.copyOf(heldOut), List.copyOf(problems));
    }

    private static FileWalk walkFile(Path root, String path, JsonNode entry, String suiteVersion,
            Set<String> ids, List<String> problems) throws IOException {
        String[] parts = path.split("/");
        Path file = root.resolve(path).normalize();
        if (parts.length != 2 || !parts[1].endsWith(".json") || !file.startsWith(root)) {
            problems.add(path + ": not a <family>/<stem>.json path under vectors/");
            return FileWalk.failed(path);
        }
        if (!Files.isRegularFile(file)) {
            problems.add(path + ": listed in the manifest but missing");
            return FileWalk.failed(path);
        }

        // Integrity before parsing: a file that fails its hash is not read (docs/08 §5 item 1).
        byte[] bytes = Files.readAllBytes(file);
        if (!entry.path("bytes").canConvertToLong()) {
            problems.add(path + ": the manifest entry has no integer bytes field");
            return FileWalk.failed(path);
        }
        if (bytes.length != entry.path("bytes").asLong()) {
            problems.add(path + ": " + bytes.length + " bytes, manifest says " + entry.path("bytes"));
            return FileWalk.failed(path);
        }
        String sha256 = HexFormat.of().formatHex(sha256(bytes));
        if (!sha256.equals(entry.path("sha256").asText())) {
            problems.add(path + ": sha256 " + sha256 + ", manifest says " + entry.path("sha256"));
            return FileWalk.failed(path);
        }

        String family = parts[0];
        String stem = parts[1].substring(0, parts[1].length() - ".json".length());
        JsonNode doc = JSON.readTree(bytes);
        expect(problems, path, "schema", doc, "fieldseal-vectors/" + family + "/v1");
        expect(problems, path, "group", doc, family);
        expect(problems, path, "vector_suite_version", doc, suiteVersion);
        expect(problems, path, "status", doc, "pinned");

        String prefix = family + "/" + stem + "/";
        Set<String> retired = new HashSet<>();
        for (JsonNode r : doc.path("retired")) {
            String id = r.path("id").asText("");
            if (!wellFormed(id, prefix)) {
                problems.add(path + ": retired id '" + id + "' is not " + prefix + "<slug>");
            }
            if (r.path("reason").asText("").isBlank()) {
                problems.add(path + ": retired id '" + id + "' has no reason");
            }
            retired.add(id);
        }
        JsonNode vectors = doc.path("vectors");
        if (!vectors.isArray() || vectors.isEmpty()) {
            problems.add(path + ": no vectors");
            return FileWalk.failed(path);
        }
        for (JsonNode v : vectors) {
            String id = v.path("id").asText("");
            for (String field : new String[] {"description", "spec_ref"}) {
                if (!v.path(field).isTextual() || v.path(field).asText().isBlank()) {
                    problems.add(path + ": vector '" + id + "' has no " + field);
                }
            }
            if (!wellFormed(id, prefix)) {
                problems.add(path + ": id '" + id + "' is not " + prefix + "<slug>");
            } else if (!ids.add(id)) {
                problems.add(path + ": id '" + id + "' is not unique in the suite");
            } else if (retired.contains(id)) {
                problems.add(path + ": id '" + id + "' is retired and may not be reused");
            }
        }
        return new FileWalk(path, vectors.size(), true);
    }

    private static boolean wellFormed(String id, String prefix) {
        return id.startsWith(prefix) && SLUG.matcher(id.substring(prefix.length())).matches();
    }

    private static void expect(
            List<String> problems, String path, String field, JsonNode doc, String want) {
        String got = doc.path(field).asText(null);
        if (!want.equals(got)) {
            problems.add(path + ": " + field + " is " + got + ", expected " + want);
        }
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every JDK provides SHA-256", e);
        }
    }

    /** {@code ./gradlew -q vectors}. Exit status 1 on any problem. */
    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("usage: VectorHarness <vectors-dir>");
            System.exit(2);
        }
        Walk walk = walk(Path.of(args[0]));
        System.out.printf("vector suite %s: %d files, %d vectors walked%n",
                walk.suiteVersion(), walk.files().size(), walk.vectors());
        for (FileWalk f : walk.files()) {
            System.out.printf("  %-30s %s%n", f.path(),
                    f.walked() ? String.format("%3d", f.vectors()) : "not walked (see PROBLEM)");
        }
        System.out.println("held_out: " + (walk.heldOut().isEmpty() ? "none" : walk.heldOut()));
        walk.problems().forEach(p -> System.err.println("PROBLEM " + p));
        if (!walk.problems().isEmpty()) {
            System.exit(1);
        }
    }
}
