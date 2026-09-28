package dev.fieldseal.core.harness;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.IndexDeclaration;
import dev.fieldseal.core.errors.FieldsealError;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

/**
 * The Java core's cross consumer (docs/08 §4.7; docs/14 §3; docs/27 §8, S7): {@code ./gradlew -q
 * crossConsume --args="<cross-*.json …> --verdict <file>"}. For every producer's document it
 * decrypts each envelope case and compares the plaintext byte for byte, and re-derives each index
 * case and compares the index byte for byte. The verdict records one pair per producer and half,
 * {@code envelope} or {@code index}, since the two fail for different reasons (docs/14 §3); the
 * run exits 1 if any case fails.
 *
 * <p>What makes a case fail, beyond a wrong byte: a {@code schema} other than {@code cross/v1}
 * or {@code cross/v2}, and a v1 document carrying {@code index_cases} (docs/08 §4.7: a consumer
 * that read past either would skip the index half and stay green); a {@code purpose} that is not
 * {@code "index:" + index_id}; not exactly one of {@code value_text}, {@code value_bytes} and
 * {@code value_marker}, or {@code value_bytes} under a normalizer other than {@code identity};
 * and an envelope that repeats another envelope's {@code msg_seed} or nonce in the same document,
 * which is what a producer off the production path looks like. A document under {@code 0xFF02},
 * the one suite this core does not build, is skipped, and the skip is in the verdict (docs/14
 * §3); any other suite this core cannot read is a failure.
 */
public final class CrossConsume {

    /** Registered and not built by this core (docs/27 §4, unimplemented-registered-suite). */
    private static final int UNBUILT = 0xFF02;

    private CrossConsume() {}

    /** One producer document and one half, as the verdict reports it. */
    record Pair(String producer, String file, String half, int pass, List<String> failures,
            int skipped, List<String> notes) {}

    /** Every pair for the document at {@code file}. */
    static List<Pair> consume(Path vectors, Path file, Consumer<String> warn) throws IOException {
        String name = file.getFileName().toString();
        JsonNode doc;
        String producer;
        try {
            doc = Cross.JSON.readTree(file.toFile());
            producer = Cross.text(doc.path("producer"), "implementation");
        } catch (IOException | IllegalArgumentException e) {
            return List.of(new Pair("?", name, "document", 0, List.of(name + ": " + e.getMessage()),
                    0, List.of()));
        }
        List<String> documentProblems = new ArrayList<>();
        String schema = doc.path("schema").asText(null);
        if (!Cross.V1.equals(schema) && !Cross.V2.equals(schema)) {
            documentProblems.add("schema " + doc.path("schema") + " is not " + Cross.V1 + " or "
                    + Cross.V2);
        } else if (Cross.V1.equals(schema) && doc.has("index_cases")) {
            documentProblems.add(Cross.V1 + " carries index_cases");
        } else if (Cross.V2.equals(schema) && (!doc.path("index_cases").isArray()
                || doc.path("index_cases").isEmpty())) {
            // v2 means "this producer carries an index half": an empty one would pass unchecked.
            documentProblems.add(Cross.V2 + " without index cases");
        }
        if (!doc.path("cases").isArray() || doc.path("cases").isEmpty()) {
            documentProblems.add("no envelope cases");
        }
        int suite = -1;
        try {
            suite = Cross.suite(Cross.text(doc, "suite_id"));
        } catch (IllegalArgumentException e) {
            documentProblems.add(e.getMessage());
        }
        if (!documentProblems.isEmpty()) {
            return List.of(new Pair(producer, name, "document", 0, documentProblems, 0, List.of()));
        }
        List<String> notes = new ArrayList<>();
        JsonNode limits = doc.path("producer").path("limitations");
        if (!limits.isMissingNode()) {
            if (!limits.isArray()) {
                return List.of(new Pair(producer, name, "document", 0,
                        List.of("producer.limitations is not an array"), 0, List.of()));
            }
            limits.forEach(l -> notes.add("limitation: " + l.path("shape").asText() + " ("
                    + l.path("reason").asText() + ")"));
        }
        JsonNode indexCases = doc.path("index_cases");
        if (suite == UNBUILT) {
            String why = "suite 0xFF02 is registered and not built by this core";
            return List.of(
                    new Pair(producer, name, "envelope", 0, List.of(), doc.path("cases").size(),
                            List.of(why)),
                    new Pair(producer, name, "index", 0, List.of(), indexCases.size(),
                            List.of(why)));
        }

        Map<String, Cross.Key> keys = Cross.keys(vectors);
        List<Pair> pairs = new ArrayList<>();
        pairs.add(envelopes(producer, name, doc.path("cases"), keys, suite, warn, notes));
        if (Cross.V2.equals(schema)) {
            pairs.add(indexes(producer, name, indexCases, keys, suite, warn));
        }
        return pairs;
    }

    private static Pair envelopes(String producer, String file, JsonNode cases,
            Map<String, Cross.Key> keys, int suite, Consumer<String> warn, List<String> notes) {
        Map<String, Fieldseal> clients = new HashMap<>();
        Map<String, String> seeds = new HashMap<>();
        Map<String, String> nonces = new HashMap<>();
        Set<String> unread = new TreeSet<>();
        List<String> failures = new ArrayList<>();
        int pass = 0;
        for (JsonNode c : cases) {
            String id = c.path("id").asText("(no id)");
            try {
                Cross.Key k = Cross.key(keys, c);
                Fieldseal client = clients.computeIfAbsent(k.ref(),
                        r -> Cross.client(k, suite, List.of(), warn));
                byte[] envelope = Cross.hex(c, "envelope");
                byte[] got = client.decrypt(envelope, Cross.context(c, "encrypt"));
                if (!Arrays.equals(Cross.hex(c, "plaintext"), got)) {
                    throw new IllegalArgumentException("decrypts to " + Cross.hex(got)
                            + ", the producer recorded " + Cross.text(c, "plaintext"));
                }
                // Decryption succeeded, so the envelope is long enough to hold both fields.
                String seed = Cross.hex(Arrays.copyOfRange(envelope, Cross.SEED_AT,
                        Cross.NONCE_AT));
                String nonce = Cross.hex(Arrays.copyOfRange(envelope, Cross.NONCE_AT,
                        Cross.NONCE_END));
                String seedTwin = seeds.putIfAbsent(seed, id);
                String nonceTwin = nonces.putIfAbsent(nonce, id);
                if (seedTwin != null || nonceTwin != null) {
                    throw new IllegalArgumentException("repeats the "
                            + (seedTwin != null ? "msg_seed of " + seedTwin
                                    : "nonce of " + nonceTwin)
                            + ": not the production path's fresh entropy");
                }
                Set<String> extra = Cross.fields(c);
                extra.removeAll(Set.of("id", "key_ref", "context", "plaintext", "envelope"));
                unread.addAll(extra);
                pass++;
            } catch (RuntimeException e) {
                failures.add(failure(id, e));
            }
        }
        if (!unread.isEmpty()) {
            notes.add("case fields this consumer does not read: " + unread);
        }
        return new Pair(producer, file, "envelope", pass, failures, 0, List.copyOf(notes));
    }

    private static Pair indexes(String producer, String file, JsonNode cases,
            Map<String, Cross.Key> keys, int suite, Consumer<String> warn) {
        List<String> failures = new ArrayList<>();
        Set<String> unread = new TreeSet<>();
        int pass = 0;
        for (JsonNode c : cases) {
            String id = c.path("id").asText("(no id)");
            try {
                Cross.Key k = Cross.key(keys, c);
                JsonNode d = c.path("declaration");
                String indexId = Cross.text(d, "index_id");
                // docs/08 §4.7: purpose and index_id are redundant on purpose, and must agree.
                FieldContext ctx = Cross.context(c, "index:" + indexId);
                IndexDeclaration declaration = Cross.declaration(d, ctx);
                Fieldseal client = Cross.client(k, suite, List.of(declaration), warn);
                List<String> values = new ArrayList<>(List.of("value_text", "value_bytes",
                        "value_marker"));
                values.removeIf(v -> !c.has(v));
                if (values.size() != 1) {
                    throw new IllegalArgumentException("carries " + values
                            + ", not exactly one of value_text, value_bytes, value_marker");
                }
                FieldContext at = ctx.forIndex(indexId);
                byte[] want = Cross.hex(c, "index");
                byte[] got = switch (values.get(0)) {
                    case "value_text" -> client.blindIndex(Cross.text(c, "value_text"), at);
                    case "value_bytes" -> {
                        if (!"identity".equals(Cross.text(d, "normalize"))) {
                            throw new IllegalArgumentException("value_bytes under normalizer '"
                                    + d.path("normalize").asText() + "', not identity");
                        }
                        yield client.blindIndex(Cross.hex(c, "value_bytes"), at);
                    }
                    default -> {
                        if (!c.path("value_marker").isBoolean()
                                || !c.path("value_marker").asBoolean()) {
                            throw new IllegalArgumentException("value_marker is not true");
                        }
                        yield client.unindexableMarker(at);
                    }
                };
                if (!Arrays.equals(want, got)) {
                    throw new IllegalArgumentException("derives " + Cross.hex(got)
                            + ", the producer recorded " + Cross.hex(want));
                }
                Set<String> extra = Cross.fields(c);
                extra.removeAll(Set.of("id", "key_ref", "declaration", "context", "index",
                        values.get(0)));
                unread.addAll(extra);
                pass++;
            } catch (RuntimeException e) {
                failures.add(failure(id, e));
            }
        }
        List<String> notes = unread.isEmpty() ? List.of()
                : List.of("case fields this consumer does not read: " + unread);
        return new Pair(producer, file, "index", pass, failures, 0, notes);
    }

    /** A case's failure: the §9 code first where the core raised one. */
    private static String failure(String id, RuntimeException e) {
        return id + ": " + (e instanceof FieldsealError f ? f.code() + " " + f.getMessage()
                : e.toString());
    }

    static ObjectNode verdict(List<Pair> pairs) {
        ObjectNode v = Cross.JSON.createObjectNode();
        v.put("consumer", CrossProduce.IMPLEMENTATION);
        int pass = 0;
        int fail = 0;
        int skipped = 0;
        ArrayNode out = v.putArray("pairs");
        for (Pair p : pairs) {
            ObjectNode o = out.addObject();
            o.put("producer", p.producer());
            o.put("file", p.file());
            o.put("half", p.half());
            o.put("pass", p.pass());
            o.put("fail", p.failures().size());
            o.put("skipped", p.skipped());
            p.failures().forEach(o.putArray("failures")::add);
            p.notes().forEach(o.putArray("notes")::add);
            pass += p.pass();
            fail += p.failures().size();
            skipped += p.skipped();
        }
        ObjectNode s = v.putObject("summary");
        s.put("pairs", pairs.size());
        s.put("pass", pass);
        s.put("fail", fail);
        s.put("skipped", skipped);
        return v;
    }

    public static void main(String[] args) throws IOException {
        int at = Arrays.asList(args).indexOf("--verdict");
        if (at < 1 || at != args.length - 2) {
            System.err.println("usage: CrossConsume <cross-*.json …> --verdict <file>");
            System.exit(2);
        }
        Path vectors = Path.of(System.getProperty("fieldseal.vectors")).toAbsolutePath()
                .normalize();
        Set<String> warnings = new TreeSet<>();
        List<Pair> pairs = new ArrayList<>();
        for (int i = 0; i < at; i++) {
            pairs.addAll(consume(vectors, Path.of(args[i]).toAbsolutePath(), warnings::add));
        }
        ObjectNode verdict = verdict(pairs);
        Files.writeString(Path.of(args[at + 1]).toAbsolutePath(),
                Cross.JSON.writeValueAsString(verdict) + "\n");
        warnings.forEach(w -> System.err.println("warning: " + w));
        for (Pair p : pairs) {
            System.err.printf("%-4s %s -> java, %s: %d pass, %d fail, %d skipped%n",
                    p.failures().isEmpty() ? "ok" : "FAIL", p.producer(), p.half(), p.pass(),
                    p.failures().size(), p.skipped());
            p.failures().forEach(f -> System.err.println("       " + f));
            p.notes().forEach(n -> System.err.println("       note: " + n));
        }
        if (verdict.path("summary").path("fail").asInt() > 0) {
            System.exit(1);
        }
    }
}
