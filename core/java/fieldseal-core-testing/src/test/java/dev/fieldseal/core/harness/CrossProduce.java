package dev.fieldseal.core.harness;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.IndexDeclaration;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

/**
 * The Java core's cross producer (docs/08 §4.7; docs/14 §3; docs/27 §8, S7): {@code ./gradlew -q
 * crossProduce --args="--out <file>"}. It encrypts every {@code cases} entry of {@code
 * cross/corpus.json} through production {@link Fieldseal#encrypt}, so {@code msg_seed} and the
 * nonce come from the client's own {@code SecureRandom}, and derives every {@code index_cases}
 * entry through a client built with the case's declaration. The document is {@code cross/v2}.
 *
 * <p>Two checks keep "the production path" from being a claim only. The producer refuses to run
 * in a process armed with {@code FIELDSEAL_TEST_MODE=1}, where the testing artifact's seam would
 * hand out {@code encrypt_with_materials} ({@link #refuseArmed}); and before it writes anything it
 * checks that no two of its envelopes share a {@code msg_seed} or a nonce ({@link #fresh}), which
 * is what fixed entropy would look like.
 */
public final class CrossProduce {

    static final String IMPLEMENTATION = "java";

    private CrossProduce() {}

    /** The cross document for {@code corpus}; {@code warn} receives the clients' warnings. */
    static ObjectNode produce(Path vectors, Consumer<String> warn) throws IOException {
        JsonNode corpus = Cross.support(vectors, "cross/corpus.json");
        Cross.expect(corpus, "schema", "fieldseal-vectors/cross-corpus/v1");
        Map<String, Cross.Key> keys = Cross.keys(vectors);
        String suiteId = Cross.text(corpus, "suite_id");
        int suite = Cross.suite(suiteId);

        ObjectNode doc = Cross.JSON.createObjectNode();
        doc.put("schema", Cross.V2);
        ObjectNode producer = doc.putObject("producer");
        producer.put("implementation", IMPLEMENTATION);
        producer.put("version", System.getProperty("fieldseal.version", "unknown"));
        producer.put("commit", ConformanceReport.implementation(vectors).path("commit").asText());
        producer.put("produced_at", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
        doc.put("suite_id", suiteId);

        Map<String, Fieldseal> clients = new HashMap<>();
        ArrayNode cases = doc.putArray("cases");
        for (JsonNode c : corpus.path("cases")) {
            Cross.Key k = Cross.key(keys, c);
            Fieldseal client = clients.computeIfAbsent(k.ref(),
                    r -> Cross.client(k, suite, List.of(), warn));
            byte[] plaintext = Cross.hex(c, "plaintext");
            byte[] envelope = client.encrypt(plaintext, Cross.context(c, "encrypt"));
            ObjectNode out = cases.addObject();
            out.put("id", "cross/" + IMPLEMENTATION + "/" + Cross.text(c, "case"));
            out.put("key_ref", k.ref());
            out.set("context", c.path("context"));
            out.put("plaintext", Cross.hex(plaintext));
            out.put("envelope", Cross.hex(envelope));
        }
        if (cases.isEmpty()) {
            throw new IllegalArgumentException("cross/corpus.json has no cases");
        }

        ArrayNode indexCases = doc.putArray("index_cases");
        for (JsonNode c : corpus.path("index_cases")) {
            indexCases.add(index(c, keys, suite, warn));
        }
        if (indexCases.isEmpty()) {
            throw new IllegalArgumentException("cross/corpus.json has no index_cases");
        }
        fresh(cases);
        return doc;
    }

    private static ObjectNode index(JsonNode c, Map<String, Cross.Key> keys, int suite,
            Consumer<String> warn) {
        Cross.Key k = Cross.key(keys, c);
        String indexId = Cross.text(c.path("declaration"), "index_id");
        FieldContext ctx = Cross.context(c, "index:" + indexId);
        IndexDeclaration declaration = Cross.declaration(c.path("declaration"), ctx);
        Fieldseal client = Cross.client(k, suite, List.of(declaration), warn);
        ObjectNode out = Cross.JSON.createObjectNode();
        out.put("id", "cross/" + IMPLEMENTATION + "/index/" + Cross.text(c, "case"));
        out.put("key_ref", k.ref());
        out.set("declaration", c.path("declaration"));
        out.set("context", c.path("context"));
        byte[] index;
        if (c.has("value_text")) {
            out.put("value_text", Cross.text(c, "value_text"));
            index = client.blindIndex(Cross.text(c, "value_text"), ctx.forIndex(indexId));
        } else if (c.has("value_bytes")) {
            out.put("value_bytes", Cross.text(c, "value_bytes"));
            index = client.blindIndex(Cross.hex(c, "value_bytes"), ctx.forIndex(indexId));
        } else if (c.path("value_marker").asBoolean(false)) {
            out.put("value_marker", true);
            index = client.unindexableMarker(ctx.forIndex(indexId));
        } else {
            throw new IllegalArgumentException(Cross.text(c, "case") + ": no value");
        }
        out.put("index", Cross.hex(index));
        return out;
    }

    /** No two envelopes share a {@code msg_seed} or a nonce (spec §3.1, §4.4). */
    static void fresh(ArrayNode cases) {
        Set<String> seeds = new TreeSet<>();
        Set<String> nonces = new TreeSet<>();
        for (JsonNode c : cases) {
            byte[] e = Cross.hex(c, "envelope");
            if (!seeds.add(Cross.hex(Arrays.copyOfRange(e, Cross.SEED_AT, Cross.NONCE_AT)))
                    || !nonces.add(Cross.hex(Arrays.copyOfRange(e, Cross.NONCE_AT,
                            Cross.NONCE_END)))) {
                throw new IllegalStateException(c.path("id").asText()
                        + " repeats a msg_seed or nonce: the entropy is not fresh");
            }
        }
    }

    /** The production path is not the armed one: refuse {@code FIELDSEAL_TEST_MODE=1}. */
    static void refuseArmed(Map<String, String> env) {
        if ("1".equals(env.get("FIELDSEAL_TEST_MODE"))) {
            throw new IllegalStateException("FIELDSEAL_TEST_MODE=1 is set: the cross producer runs"
                    + " the production path, in a process where encrypt_with_materials is unarmed");
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2 || !args[0].equals("--out")) {
            System.err.println("usage: CrossProduce --out <file>");
            System.exit(2);
        }
        refuseArmed(System.getenv());
        Path vectors = Path.of(System.getProperty("fieldseal.vectors")).toAbsolutePath()
                .normalize();
        Set<String> warnings = new TreeSet<>();
        ObjectNode doc = produce(vectors, warnings::add);
        Path out = Path.of(args[1]).toAbsolutePath();
        Files.writeString(out, Cross.JSON.writeValueAsString(doc) + "\n");
        // The static provider's warning, once: this is test key material (docs/08 §4.7).
        warnings.forEach(w -> System.err.println("warning: " + w));
        System.err.printf("cross: java produced %d envelope and %d index cases into %s%n",
                doc.path("cases").size(), doc.path("index_cases").size(), out);
    }
}
