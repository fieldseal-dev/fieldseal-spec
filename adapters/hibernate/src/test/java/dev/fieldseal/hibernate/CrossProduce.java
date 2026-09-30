package dev.fieldseal.hibernate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.fieldseal.hibernate.fixture.AllTypes;
import dev.fieldseal.hibernate.fixture.Patient;
import dev.fieldseal.hibernate.fixture.Person;
import dev.fieldseal.hibernate.fixture.TenantDoc;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import org.hibernate.Session;
import org.hibernate.SessionFactory;

/**
 * Cross-language producer: rows written by <b>Hibernate</b>, read by any core (docs/29 §8,
 * docs/14 §3).
 *
 * <p>The core producers already show that a value one core encrypts, another decrypts. What they
 * cannot show is that the bytes this adapter puts in a column are those bytes, because three
 * decisions between the application value and the stored column are the adapter's: the codec
 * (spec §3.6), the storage form (raw {@code bytea}/{@code varbinary}), and the context, assembled
 * from {@code @FieldsealTable}, {@code @Encrypted} and the session's tenant identifier. So this
 * writes rows through the real session path, with the core's runtime CSPRNG and no test mode,
 * reads the columns back over JDBC, and emits a standard {@code fieldseal-vectors/cross/v2}
 * document, which every core consumer reads unmodified.
 *
 * <p>The index half is the more valuable assertion: an index this adapter wrote that a core
 * derives differently is a silent lookup miss. The declaration in each index case is the
 * entity's own {@code @BlindIndex}, read back from what the integrator resolved.
 *
 * <p>Key material is resolved by {@code key_ref} against {@code vectors/keys/test-keys.json}.
 */
public final class CrossProduce {
    private CrossProduce() {}

    static final String KEY_REF = TestSupport.KEY_REF;

    public static void main(String[] args) throws IOException {
        if (args.length != 2 || !args[0].equals("--out")) {
            System.err.println("usage: CrossProduce --out <file>");
            System.exit(2);
        }
        if ("1".equals(System.getenv("FIELDSEAL_TEST_MODE"))) {
            // The producer is the production path; test mode is the injection seam's.
            System.err.println("CrossProduce refuses to run with FIELDSEAL_TEST_MODE=1");
            System.exit(2);
        }
        ObjectNode doc = produce();
        Path out = Path.of(args[1]);
        if (out.getParent() != null) {
            Files.createDirectories(out.getParent());
        }
        Files.writeString(out, TestSupport.JSON.writerWithDefaultPrettyPrinter()
                .writeValueAsString(doc) + "\n");
        System.err.printf("wrote %s (%d cases, %d index cases, producer hibernate@%s)%n", out,
                doc.get("cases").size(), doc.get("index_cases").size(),
                doc.get("producer").get("commit").asText());
    }

    static ObjectNode produce() {
        try (SessionFactory sf = TestSupport.sessionFactory(Patient.class, Person.class,
                TenantDoc.class, AllTypes.class)) {
            return produce(sf);
        }
    }

    static ObjectNode produce(SessionFactory sf) {
        FieldsealRuntime rt = runtime(sf);
        ArrayNode cases = TestSupport.JSON.createArrayNode();
        ArrayNode indexCases = TestSupport.JSON.createArrayNode();

        Patient ada = new Patient("ada@example.com", "a note", 36);
        persist(sf, null, ada);
        cases.add(envelope(sf, rt, "text-email", "Patient", "email", ada.id,
                utf8("ada@example.com"), null));

        // Not ASCII: the codec's UTF-8 is what the consumer decodes.
        Patient renee = new Patient("renee@example.com", "日本語とEmoji 🔐", 41);
        persist(sf, null, renee);
        cases.add(envelope(sf, rt, "text-non-ascii", "Patient", "note", renee.id,
                utf8("日本語とEmoji 🔐"), null));

        // An Integer: the adapter decides it is b"45" (spec §3.6).
        Patient grace = new Patient("grace@example.com", "g", 45);
        persist(sf, null, grace);
        cases.add(envelope(sf, rt, "non-text-integer", "Patient", "age", grace.id, utf8("45"),
                null));

        // The empty string is a value, not an absence (spec §10.2).
        Patient empty = new Patient("empty@example.com", "", 1);
        persist(sf, null, empty);
        cases.add(envelope(sf, rt, "text-empty", "Patient", "note", empty.id, new byte[0],
                null));

        // The other renderings this adapter owns, one each.
        AllTypes t = new AllTypes();
        t.amount = new BigDecimal("1.50");
        t.ratio = 0.1;
        t.flag = Boolean.TRUE;
        t.born = LocalDate.of(1815, 12, 10);
        t.seen = Instant.parse("2026-09-29T12:00:00.123456Z");
        t.at = Instant.parse("2026-09-29T12:00:00Z").atOffset(ZoneOffset.ofHours(2))
                .truncatedTo(ChronoUnit.MICROS);
        t.blob = new byte[] {0, 1, 2, (byte) 0xff};
        persist(sf, null, t);
        cases.add(envelope(sf, rt, "decimal", "AllTypes", "amount", t.id, utf8("1.5"), null));
        cases.add(envelope(sf, rt, "float", "AllTypes", "ratio", t.id, utf8("0.1"), null));
        cases.add(envelope(sf, rt, "boolean", "AllTypes", "flag", t.id, utf8("true"), null));
        cases.add(envelope(sf, rt, "date", "AllTypes", "born", t.id, utf8("1815-12-10"), null));
        cases.add(envelope(sf, rt, "datetime", "AllTypes", "seen", t.id,
                utf8("2026-09-29T12:00:00.123456Z"), null));
        cases.add(envelope(sf, rt, "datetime-offset", "AllTypes", "at", t.id,
                utf8("2026-09-29T12:00:00.000000Z"), null));
        cases.add(envelope(sf, rt, "bytes", "AllTypes", "blob", t.id, t.blob, null));

        // Tenant-bound: the tenant is the session's tenant identifier (docs/29 §4).
        TenantDoc doc = new TenantDoc("tenant-scoped body", "ada@example.com");
        persist(sf, "tenant-0001", doc);
        cases.add(envelope(sf, rt, "tenant-bound", "TenantDoc", "body", doc.id,
                utf8("tenant-scoped body"), utf8("tenant-0001")));

        // A column whose index is bucketed: the envelope is ordinary.
        Person person = new Person("Ada Lovelace");
        persist(sf, null, person);
        cases.add(envelope(sf, rt, "indexed-column", "Person", "legalName", person.id,
                utf8("Ada Lovelace"), null));

        // ---- the index half ----
        indexCases.add(index(sf, rt, "email-exact", "Patient", "emailIndex", ada.id,
                "ada@example.com", null));
        Patient upper = new Patient("ADA@EXAMPLE.COM", "n", 2);
        persist(sf, null, upper);
        indexCases.add(index(sf, rt, "email-fold", "Patient", "emailIndex", upper.id,
                "ADA@EXAMPLE.COM", null));
        Patient accented = new Patient("renée@example.com", "n", 3);
        persist(sf, null, accented);
        indexCases.add(index(sf, rt, "email-non-ascii", "Patient", "emailIndex", accented.id,
                "renée@example.com", null));
        indexCases.add(index(sf, rt, "legal-name", "Person", "legalNameIndex", person.id,
                "Ada Lovelace", null));
        // The case only an adapter can produce: the listener stored the reserved marker by
        // itself, because the column declares BUCKET. U+0378 is unassigned in every version.
        Person bucketed = new Person("Ada͸ Lovelace");
        persist(sf, null, bucketed);
        indexCases.add(index(sf, rt, "bucket-marker", "Person", "legalNameIndex", bucketed.id,
                null, null));
        indexCases.add(index(sf, rt, "tenant-bound", "TenantDoc", "handleIndex", doc.id,
                "ada@example.com", utf8("tenant-0001")));

        JsonNode key = TestSupport.key();
        ObjectNode root = TestSupport.JSON.createObjectNode();
        root.put("schema", "fieldseal-vectors/cross/v2");
        ObjectNode producer = root.putObject("producer");
        producer.put("implementation", "hibernate");
        producer.put("version", "0.0.0-SNAPSHOT");
        producer.put("commit", commit());
        ArrayNode limits = producer.putArray("limitations");
        limits.addObject().put("shape", "row_id-present").put("reason", "L3-row binding is "
                + "not in v0: the read path has no id where it decrypts (docs/29 §4)");
        limits.addObject().put("shape", "normalizer:identity, normalizer:digits-only-v1")
                .put("reason", "every indexed column in this fixture declares "
                        + "nfc-casefold-v1; the other two are covered by the core producers");
        producer.put("produced_at", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
        root.put("suite_id", key.get("suite_id").asText());
        root.set("index_cases", indexCases);
        root.set("cases", cases);
        return root;
    }

    static FieldsealRuntime runtime(SessionFactory sf) {
        return ((FieldsealSqmTranslatorFactory) sf.unwrap(
                org.hibernate.engine.spi.SessionFactoryImplementor.class)
                .getSessionFactoryOptions().getCustomSqmTranslatorFactory()).runtime();
    }

    private static void persist(SessionFactory sf, String tenant, Object entity) {
        try (Session s = tenant == null ? sf.openSession()
                : sf.withOptions().tenantIdentifier((Object) tenant).openSession()) {
            s.beginTransaction();
            s.persist(entity);
            s.getTransaction().commit();
        }
    }

    private static ObjectNode envelope(SessionFactory sf, FieldsealRuntime rt, String id,
            String entity, String attribute, Object pk, byte[] plaintext, byte[] tenant) {
        ColumnSpec c = rt.column(entityName(sf, entity), attribute);
        ObjectNode n = TestSupport.JSON.createObjectNode();
        n.put("id", "cross/hibernate/" + id);
        n.put("key_ref", KEY_REF);
        ObjectNode ctx = n.putObject("context");
        ctx.put("table_uuid", hex(c.tableUuid()));
        ctx.put("column_uuid", hex(c.columnUuid()));
        ctx.put("tenant_id", tenant == null ? null : hex(tenant));
        ctx.putNull("row_id");
        ctx.put("purpose", "encrypt");
        n.put("plaintext", hex(plaintext));
        n.put("envelope", hex(raw(sf, entity, attribute, pk)));
        return n;
    }

    private static ObjectNode index(SessionFactory sf, FieldsealRuntime rt, String id,
            String entity, String attribute, Object pk, String value, byte[] tenant) {
        IndexSpec ix = rt.index(entityName(sf, entity), attribute);
        var d = ix.declaration;
        ObjectNode n = TestSupport.JSON.createObjectNode();
        n.put("id", "cross/hibernate/index/" + id);
        n.put("key_ref", KEY_REF);
        ObjectNode decl = n.putObject("declaration");
        decl.put("index_id", d.indexId());
        decl.put("idf", d.idf().id());
        decl.putObject("idf_params");
        decl.put("normalize", d.normalize().id());
        decl.put("truncate_bits", d.truncateBits());
        decl.put("projected_population", d.projectedPopulation());
        decl.put("on_unindexable", d.onUnindexable().id());
        if (d.unindexableOverride() != null) {
            decl.putObject("unindexable_override")
                    .put("reason", d.unindexableOverride().reason())
                    .put("approved_by", d.unindexableOverride().approvedBy())
                    .put("date", d.unindexableOverride().date().toString());
        }
        ObjectNode ctx = n.putObject("context");
        ctx.put("table_uuid", hex(ix.source.tableUuid()));
        ctx.put("column_uuid", hex(ix.source.columnUuid()));
        ctx.put("tenant_id", tenant == null ? null : hex(tenant));
        ctx.putNull("row_id");
        ctx.put("purpose", "index:" + d.indexId());
        if (value == null) {
            n.put("value_marker", true);
        } else {
            n.put("value_text", value);
        }
        n.put("index", hex(raw(sf, entity, attribute, pk)));
        return n;
    }

    private static String entityName(SessionFactory sf, String simple) {
        Class<?> type = switch (simple) {
            case "Patient" -> Patient.class;
            case "Person" -> Person.class;
            case "TenantDoc" -> TenantDoc.class;
            case "AllTypes" -> AllTypes.class;
            default -> throw new IllegalArgumentException(simple);
        };
        return sf.unwrap(org.hibernate.engine.spi.SessionFactoryImplementor.class)
                .getMappingMetamodel().getEntityDescriptor(type).getEntityName();
    }

    /** The column as the database holds it: over JDBC, never through the type, which decrypts. */
    static byte[] raw(SessionFactory sf, String table, String column, Object pk) {
        try (Session s = sf.openSession()) {
            return s.doReturningWork(c -> {
                try (PreparedStatement ps = c.prepareStatement(
                        "select " + column + " from " + table + " where id = ?")) {
                    ps.setObject(1, pk);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            throw new IllegalStateException(table + " has no row " + pk);
                        }
                        return rs.getBytes(1);
                    }
                }
            });
        }
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    private static String commit() {
        String sha = System.getenv("GITHUB_SHA");
        if (sha != null && !sha.isEmpty()) {
            return sha;
        }
        try {
            Process p = new ProcessBuilder("git", "rev-parse", "HEAD").redirectErrorStream(true)
                    .start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                    .trim();
            return p.waitFor() == 0 ? out : "unknown";
        } catch (IOException | InterruptedException e) {
            return "unknown";
        }
    }
}
