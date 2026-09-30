package dev.fieldseal.hibernate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.KeyProviders;
import dev.fieldseal.core.ReadMode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.resource.jdbc.spi.StatementInspector;

/** Session factories over H2 or Postgres (FIELDSEAL_TEST_DB), keyed from vectors/keys. */
final class TestSupport {
    private TestSupport() {}

    static final Path VECTORS = Path.of(System.getProperty("fieldseal.vectors"));
    static final ObjectMapper JSON = new ObjectMapper();
    static final String KEY_REF = "tenant-a-dek-v1";
    private static final AtomicInteger DB = new AtomicInteger();

    /** Every SQL statement Hibernate prepared, in order, since the last {@link #clearSql()}. */
    static final List<String> SQL = Collections.synchronizedList(new ArrayList<>());

    /** Captures statements for the behaviour pins (docs/29 §2.1). */
    public static final class Capture implements StatementInspector {
        private static final long serialVersionUID = 1L;

        @Override
        public String inspect(String sql) {
            SQL.add(sql);
            return sql;
        }
    }

    static void clearSql() {
        SQL.clear();
    }

    static List<String> sql(String prefix) {
        synchronized (SQL) {
            return SQL.stream().filter(s -> s.toLowerCase().startsWith(prefix)).toList();
        }
    }

    static String db() {
        String db = System.getenv("FIELDSEAL_TEST_DB");
        return db == null ? "h2" : db;
    }

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    static JsonNode key() {
        try {
            return JSON.readTree(Files.readString(VECTORS.resolve("keys/test-keys.json")))
                    .get("keys").get(KEY_REF);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The shared public test key, as a configurer. */
    static FieldsealConfigurer configurer() {
        return configurer(ReadMode.STRICT);
    }

    static FieldsealConfigurer configurer(ReadMode mode) {
        JsonNode k = key();
        return b -> b.keyProvider(KeyProviders.staticKeys(hex(k.get("tenant_dek").asText()),
                        hex(k.get("tenant_index_key").asText()), hex(k.get("key_id").asText())))
                .allowedSuites(Set.of(0xFF01)).writeSuite(0xFF01).readMode(mode)
                .armProvisionalSuites(true).onWarning(w -> {});
    }

    /** A client over the same key, built independently of any session factory. */
    static Fieldseal independentClient() {
        Fieldseal.Builder b = Fieldseal.builder();
        configurer().configure(b);
        return b.build();
    }

    static SessionFactory sessionFactory(Class<?>... entities) {
        return sessionFactory(Map.of(), entities);
    }

    static SessionFactory sessionFactory(Map<String, Object> extra, Class<?>... entities) {
        Map<String, Object> settings = new HashMap<>(baseSettings());
        FieldsealSettings.apply(settings, configurer());
        settings.putAll(extra);
        return build(settings, entities);
    }

    /** The database and schema settings, with no Fieldseal settings at all. */
    static Map<String, Object> baseSettings() {
        Map<String, Object> s = new HashMap<>();
        if (db().equals("postgres")) {
            String host = env("PGHOST", "127.0.0.1");
            s.put("hibernate.connection.url", "jdbc:postgresql://" + host + ":"
                    + env("PGPORT", "5432") + "/" + env("PGDATABASE", "fieldseal_test"));
            s.put("hibernate.connection.username", env("PGUSER", "postgres"));
            s.put("hibernate.connection.password", env("PGPASSWORD", "postgres"));
        } else {
            s.put("hibernate.connection.url",
                    "jdbc:h2:mem:fs" + DB.incrementAndGet() + ";DB_CLOSE_DELAY=-1");
        }
        s.put("hibernate.hbm2ddl.auto", "create-drop");
        s.put("hibernate.session_factory.statement_inspector", Capture.class.getName());
        s.put("hibernate.jdbc.batch_size", "20");
        return s;
    }

    static SessionFactory build(Map<String, Object> settings, Class<?>... entities) {
        StandardServiceRegistry ssr =
                new StandardServiceRegistryBuilder().applySettings(settings).build();
        try {
            MetadataSources sources = new MetadataSources(ssr);
            for (Class<?> c : entities) {
                sources.addAnnotatedClass(c);
            }
            return sources.buildMetadata().buildSessionFactory();
        } catch (RuntimeException e) {
            StandardServiceRegistryBuilder.destroy(ssr);
            throw e;
        }
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isEmpty() ? fallback : v;
    }

    /** The first exception of {@code type} in {@code t}'s cause chain, or null. */
    static <X extends Throwable> X causeOf(Throwable t, Class<X> type) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (type.isInstance(c)) {
                return type.cast(c);
            }
        }
        return null;
    }
}
