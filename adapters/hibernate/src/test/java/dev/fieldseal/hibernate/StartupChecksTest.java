package dev.fieldseal.hibernate;

import static dev.fieldseal.hibernate.TestSupport.causeOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.core.IndexDeclaration.OnUnindexable;
import dev.fieldseal.hibernate.fixture.Patient;
import jakarta.persistence.Cacheable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.Version;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.hibernate.SessionFactory;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.NaturalId;
import org.hibernate.cfg.QuerySettings;
import org.junit.jupiter.api.Test;

/** docs/29 §5: each check refuses its condition, by id, when the session factory is built. */
class StartupChecksTest {

    static final String T = "018f3c2e-7a1b-7c3d-8e4f-0000000000a1";

    static void refusedWith(String id, Map<String, Object> extra, Class<?>... entities) {
        var e = assertThrows(RuntimeException.class,
                () -> TestSupport.sessionFactory(extra, entities).close());
        FieldsealConfigurationException c = causeOf(e, FieldsealConfigurationException.class);
        assertNotNull(c, e.toString());
        assertTrue(c.getMessage().startsWith(id + ":"), c.getMessage());
    }

    static void refusedWith(String id, Class<?>... entities) {
        refusedWith(id, Map.of(), entities);
    }

    // ---- FS-H001 --------------------------------------------------------------------------

    @Entity public static class NoTable {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
    }

    @Entity @FieldsealTable("not-a-uuid") public static class BadTable {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
    }

    @Entity @FieldsealTable(T) public static class BadColumn {
        @Id UUID id;
        @Encrypted(column = "018f3c2e7a1b7c3d8e4f0000000000a2") String v;
    }

    @Entity @FieldsealTable(T) public static class DuplicateColumn {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String w;
    }

    @Test
    void fsH001() {
        refusedWith("FS-H001", NoTable.class);
        refusedWith("FS-H001", BadTable.class);
        refusedWith("FS-H001", BadColumn.class);
        refusedWith("FS-H001", DuplicateColumn.class);
    }

    // ---- FS-H002 --------------------------------------------------------------------------

    @Entity @FieldsealTable(T) public static class UniqueEnc {
        @Id UUID id;
        @Column(unique = true)
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
    }

    @Entity @FieldsealTable(T) public static class NaturalEnc {
        @Id UUID id;
        @NaturalId
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
    }

    @Entity @FieldsealTable(T) public static class UniqueIndex {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
        @Column(unique = true)
        @BlindIndex(source = "v", idf = Idf.HMAC_SHA512, normalize = Normalizer.IDENTITY,
                truncateBits = 15, projectedPopulation = 100_000) byte[] vIndex;
    }

    @Entity @FieldsealTable(T) public static class EncId {
        @Id @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String id;
    }

    @Entity @FieldsealTable(T) public static class EncVersion {
        @Id UUID id;
        @Version @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") Long v;
    }

    @Test
    void fsH002() {
        refusedWith("FS-H002", UniqueEnc.class);
        refusedWith("FS-H002", NaturalEnc.class);
        refusedWith("FS-H002", UniqueIndex.class);
        refusedWith("FS-H002", EncId.class);
    }

    @Test
    void fsH002Version() {
        refusedWith("FS-H002", EncVersion.class);
    }

    // ---- FS-H003 --------------------------------------------------------------------------

    @Entity @FieldsealTable(T) public static class OrphanIndex {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
        @BlindIndex(source = "nope", idf = Idf.HMAC_SHA512, normalize = Normalizer.IDENTITY,
                truncateBits = 15, projectedPopulation = 100_000) byte[] vIndex;
    }

    @Entity @FieldsealTable(T) public static class StringIndex {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
        @BlindIndex(source = "v", idf = Idf.HMAC_SHA512, normalize = Normalizer.IDENTITY,
                truncateBits = 15, projectedPopulation = 100_000) String vIndex;
    }

    /** Spec §7.4: b = 16 is out of band for P = 100,000. */
    @Entity @FieldsealTable(T) public static class OutOfBand {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
        @BlindIndex(source = "v", idf = Idf.HMAC_SHA512, normalize = Normalizer.IDENTITY,
                truncateBits = 16, projectedPopulation = 100_000) byte[] vIndex;
    }

    /** Spec §7.6: P below 2^10 without an override. */
    @Entity @FieldsealTable(T) public static class LowCardinality {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
        @BlindIndex(source = "v", idf = Idf.HMAC_SHA512, normalize = Normalizer.IDENTITY,
                truncateBits = 4, projectedPopulation = 100) byte[] vIndex;
    }

    /** docs/09 §7.2: bucket needs its override. */
    @Entity @FieldsealTable(T) public static class BucketNoOverride {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
        @BlindIndex(source = "v", idf = Idf.HMAC_SHA512, normalize = Normalizer.NFC_CASEFOLD_V1,
                truncateBits = 15, projectedPopulation = 100_000,
                onUnindexable = OnUnindexable.BUCKET) byte[] vIndex;
    }

    @Entity @FieldsealTable(T) public static class BadOverrideDate {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
        @BlindIndex(source = "v", idf = Idf.HMAC_SHA512, normalize = Normalizer.IDENTITY,
                truncateBits = 4, projectedPopulation = 100,
                cardinalityOverride = @ReviewedOverride(reason = "r", approvedBy = "a",
                        date = "yesterday")) byte[] vIndex;
    }

    @Test
    void fsH003() {
        refusedWith("FS-H003", OrphanIndex.class);
        refusedWith("FS-H003", StringIndex.class);
        refusedWith("FS-H003", OutOfBand.class);
        refusedWith("FS-H003", LowCardinality.class);
        refusedWith("FS-H003", BucketNoOverride.class);
        refusedWith("FS-H003", BadOverrideDate.class);
    }

    // ---- FS-H004 --------------------------------------------------------------------------

    @Test
    void fsH004NoClient() {
        Map<String, Object> s = new HashMap<>(TestSupport.baseSettings());
        s.put(QuerySettings.SEMANTIC_QUERY_TRANSLATOR,
                FieldsealSqmTranslatorFactory.class.getName());
        var e = assertThrows(RuntimeException.class,
                () -> TestSupport.build(s, Patient.class).close());
        FieldsealConfigurationException c = causeOf(e, FieldsealConfigurationException.class);
        assertNotNull(c, e.toString());
        assertTrue(c.getMessage().startsWith("FS-H004:"), c.getMessage());
    }

    @Test
    void fsH004WrongType() {
        refusedWith("FS-H004", Map.of(FieldsealSettings.CLIENT, "a string"), Patient.class);
    }

    /** A prebuilt client with no indexes: the registry must match the declarations exactly. */
    @Test
    void fsH004RegistryMismatch() {
        refusedWith("FS-H004", Map.of(FieldsealSettings.CLIENT,
                TestSupport.independentClient()), Patient.class);
    }

    /** A configurer that replaces the declared indexes. */
    @Test
    void fsH004ReplacedIndexes() {
        FieldsealConfigurer c = b -> {
            TestSupport.configurer().configure(b);
            b.indexes(List.of());
        };
        refusedWith("FS-H004", Map.of(FieldsealSettings.CLIENT, c), Patient.class);
    }

    /** The matching prebuilt client is accepted. */
    @Test
    void aMatchingPrebuiltClientIsAccepted() {
        SessionFactory probe = TestSupport.sessionFactory(Patient.class);
        Fieldseal.Builder b = Fieldseal.builder();
        TestSupport.configurer().configure(b);
        b.indexes(declared(probe));
        probe.close();
        TestSupport.sessionFactory(Map.of(FieldsealSettings.CLIENT, b.build()), Patient.class)
                .close();
    }

    private static List<dev.fieldseal.core.IndexDeclaration> declared(SessionFactory sf) {
        FieldsealRuntime rt = ((FieldsealSqmTranslatorFactory) sf.unwrap(
                org.hibernate.engine.spi.SessionFactoryImplementor.class)
                .getSessionFactoryOptions().getCustomSqmTranslatorFactory()).runtime();
        List<dev.fieldseal.core.IndexDeclaration> out = new java.util.ArrayList<>();
        for (var p : rt.plans()) {
            for (IndexSpec i : p.indexes()) {
                out.add(i.declaration);
            }
        }
        return out;
    }

    // ---- FS-H005 --------------------------------------------------------------------------

    @Test
    void fsH005() {
        Map<String, Object> s = new HashMap<>(TestSupport.baseSettings());
        s.put(FieldsealSettings.CLIENT, TestSupport.configurer());
        var e = assertThrows(RuntimeException.class,
                () -> TestSupport.build(s, Patient.class).close());
        FieldsealConfigurationException c = causeOf(e, FieldsealConfigurationException.class);
        assertNotNull(c, e.toString());
        assertTrue(c.getMessage().startsWith("FS-H005:"), c.getMessage());
    }

    /** A session factory with no encrypted attribute needs no Fieldseal setting at all. */
    @Entity public static class Plain {
        @Id UUID id;
        String v;
    }

    @Test
    void anUnrelatedSessionFactoryIsLeftAlone() {
        TestSupport.build(new HashMap<>(TestSupport.baseSettings()), Plain.class).close();
    }

    // ---- FS-H006 .. FS-H009 ---------------------------------------------------------------

    @Entity @Cacheable @org.hibernate.annotations.Cache(
            usage = org.hibernate.annotations.CacheConcurrencyStrategy.READ_WRITE)
    @FieldsealTable(T) public static class Cached {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
    }

    @Test
    void fsH006() {
        refusedWith("FS-H006", Cached.class);
    }

    /**
     * The query cache stores decrypted results where no UserType hook runs (#238 review, finding
     * 1). The map-backed region factory is what lets a query cache be switched on at all here.
     */
    @Test
    void fsH010() {
        refusedWith("FS-H010", Map.of("hibernate.cache.use_query_cache", "true",
                "hibernate.cache.use_second_level_cache", "true",
                "hibernate.cache.region.factory_class", RecordingRegionFactory.class.getName()),
                Patient.class);
    }

    /** FS-H010 is the adapter's entities' rule: a factory without them keeps its query cache. */
    @Test
    void aQueryCacheOverAPlainEntityIsLeftAlone() {
        TestSupport.build(withQueryCache(), Plain.class).close();
    }

    private static Map<String, Object> withQueryCache() {
        Map<String, Object> s = new HashMap<>(TestSupport.baseSettings());
        s.put("hibernate.cache.use_query_cache", "true");
        s.put("hibernate.cache.use_second_level_cache", "true");
        s.put("hibernate.cache.region.factory_class", RecordingRegionFactory.class.getName());
        return s;
    }

    @Entity @DynamicUpdate @FieldsealTable(T) public static class Dynamic {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
        @BlindIndex(source = "v", idf = Idf.HMAC_SHA512, normalize = Normalizer.IDENTITY,
                truncateBits = 15, projectedPopulation = 100_000) byte[] vIndex;
    }

    @Test
    void fsH007() {
        refusedWith("FS-H007", Dynamic.class);
    }

    @Embeddable public static class Address {
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a3") String street;
    }

    @Entity @FieldsealTable(T) public static class WithEmbedded {
        @Id UUID id;
        @Embedded Address address;
    }

    @Entity @FieldsealTable(T) public static class WithCollection {
        @Id UUID id;
        @ElementCollection
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a3") List<String> phones;
    }

    @Entity @Inheritance @FieldsealTable(T) public static class Base {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") String v;
    }

    @Entity public static class Derived extends Base {
        String extra;
    }

    @Test
    void fsH008() {
        refusedWith("FS-H008", WithEmbedded.class);
        refusedWith("FS-H008", Base.class, Derived.class);
    }

    @Test
    void fsH008Collection() {
        refusedWith("FS-H008", WithCollection.class);
    }

    @Entity @FieldsealTable(T) public static class Naive {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") LocalDateTime at;
    }

    @Entity @FieldsealTable(T) public static class Binary32 {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") float f;
    }

    @Entity @FieldsealTable(T) public static class Ident {
        @Id UUID id;
        @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-0000000000a2") UUID other;
    }

    @Test
    void fsH009() {
        refusedWith("FS-H009", Naive.class);
        refusedWith("FS-H009", Binary32.class);
        refusedWith("FS-H009", Ident.class);
    }

    /** The ids are distinct and each appears in docs/29 §5 exactly once. */
    @Test
    void everyIdIsDocumented() throws Exception {
        String doc = java.nio.file.Files.readString(TestSupport.VECTORS.resolve(
                "../docs/29-adapter-hibernate.md"));
        for (int i = 1; i <= 10; i++) {
            String id = String.format("| FS-H%03d |", i);
            assertEquals(1, doc.split(java.util.regex.Pattern.quote(id), -1).length - 1, id);
        }
    }
}
