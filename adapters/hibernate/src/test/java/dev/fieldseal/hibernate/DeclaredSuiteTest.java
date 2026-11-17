package dev.fieldseal.hibernate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.IndexDeclaration;
import dev.fieldseal.hibernate.fixture.Archive;
import java.util.Arrays;
import java.util.List;
import org.hibernate.SessionFactory;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Spec §7.2 (#213) end to end: an index declared under {@code 0xFF02}, with the write suite and
 * allow-list at {@code 0xFF01}, is derived under {@code 0xFF02}. The comparison is derived through
 * a core client, never by hand.
 */
class DeclaredSuiteTest {
    static SessionFactory sf;

    @BeforeAll
    static void open() {
        sf = TestSupport.sessionFactory(Archive.class);
    }

    @AfterAll
    static void close() {
        sf.close();
    }

    private static IndexSpec spec() {
        String name = sf.unwrap(SessionFactoryImplementor.class).getMappingMetamodel()
                .getEntityDescriptor(Archive.class).getEntityName();
        return CrossProduce.runtime(sf).index(name, "refIndex");
    }

    /** A core client over the shared key whose index is Archive.refIndex declared under suite. */
    private static byte[] derive(int suite, String value) {
        IndexDeclaration d = spec().declaration;
        IndexDeclaration other = IndexDeclaration.builder(d.tableUuid(), d.columnUuid())
                .suiteId(suite).indexId(d.indexId()).idf(d.idf()).normalize(d.normalize())
                .truncateBits(d.truncateBits()).projectedPopulation(d.projectedPopulation())
                .build();
        Fieldseal.Builder b = Fieldseal.builder();
        TestSupport.configurer().configure(b);
        Fieldseal client = b.indexes(List.of(other)).build();
        FieldContext fc = FieldContext.of(d.tableUuid(), d.columnUuid()).forIndex(d.indexId());
        return client.blindIndex(value, fc);
    }

    @Test
    void theAdapterCarriesTheDeclaredSuiteNotTheWriteSuite() {
        assertEquals(0xFF02, spec().declaration.suiteId());
    }

    @Test
    void persistLookupAndStoredBytesUseTheDeclaredSuite() {
        Archive a = new Archive("Case-0001");
        sf.inTransaction(s -> s.persist(a));

        byte[] stored = CrossProduce.raw(sf, "Archive", "refIndex", a.id);
        assertArrayEquals(derive(0xFF02, "Case-0001"), stored);
        assertFalse(Arrays.equals(derive(0xFF01, "Case-0001"), stored),
                "the stored index must not be the write-suite derivation");

        List<Archive> hits = sf.fromTransaction(s -> FieldsealQueries.of(s, Archive.class)
                .whereIndex("refIndex", "case-0001").list());
        assertEquals(1, hits.size());
        assertEquals(a.id, hits.get(0).id);
        assertEquals("Case-0001", hits.get(0).ref);
    }
}
