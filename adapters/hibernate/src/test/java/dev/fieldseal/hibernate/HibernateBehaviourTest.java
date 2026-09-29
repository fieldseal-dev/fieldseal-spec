package dev.fieldseal.hibernate;

import static dev.fieldseal.hibernate.TestSupport.clearSql;
import static dev.fieldseal.hibernate.TestSupport.sql;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.hibernate.fixture.AllTypes;
import dev.fieldseal.hibernate.fixture.Patient;
import java.util.UUID;
import org.hibernate.SessionFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Pins the Hibernate behaviour docs/29 §2.1 builds on, measured on 7.4.11, so that an upgrade that
 * changes any of it goes red here rather than somewhere quieter.
 */
class HibernateBehaviourTest {
    static SessionFactory sf;

    @BeforeAll
    static void start() {
        sf = TestSupport.sessionFactory(Patient.class, AllTypes.class);
    }

    @AfterAll
    static void stop() {
        sf.close();
    }

    /** One INSERT, and a second flush finds nothing dirty: equals compares a Sealed value by plaintext. */
    @Test
    void persistThenFlushTwiceIssuesOneInsertAndNoUpdate() {
        clearSql();
        sf.inTransaction(s -> {
            Patient p = new Patient("ada@example.com", "n", 36);
            s.persist(p);
            s.flush();
            s.flush();
            assertEquals("ada@example.com", p.email, "the entity keeps its plaintext");
        });
        assertEquals(1, sql("insert").size(), TestSupport.SQL.toString());
        assertEquals(0, sql("update").size(), TestSupport.SQL.toString());
    }

    @Test
    void loadThenFlushIssuesNoUpdate() {
        UUID id = persist(new Patient("load@example.com", "n", 1));
        clearSql();
        sf.inTransaction(s -> {
            s.find(Patient.class, id);
            s.flush();
        });
        assertEquals(0, sql("update").size(), TestSupport.SQL.toString());
    }

    @Test
    void aChangedValueIssuesOneUpdateAndThenNone() {
        UUID id = persist(new Patient("before@example.com", "n", 1));
        clearSql();
        sf.inTransaction(s -> {
            Patient p = s.find(Patient.class, id);
            p.email = "after@example.com";
            s.flush();
            s.flush();
        });
        assertEquals(1, sql("update").size(), TestSupport.SQL.toString());
        sf.inTransaction(s -> assertEquals("after@example.com", s.find(Patient.class, id).email));
    }

    /** JDBC batching survives the listener: five inserts, one prepared statement. */
    @Test
    void batchedInsertsStayBatched() {
        clearSql();
        sf.inTransaction(s -> {
            for (int i = 0; i < 5; i++) {
                s.persist(new Patient("b" + i + "@example.com", "n", i));
            }
        });
        assertEquals(1, sql("insert").size(), TestSupport.SQL.toString());
    }

    @Test
    void statelessInsertAndUpdateGoThroughTheListener() {
        UUID id = UUID.randomUUID();
        sf.inStatelessTransaction(s -> {
            Patient p = new Patient("stateless@example.com", "n", 2);
            p.id = id;
            s.insert(p);
        });
        sf.inStatelessTransaction(s -> {
            Patient p = s.get(Patient.class, id);
            assertEquals("stateless@example.com", p.email);
            p.email = "stateless2@example.com";
            s.update(p);
        });
        sf.inTransaction(s -> assertEquals("stateless2@example.com",
                s.find(Patient.class, id).email));
    }

    @Test
    void mergeOfADetachedEntityGoesThroughTheListener() {
        UUID id = persist(new Patient("merge@example.com", "n", 3));
        Patient detached = new Patient("merged@example.com", "m", 4);
        detached.id = id;
        sf.inTransaction(s -> s.merge(detached));
        sf.inTransaction(s -> assertEquals("merged@example.com", s.find(Patient.class, id).email));
    }

    /** IDENTITY: the id is null in the pre-insert listener (docs/29 §1), and the write still seals. */
    @Test
    void identityInsertSeals() {
        AllTypes a = new AllTypes();
        a.text = "identity";
        sf.inTransaction(s -> s.persist(a));
        assertNotNull(a.id);
        sf.inTransaction(s -> assertEquals("identity", s.find(AllTypes.class, a.id).text));
    }

    /** HQL and Criteria reach the translator; find, and a lazy association, do not (docs/29 §1). */
    @Test
    void onlyHqlAndCriteriaReachTheTranslator() {
        UUID id = persist(new Patient("find@example.com", "n", 5));
        long before = FieldsealSqmTranslatorFactory.WALKED.get();
        sf.inTransaction(s -> assertTrue(s.find(Patient.class, id).email.startsWith("find@")));
        sf.inTransaction(s -> assertNull(s.find(Patient.class, UUID.randomUUID())));
        assertEquals(before, FieldsealSqmTranslatorFactory.WALKED.get(), "find");
        sf.inTransaction(s -> s.createSelectionQuery("from Patient", Patient.class)
                .getResultList());
        assertEquals(before + 1, FieldsealSqmTranslatorFactory.WALKED.get(), "HQL");
        sf.inTransaction(s -> {
            var cb = s.getCriteriaBuilder();
            var q = cb.createQuery(Patient.class);
            q.from(Patient.class);
            s.createSelectionQuery(q).getResultList();
        });
        assertEquals(before + 2, FieldsealSqmTranslatorFactory.WALKED.get(), "Criteria");
    }

    private static UUID persist(Patient p) {
        sf.inTransaction(s -> s.persist(p));
        return p.id;
    }
}
