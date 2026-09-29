package dev.fieldseal.hibernate;

import static dev.fieldseal.hibernate.TestSupport.causeOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.fieldseal.hibernate.fixture.Patient;
import java.util.List;
import java.util.function.Consumer;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

/** docs/29 §3.3: every shape refused, by type, and every shape served. */
class QueryRefusalTest {
    static SessionFactory sf;

    @BeforeAll
    static void start() {
        sf = TestSupport.sessionFactory(Patient.class);
        sf.inTransaction(s -> {
            s.persist(new Patient("ada@example.com", "n1", 36));
            s.persist(new Patient("grace@example.com", "n2", 45));
            s.persist(new Patient(null, "n3", null));
        });
    }

    @AfterAll
    static void stop() {
        sf.close();
    }

    static void refused(Consumer<Session> work) {
        var e = assertThrows(RuntimeException.class, () -> sf.inTransaction(work));
        assertNotNull(causeOf(e, FieldsealNotSupportedException.class), e.toString());
    }

    static void refusedHql(String hql) {
        refused(s -> s.createSelectionQuery(hql, Object.class).getResultList());
    }

    // ---- the binding guard ------------------------------------------------------------------

    /** Refused at the JDBC binding even without the walker's opinion: the backstop. */
    @Test
    void aParameterOnAnEncryptedColumnIsRefused() {
        refused(s -> s.createSelectionQuery("from Patient p where p.email = :e", Patient.class)
                .setParameter("e", "ada@example.com").getResultList());
    }

    @Test
    void aNativeQueryParameterIsNotIntercepted() {
        // The documented residue (docs/29 §3.3): native SQL never reaches the type or the walker.
        // It is asserted as a residue so that the claim cannot drift into a coverage claim.
        List<?> rows = sf.fromTransaction(s -> s.createNativeQuery(
                "select id from Patient where email = ?", Object.class)
                .setParameter(1, "ada@example.com".getBytes()).getResultList());
        assertEquals(0, rows.size(), "served, and silently empty: why raw SQL is documented");
    }

    // ---- the walker: encrypted attributes ------------------------------------------------------

    @ParameterizedTest(name = "{displayName}[{index}] {0}")
    @ValueSource(strings = {
        "from Patient p where p.email = 'ada@example.com'",
        "from Patient p where p.email <> 'ada@example.com'",
        "from Patient p where p.email in ('a', 'b')",
        "from Patient p where p.email between 'a' and 'b'",
        "from Patient p where p.email = p.note",
        "from Patient p where not (p.email = 'x')",
        "from Patient p where p.status = 'active' or p.email = 'x'",
        "from Patient p where p.id in (select q.id from Patient q where q.email = 'x')",
        "from Patient p where exists (select 1 from Patient q where q.email = p.email)",
        "from Patient p order by p.email",
        "select p.email, count(p) from Patient p group by p.email",
        "select distinct p.email from Patient p",
        "select count(distinct p.email) from Patient p",
        "select p.email || 'x' from Patient p",
        "select p.age + 1 from Patient p",
        "select coalesce(p.email, 'none') from Patient p",
        "select case when p.email is null then 0 else 1 end from Patient p where p.email = 'x'",
        "from Patient p where p.id in (select q.id from Patient q order by q.email)",
        "select p.id from Patient p where p.status in (select q.email from Patient q)",
    })
    void encryptedAttributeShapesAreRefused(String hql) {
        refusedHql(hql);
    }

    /**
     * Refused by Hibernate before the walker sees them: the column is VARBINARY, and Hibernate's
     * own typing rejects a string or comparable function over it when the query is created.
     * Pinned, because docs/29 §3.3 counts on it; the walker is default-deny, so a Hibernate that
     * stopped rejecting them would reach {@link #encryptedAttributeShapesAreRefused}'s refusal.
     */
    @ParameterizedTest(name = "{displayName}[{index}] {0}")
    @ValueSource(strings = {
        "from Patient p where p.email like 'ada%'",
        "from Patient p where lower(p.email) is null",
        "from Patient p order by lower(p.email)",
        "select max(p.age) from Patient p",
        "select min(p.email) from Patient p",
        "select length(p.email) from Patient p",
        "select upper(p.note) from Patient p",
        "select length(p.emailIndex) from Patient p",
    })
    void hibernatesOwnTypingRefusesStringFunctionsOverTheColumn(String hql) {
        var e = assertThrows(RuntimeException.class, () -> sf.inTransaction(
                s -> s.createSelectionQuery(hql, Object.class).getResultList()));
        assertNotNull(causeOf(e, org.hibernate.query.SemanticException.class), e.toString());
    }

    @ParameterizedTest(name = "{displayName}[{index}] {0}")
    @ValueSource(strings = {
        "from Patient p where p.email is null",
        "from Patient p where p.email is not null",
        "from Patient p where not (p.email is null)",
        "select count(p.email) from Patient p",
        "select p.email from Patient p",
        "select p.email, p.note from Patient p where p.status = 'active'",
        "select case when p.email is null then 0 else 1 end from Patient p",
        "select distinct p from Patient p",
        "from Patient p order by p.emailIndex",
        "select p.emailIndex from Patient p",
        "from Patient p where p.emailIndex is not null",
    })
    void servedShapesAreServed(String hql) {
        sf.inTransaction(s -> s.createSelectionQuery(hql, Object.class).getResultList());
    }

    @Test
    void countOverAnEncryptedColumnIsExact() {
        long n = sf.fromTransaction(s -> s.createSelectionQuery(
                "select count(p.email) from Patient p", Long.class).getSingleResult());
        long nulls = sf.fromTransaction(s -> s.createSelectionQuery(
                "select count(p) from Patient p where p.email is null", Long.class)
                .getSingleResult());
        long all = sf.fromTransaction(s -> s.createSelectionQuery(
                "select count(p) from Patient p", Long.class).getSingleResult());
        assertEquals(all, n + nulls);
    }

    // ---- the walker: index attributes ---------------------------------------------------------

    @ParameterizedTest(name = "{displayName}[{index}] {0}")
    @ValueSource(strings = {
        "from Patient p where p.emailIndex = X'00ff'",
        "from Patient p where p.emailIndex in (X'00', X'01')",
        "from Patient p where p.emailIndex <> X'00ff'",
        "from Patient p where not (p.emailIndex = X'00ff')",
        "from Patient p where p.emailIndex = p.emailIndex",
    })
    void indexAttributeShapesAreRefusedOutsideTheFinder(String hql) {
        refusedHql(hql);
    }

    /**
     * Inside the finder's scope the walker still refuses an index under negation or a non-equality
     * (spec §10.2, G24). The finder never builds either, so this enters the scope itself: it
     * tests the walker's rule, which no finder query can reach.
     */
    @ParameterizedTest(name = "{displayName}[{index}] {0}")
    @ValueSource(strings = {
        "from Patient p where not (p.emailIndex = :v)",
        "from Patient p where p.emailIndex <> :v",
        "from Patient p where p.emailIndex not in (:v)",
        "from Patient p where not (p.status = 'x' and p.emailIndex = :v)",
        "from Patient p where p.emailIndex > :v",
    })
    void negationAndNonEqualityAreRefusedEvenInScope(String hql) {
        var scope = FinderScope.enter();
        try {
            refused(s -> s.createSelectionQuery(hql, Patient.class)
                    .setParameter("v", new byte[] {1}).setQueryPlanCacheable(false)
                    .getResultList());
        } finally {
            scope.close();
        }
    }

    @Test
    void anEqualityIsServedInScope() {
        var scope = FinderScope.enter();
        try {
            sf.inTransaction(s -> s.createSelectionQuery(
                    "from Patient p where p.emailIndex = :v", Patient.class)
                    .setParameter("v", new byte[] {1}).setQueryPlanCacheable(false)
                    .getResultList());
        } finally {
            scope.close();
        }
    }

    @Test
    void aCriteriaPredicateOnAnIndexIsRefused() {
        refused(s -> {
            var cb = s.getCriteriaBuilder();
            var q = cb.createQuery(Patient.class);
            var r = q.from(Patient.class);
            q.where(cb.equal(r.get("emailIndex"), new byte[] {1, 2}));
            s.createSelectionQuery(q).getResultList();
        });
    }

    @Test
    void aCriteriaPredicateOnAnEncryptedAttributeIsRefused() {
        refused(s -> {
            var cb = s.getCriteriaBuilder();
            var q = cb.createQuery(Patient.class);
            var r = q.from(Patient.class);
            q.where(cb.equal(r.get("email"), "ada@example.com"));
            s.createSelectionQuery(q).getResultList();
        });
    }

    @Test
    void aCriteriaOrderingOnAnEncryptedAttributeIsRefused() {
        refused(s -> {
            var cb = s.getCriteriaBuilder();
            var q = cb.createQuery(Patient.class);
            var r = q.from(Patient.class);
            q.orderBy(cb.asc(r.get("email")));
            s.createSelectionQuery(q).getResultList();
        });
    }

    // ---- mutations ------------------------------------------------------------------------------

    @ParameterizedTest(name = "{displayName}[{index}] {0}")
    @ValueSource(strings = {
        "update Patient p set p.email = null",
        "update Patient p set p.emailIndex = null",
        "update Patient p set p.note = p.email",
        "update Patient p set p.status = 'x' where p.email = 'y'",
        "delete from Patient p where p.email = 'y'",
        "delete from Patient p where p.emailIndex = X'00'",
    })
    void mutationShapesAreRefused(String hql) {
        refused(s -> s.createMutationQuery(hql).executeUpdate());
    }

    @Test
    void anUpdateWithAParameterIsRefused() {
        refused(s -> s.createMutationQuery("update Patient p set p.email = :e")
                .setParameter("e", "x").executeUpdate());
    }

    @Test
    void anInsertIsRefused() {
        refused(s -> s.createMutationQuery(
                "insert into Patient (id, email, status) values (:id, :e, 'x')")
                .setParameter("id", java.util.UUID.randomUUID()).setParameter("e", "x")
                .executeUpdate());
    }

    @Test
    void aMutationOnPlainColumnsIsServed() {
        sf.inTransaction(s -> s.createMutationQuery(
                "update Patient p set p.status = 'seen' where p.email is not null")
                .executeUpdate());
    }
}
