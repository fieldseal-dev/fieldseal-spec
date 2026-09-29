package dev.fieldseal.hibernate;

import static dev.fieldseal.hibernate.TestSupport.causeOf;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.hibernate.fixture.Collide;
import dev.fieldseal.hibernate.fixture.Patient;
import dev.fieldseal.hibernate.fixture.Person;
import dev.fieldseal.hibernate.fixture.TenantDoc;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** L2 (a) through the finder, re-verified (docs/29 §3.1, spec §7.5). */
class FinderTest {
    static SessionFactory sf;
    /** Two different codes that collide at b = 4, and one that does not collide with them. */
    static String a;
    static String b;
    static String other;

    @BeforeAll
    static void start() {
        sf = TestSupport.sessionFactory(Patient.class, Person.class, Collide.class,
                TenantDoc.class);
        Fieldseal client = FieldsealHibernate.client(sf);
        FieldContext ctx = FieldContext.of(TestSupport.hex("018f3c2e7a1b7c3d8e4f000000000031"),
                TestSupport.hex("018f3c2e7a1b7c3d8e4f000000000032")).forIndex("exact");
        List<String> seen = new ArrayList<>();
        List<byte[]> idx = new ArrayList<>();
        for (int i = 0; a == null || other == null; i++) {
            String code = "code-" + i;
            byte[] ix = client.blindIndex(code.getBytes(StandardCharsets.UTF_8), ctx);
            for (int j = 0; j < seen.size() && a == null; j++) {
                if (Arrays.equals(idx.get(j), ix)) {
                    a = seen.get(j);
                    b = code;
                }
            }
            seen.add(code);
            idx.add(ix);
            if (a != null && other == null) {
                byte[] ia = client.blindIndex(a.getBytes(StandardCharsets.UTF_8), ctx);
                for (String s : seen) {
                    if (!Arrays.equals(ia, client.blindIndex(s.getBytes(StandardCharsets.UTF_8),
                            ctx))) {
                        other = s;
                        break;
                    }
                }
            }
        }
        sf.inTransaction(s -> {
            s.persist(new Collide(a, "x"));
            s.persist(new Collide(b, "x"));
            s.persist(new Collide(other, "y"));
            s.persist(new Collide(a, "y"));
            s.persist(new Patient("ada@example.com", "n", 1));
            s.persist(new Patient("grace@example.com", "n", 2));
        });
    }

    @AfterAll
    static void stop() {
        sf.close();
    }

    static Set<String> codes(List<Collide> rows) {
        return rows.stream().map(r -> r.code + "/" + r.kind).collect(Collectors.toSet());
    }

    /** The collision is in the bucket, and verification drops it. */
    @Test
    void aCollidingRowIsDroppedByVerification() {
        List<Collide> verified = sf.fromTransaction(s -> FieldsealQueries.of(s, Collide.class)
                .whereIndex("codeIndex", a).list());
        assertEquals(Set.of(a + "/x", a + "/y"), codes(verified));
    }

    /** .candidates() hands over the bucket: the collision included, by request. */
    @Test
    void candidatesReturnTheBucket() {
        List<Collide> bucket = sf.fromTransaction(s -> FieldsealQueries.of(s, Collide.class)
                .whereIndex("codeIndex", a).candidates().list());
        assertTrue(codes(bucket).contains(b + "/x"), codes(bucket).toString());
        assertEquals(3, bucket.size());
    }

    @Test
    void anOrdinaryEqualityIsAndedInSql() {
        List<Collide> rows = sf.fromTransaction(s -> FieldsealQueries.of(s, Collide.class)
                .whereIndex("codeIndex", a).where("kind", "y").list());
        assertEquals(Set.of(a + "/y"), codes(rows));
    }

    @Test
    void membershipIsVerifiedPerValue() {
        List<Collide> rows = sf.fromTransaction(s -> FieldsealQueries.of(s, Collide.class)
                .whereIndexIn("codeIndex", List.of(a, other)).list());
        assertEquals(Set.of(a + "/x", a + "/y", other + "/y"), codes(rows));
        assertEquals(0, (long) sf.fromTransaction(s -> FieldsealQueries.of(s, Collide.class)
                .whereIndexIn("codeIndex", List.of()).count()));
    }

    @Test
    void countFirstAndExistsAreVerified() {
        assertEquals(2, (long) sf.fromTransaction(s -> FieldsealQueries.of(s, Collide.class)
                .whereIndex("codeIndex", a).count()));
        boolean found = sf.fromTransaction(s -> FieldsealQueries.of(s, Collide.class)
                .whereIndex("codeIndex", b).exists());
        assertTrue(found);
        assertEquals(b, sf.fromTransaction(s -> FieldsealQueries.of(s, Collide.class)
                .whereIndex("codeIndex", b).first().orElseThrow().code));
        boolean absent = sf.fromTransaction(s -> FieldsealQueries.of(s, Collide.class)
                .whereIndex("codeIndex", "absent-value").exists());
        assertFalse(absent);
    }

    /** Spec §7.5's comparison is the normalizer's: nfc-casefold-v1 makes this the caseless match. */
    @Test
    void theNormalizerDecidesEquality() {
        List<Patient> rows = sf.fromTransaction(s -> FieldsealQueries.of(s, Patient.class)
                .whereIndex("emailIndex", "ADA@Example.COM").list());
        assertEquals(1, rows.size());
        assertEquals("ada@example.com", rows.get(0).email);
    }

    @Test
    void theFinderRefusesAnEncryptedOrIndexAttributeInWhere() {
        sf.inTransaction(s -> {
            assertThrows(FieldsealNotSupportedException.class,
                    () -> FieldsealQueries.of(s, Patient.class).where("email", "x"));
            assertThrows(FieldsealNotSupportedException.class,
                    () -> FieldsealQueries.of(s, Patient.class).where("emailIndex", "x"));
            assertThrows(FieldsealNotSupportedException.class,
                    () -> FieldsealQueries.of(s, Patient.class).whereIndex("email", "x"));
            // `is null` on an encrypted attribute is exact, so the finder serves it.
            FieldsealQueries.of(s, Patient.class).where("email", null).list();
        });
    }

    /** The scope is the finder's query only: the same shape afterwards, in HQL, is refused. */
    @Test
    void theScopeDoesNotOutliveTheFindersQuery() {
        sf.inTransaction(s -> FieldsealQueries.of(s, Patient.class)
                .whereIndex("emailIndex", "ada@example.com").list());
        var e = assertThrows(RuntimeException.class, () -> sf.inTransaction(s ->
                s.createSelectionQuery("from Patient p where p.emailIndex = :v", Patient.class)
                        .setParameter("v", new byte[] {1, 2}).getResultList()));
        assertNotNull(causeOf(e, FieldsealNotSupportedException.class), e.toString());
    }

    @Test
    void aStatelessSessionCanUseTheFinder() {
        List<Patient> rows = sf.fromStatelessTransaction(s -> FieldsealQueries.of(s,
                Patient.class).whereIndex("emailIndex", "grace@example.com").list());
        assertEquals(1, rows.size());
    }

    // ---- unindexable values (docs/29 §10) ----------------------------------------------------

    /** U+0378 is unassigned in every published Unicode version. */
    static final String UNASSIGNED = "Ada͸ Lovelace";

    @Test
    void refuseRaisesOnWriteNamingTheCharacter() {
        var e = assertThrows(RuntimeException.class, () -> sf.inTransaction(
                s -> s.persist(new Patient("x" + "͸" + "@example.com", "n", 1))));
        FieldsealUnindexableException u = causeOf(e, FieldsealUnindexableException.class);
        assertNotNull(u, e.toString());
        assertEquals(0x378, u.codePoint());
        assertEquals(1, u.offset());
        assertEquals("Patient.email", u.attribute());
    }

    @Test
    void refuseRaisesOnLookupRatherThanReturningNothing() {
        sf.inTransaction(s -> assertThrows(FieldsealUnindexableException.class,
                () -> FieldsealQueries.of(s, Patient.class).whereIndex("emailIndex",
                        "x͸@example.com").list()));
    }

    @Test
    void bucketStoresTheMarkerAndVerificationNarrows() {
        Person odd = new Person(UNASSIGNED);
        Person other = new Person("Ada͹ Lovelace");
        Person plain = new Person("Ada Lovelace");
        sf.inTransaction(s -> {
            s.persist(odd);
            s.persist(other);
            s.persist(plain);
        });
        byte[] marker = FieldsealHibernate.client(sf).unindexableMarker(FieldContext.of(
                TestSupport.hex("018f3c2e7a1b7c3d8e4f000000000011"),
                TestSupport.hex("018f3c2e7a1b7c3d8e4f000000000012")).forIndex("exact"));
        assertArrayEquals(marker, odd.legalNameIndex);
        assertArrayEquals(marker, other.legalNameIndex, "both unindexable values share the bucket");
        List<Person> rows = sf.fromTransaction(s -> FieldsealQueries.of(s, Person.class)
                .whereIndex("legalNameIndex", UNASSIGNED).list());
        assertEquals(List.of(UNASSIGNED), rows.stream().map(p -> p.legalName).toList(),
                "re-verification tells two refused values apart byte for byte (G19)");
    }

    // ---- tenant-bound -------------------------------------------------------------------------

    @Test
    void aTenantBoundIndexIsDerivedUnderTheSessionsTenant() {
        TenantDoc d = new TenantDoc("b", "ada@example.com");
        try (Session s = sf.withOptions().tenantIdentifier((Object) "t1").openSession()) {
            s.beginTransaction();
            s.persist(d);
            s.getTransaction().commit();
        }
        try (Session s = sf.withOptions().tenantIdentifier((Object) "t1").openSession()) {
            assertEquals(1, FieldsealQueries.of(s, TenantDoc.class)
                    .whereIndex("handleIndex", "ada@example.com").list().size());
        }
        try (Session s = sf.withOptions().tenantIdentifier((Object) "t2").openSession()) {
            assertEquals(0, FieldsealQueries.of(s, TenantDoc.class)
                    .whereIndex("handleIndex", "ada@example.com").candidates().list().size(),
                    "another tenant's index key derives another value");
        }
    }
}
