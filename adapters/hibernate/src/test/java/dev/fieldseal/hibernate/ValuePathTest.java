package dev.fieldseal.hibernate;

import static dev.fieldseal.hibernate.TestSupport.causeOf;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.hibernate.fixture.AllTypes;
import dev.fieldseal.hibernate.fixture.Patient;
import dev.fieldseal.hibernate.fixture.TenantDoc;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** The write and read paths (docs/29 §2), and the context they bind (§4). */
class ValuePathTest {
    static SessionFactory sf;
    static final byte[] PATIENT = TestSupport.hex("018f3c2e7a1b7c3d8e4f000000000001");
    static final byte[] EMAIL = TestSupport.hex("018f3c2e7a1b7c3d8e4f000000000002");
    static final byte[] TENANT_DOC = TestSupport.hex("018f3c2e7a1b7c3d8e4f000000000021");
    static final byte[] BODY = TestSupport.hex("018f3c2e7a1b7c3d8e4f000000000022");

    @BeforeAll
    static void start() {
        sf = TestSupport.sessionFactory(Patient.class, AllTypes.class, TenantDoc.class);
    }

    @AfterAll
    static void stop() {
        sf.close();
    }

    static byte[] raw(Session s, String table, String column, Object id) {
        return s.doReturningWork(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "select " + column + " from " + table + " where id = ?")) {
                ps.setObject(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return rs.getBytes(1);
                }
            }
        });
    }

    /** The column holds an envelope that an independent client decrypts to spec §3.6's bytes. */
    @Test
    void theColumnHoldsAnEnvelopeOverTheCanonicalRendering() {
        Patient p = new Patient("ada@example.com", "a note", 36);
        sf.inTransaction(s -> s.persist(p));
        Fieldseal independent = TestSupport.independentClient();
        sf.inTransaction(s -> {
            byte[] stored = raw(s, "Patient", "email", p.id);
            assertTrue(independent.isCiphertext(stored));
            assertArrayEquals("ada@example.com".getBytes(StandardCharsets.UTF_8),
                    independent.decrypt(stored, FieldContext.of(PATIENT, EMAIL)));
            byte[] age = raw(s, "Patient", "age", p.id);
            assertArrayEquals("36".getBytes(StandardCharsets.US_ASCII), independent.decrypt(age,
                    FieldContext.of(PATIENT, TestSupport.hex("018f3c2e7a1b7c3d8e4f000000000004"))));
        });
    }

    /** The sibling holds exactly what the core derives from the same rendering. */
    @Test
    void theIndexSiblingIsTheCoresDerivation() {
        Patient p = new Patient("Ada@Example.com", "n", 1);
        sf.inTransaction(s -> s.persist(p));
        byte[] expected = FieldsealHibernate.client(sf).blindIndex(
                "Ada@Example.com".getBytes(StandardCharsets.UTF_8),
                FieldContext.of(PATIENT, EMAIL).forIndex("exact"));
        sf.inTransaction(s -> assertArrayEquals(expected, raw(s, "Patient", "emailIndex", p.id)));
        assertArrayEquals(expected, p.emailIndex, "the entity carries the index too");
    }

    /** Spec §3.1: every write draws a fresh nonce, including an UPDATE of the same value. */
    @Test
    void everyWriteIsAFreshEnvelope() {
        Patient p = new Patient("fresh@example.com", "n", 1);
        sf.inTransaction(s -> s.persist(p));
        byte[] first = sf.fromTransaction(s -> raw(s, "Patient", "email", p.id));
        sf.inTransaction(s -> s.find(Patient.class, p.id).note = "changed");
        byte[] second = sf.fromTransaction(s -> raw(s, "Patient", "email", p.id));
        assertFalse(java.util.Arrays.equals(first, second), "an UPDATE re-encrypts every column");
        sf.inTransaction(s -> assertEquals("fresh@example.com", s.find(Patient.class, p.id).email));
    }

    /** Spec §10.2's NULL invariant: NULL in both columns, and "" is a value. */
    @Test
    void nullIsNullAndTheEmptyStringIsAValue() {
        Patient none = new Patient(null, "", null);
        sf.inTransaction(s -> s.persist(none));
        sf.inTransaction(s -> {
            assertNull(raw(s, "Patient", "email", none.id));
            assertNull(raw(s, "Patient", "emailIndex", none.id));
            assertNull(raw(s, "Patient", "age", none.id));
            byte[] empty = raw(s, "Patient", "note", none.id);
            assertNotNull(empty);
            assertTrue(TestSupport.independentClient().isCiphertext(empty));
            Patient back = s.find(Patient.class, none.id);
            assertNull(back.email);
            assertEquals("", back.note);
        });
    }

    /** An index assignment by the application is undone: the listener owns the sibling. */
    @Test
    void anAssignedSiblingIsRestored() {
        Patient p = new Patient("owned@example.com", "n", 1);
        sf.inTransaction(s -> s.persist(p));
        byte[] good = p.emailIndex.clone();
        sf.inTransaction(s -> s.find(Patient.class, p.id).emailIndex = new byte[] {1, 2});
        sf.inTransaction(s -> assertArrayEquals(good, raw(s, "Patient", "emailIndex", p.id)));
    }

    @Test
    void aChangedSourceRederivesTheIndex() {
        Patient p = new Patient("old@example.com", "n", 1);
        sf.inTransaction(s -> s.persist(p));
        sf.inTransaction(s -> s.find(Patient.class, p.id).email = "new@example.com");
        byte[] expected = FieldsealHibernate.client(sf).blindIndex(
                "new@example.com".getBytes(StandardCharsets.UTF_8),
                FieldContext.of(PATIENT, EMAIL).forIndex("exact"));
        sf.inTransaction(s -> assertArrayEquals(expected, raw(s, "Patient", "emailIndex", p.id)));
        sf.inTransaction(s -> s.find(Patient.class, p.id).email = null);
        sf.inTransaction(s -> assertNull(raw(s, "Patient", "emailIndex", p.id)));
    }

    @Test
    void everySupportedTypeRoundTrips() {
        AllTypes a = new AllTypes();
        a.text = "日本語 🔐";
        a.blob = new byte[] {0, 1, (byte) 0xff};
        a.bigCount = Long.MIN_VALUE;
        a.small = -7;
        a.tiny = (short) 32767;
        a.huge = new BigInteger("18446744073709551616");
        a.amount = new BigDecimal("1.50");
        a.ratio = -0.0;
        a.flag = Boolean.FALSE;
        a.born = LocalDate.of(1815, 12, 10);
        a.seen = Instant.parse("2026-09-29T12:00:00.123456Z");
        a.at = OffsetDateTime.of(2026, 9, 29, 17, 30, 0, 0, ZoneOffset.ofHoursMinutes(5, 30));
        sf.inTransaction(s -> s.persist(a));
        sf.inTransaction(s -> {
            AllTypes b = s.find(AllTypes.class, a.id);
            assertEquals(a.text, b.text);
            assertArrayEquals(a.blob, b.blob);
            assertEquals(a.bigCount, b.bigCount);
            assertEquals(a.small, b.small);
            assertEquals(a.tiny, b.tiny);
            assertEquals(a.huge, b.huge);
            assertEquals(new BigDecimal("1.5"), b.amount, "canonical by value: 1.50 reads 1.5");
            assertEquals(Double.doubleToRawLongBits(-0.0), Double.doubleToRawLongBits(b.ratio));
            assertEquals(a.flag, b.flag);
            assertEquals(a.born, b.born);
            assertEquals(a.seen, b.seen);
            assertEquals(a.at.toInstant(), b.at.toInstant());
            assertEquals(ZoneOffset.UTC, b.at.getOffset(), "an OffsetDateTime reads back at UTC");
        });
    }

    /** Spec §3.6: a sub-microsecond digit is refused, never truncated. */
    @Test
    void aNanosecondInstantIsRefusedNotTruncated() {
        AllTypes a = new AllTypes();
        a.seen = Instant.parse("2026-09-29T12:00:00.123456789Z");
        var e = assertThrows(RuntimeException.class, () -> sf.inTransaction(s -> s.persist(a)));
        assertNotNull(causeOf(e, FieldsealNotSupportedException.class), e.toString());
    }

    @Test
    void anUnpairedSurrogateIsRefused() {
        Patient p = new Patient("x@example.com", "a\uD800b", 1);
        var e = assertThrows(RuntimeException.class, () -> sf.inTransaction(s -> s.persist(p)));
        assertNotNull(causeOf(e, FieldsealNotSupportedException.class), e.toString());
    }

    /** A projection decrypts, as an entity load does. */
    @Test
    void aProjectionDecrypts() {
        Patient p = new Patient("projected@example.com", "n", 1);
        sf.inTransaction(s -> s.persist(p));
        List<Object> emails = sf.fromTransaction(s -> s.createSelectionQuery(
                "select p.email from Patient p where p.id = :id", Object.class)
                .setParameter("id", p.id).getResultList());
        assertEquals(List.of("projected@example.com"), emails);
    }

    // ---- L3: the tenant is the session's --------------------------------------------------

    @Test
    void aTenantBoundColumnBindsTheSessionsTenant() {
        TenantDoc d = new TenantDoc("tenant body", "ada@example.com");
        try (Session s = sf.withOptions().tenantIdentifier((Object) "tenant-0001").openSession()) {
            s.beginTransaction();
            s.persist(d);
            s.getTransaction().commit();
        }
        Fieldseal independent = TestSupport.independentClient();
        byte[] stored = sf.fromTransaction(s -> raw(s, "TenantDoc", "body", d.id));
        assertArrayEquals("tenant body".getBytes(StandardCharsets.UTF_8), independent.decrypt(stored,
                FieldContext.of(TENANT_DOC, BODY).withTenant("tenant-0001".getBytes(
                        StandardCharsets.UTF_8))));
        try (Session s = sf.withOptions().tenantIdentifier((Object) "tenant-0001").openSession()) {
            assertEquals("tenant body", s.find(TenantDoc.class, d.id).body);
        }
    }

    @Test
    void aTenantBoundColumnWithNoTenantFailsClosedOnWrite() {
        var e = assertThrows(RuntimeException.class,
                () -> sf.inTransaction(s -> s.persist(new TenantDoc("b", "h"))));
        assertNotNull(causeOf(e, FieldsealConfigurationException.class), e.toString());
    }

    @Test
    void aTenantBoundColumnWithNoTenantFailsClosedOnRead() {
        TenantDoc d = new TenantDoc("b", "h@example.com");
        try (Session s = sf.withOptions().tenantIdentifier((Object) "tenant-0002").openSession()) {
            s.beginTransaction();
            s.persist(d);
            s.getTransaction().commit();
        }
        var e = assertThrows(RuntimeException.class,
                () -> sf.inTransaction(s -> s.find(TenantDoc.class, d.id)));
        assertNotNull(causeOf(e, FieldsealConfigurationException.class), e.toString());
    }

    /** Read under another tenant: the core refuses, since the context is part of the key (spec §6). */
    @Test
    void aTenantBoundColumnReadUnderAnotherTenantIsRefused() {
        TenantDoc d = new TenantDoc("b", "h2@example.com");
        try (Session s = sf.withOptions().tenantIdentifier((Object) "tenant-a").openSession()) {
            s.beginTransaction();
            s.persist(d);
            s.getTransaction().commit();
        }
        try (Session s = sf.withOptions().tenantIdentifier((Object) "tenant-b").openSession()) {
            var e = assertThrows(RuntimeException.class, () -> s.find(TenantDoc.class, d.id));
            assertNotNull(causeOf(e, dev.fieldseal.core.errors.FieldsealError.class),
                    e.toString());
        }
    }

    @Test
    void aTenantThatIsNotAStringOrBytesIsRefused() {
        try (Session s = sf.withOptions().tenantIdentifier((Object) UUID.randomUUID())
                .openSession()) {
            s.beginTransaction();
            var e = assertThrows(RuntimeException.class, () -> {
                s.persist(new TenantDoc("b", "h"));
                s.flush();
            });
            assertNotNull(causeOf(e, FieldsealConfigurationException.class), e.toString());
            s.getTransaction().rollback();
        }
    }
}
