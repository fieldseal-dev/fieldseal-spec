package dev.fieldseal.hibernate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.fieldseal.hibernate.fixture.Patient;
import dev.fieldseal.hibernate.fixture.TenantDoc;
import java.util.HashMap;
import java.util.List;
import org.hibernate.SessionFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** docs/29 §7: warming names what it could not warm, rather than reporting a warm cache. */
class WarmTest {
    static SessionFactory sf;

    @BeforeAll
    static void start() {
        sf = TestSupport.sessionFactory(Patient.class, TenantDoc.class);
    }

    @AfterAll
    static void stop() {
        sf.close();
    }

    @Test
    void withNoTenantsTheTenantBoundColumnsAreNamedAsSkipped() {
        FieldsealHibernate.Warming w = FieldsealHibernate.warm(sf, List.of());
        w.done().join();
        assertEquals(List.of("TenantDoc.body", "TenantDoc.handle", "TenantDoc.handleIndex"),
                w.skipped().stream().sorted().toList());
    }

    @Test
    void withTenantsNothingIsSkipped() {
        FieldsealHibernate.Warming w = FieldsealHibernate.warm(sf, List.of("t1", "t2"));
        w.done().join();
        assertEquals(List.of(), w.skipped());
    }

    @Test
    void aSessionFactoryWithoutTheAdapterIsRefused() {
        try (SessionFactory plain = TestSupport.build(new HashMap<>(TestSupport.baseSettings()),
                StartupChecksTest.Plain.class)) {
            assertThrows(FieldsealConfigurationException.class,
                    () -> FieldsealHibernate.warm(plain, List.of()));
        }
    }
}
