package dev.fieldseal.hibernate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.fieldseal.hibernate.fixture.Patient;
import java.lang.reflect.Proxy;
import java.sql.PreparedStatement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import org.hibernate.SessionFactory;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.type.CustomType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The type's JDBC binding, directly (docs/29 §2.1 item 2). End to end it is a backstop no
 * configured path reaches today: the listener seals every write it sees, and the walker refuses a
 * query shape before a parameter is bound (FS-H005 makes the walker mandatory). That is exactly
 * why it is tested here: a backstop no test can reach would otherwise never be seen to hold.
 */
class BindingGuardTest {
    static SessionFactory sf;
    static EncryptedType email;

    @BeforeAll
    static void start() {
        sf = TestSupport.sessionFactory(Patient.class);
        var persister = sf.unwrap(SessionFactoryImplementor.class).getMappingMetamodel()
                .getEntityDescriptor(Patient.class);
        email = (EncryptedType) ((CustomType<?>) persister.findAttributeMapping("email")
                .getSingleJdbcMapping()).getUserType();
    }

    @AfterAll
    static void stop() {
        sf.close();
    }

    /** Records every setter call; nothing else is expected. */
    static PreparedStatement recorder(List<String> calls) {
        return (PreparedStatement) Proxy.newProxyInstance(
                BindingGuardTest.class.getClassLoader(), new Class<?>[] {PreparedStatement.class},
                (proxy, method, args) -> {
                    calls.add(method.getName() + (args == null ? "" : ":" + args.length));
                    if (method.getName().equals("setBytes")) {
                        last = (byte[]) args[1];
                    }
                    return null;
                });
    }

    static byte[] last;

    @Test
    void aPlainValueIsRefusedAndNothingIsBound() {
        List<String> calls = new ArrayList<>();
        sf.inTransaction(s -> assertThrows(FieldsealNotSupportedException.class,
                () -> email.nullSafeSet(recorder(calls), "ada@example.com", 1,
                        (org.hibernate.type.descriptor.WrapperOptions) s.unwrap(org.hibernate.engine.spi.SharedSessionContractImplementor.class))));
        assertEquals(List.of(), calls);
    }

    @Test
    void aSealedValueBindsItsEnvelope() throws Exception {
        List<String> calls = new ArrayList<>();
        byte[] envelope = {1, 2, 3};
        Sealed sealed = new Sealed(email.spec(), "ada@example.com", envelope);
        sf.inTransaction(s -> {
            try {
                email.nullSafeSet(recorder(calls), sealed, 1,
                        (org.hibernate.type.descriptor.WrapperOptions) s.unwrap(org.hibernate.engine.spi.SharedSessionContractImplementor.class));
            } catch (java.sql.SQLException e) {
                throw new IllegalStateException(e);
            }
        });
        assertEquals(List.of("setBytes:2"), calls);
        assertArrayEquals(envelope, last);
    }

    /** Another column's sealed value is not this column's: refused, not bound. */
    @Test
    void anotherColumnsSealedValueIsRefused() {
        var persister = sf.unwrap(SessionFactoryImplementor.class).getMappingMetamodel()
                .getEntityDescriptor(Patient.class);
        EncryptedType note = (EncryptedType) ((CustomType<?>) persister
                .findAttributeMapping("note").getSingleJdbcMapping()).getUserType();
        Sealed foreign = new Sealed(note.spec(), "x", new byte[] {9});
        sf.inTransaction(s -> assertThrows(FieldsealNotSupportedException.class,
                () -> email.nullSafeSet(recorder(new ArrayList<>()), foreign, 1,
                        (org.hibernate.type.descriptor.WrapperOptions) s.unwrap(org.hibernate.engine.spi.SharedSessionContractImplementor.class))));
    }

    @Test
    void nullBindsNull() throws Exception {
        List<String> calls = new ArrayList<>();
        sf.inTransaction(s -> {
            try {
                email.nullSafeSet(recorder(calls), null, 1,
                        (org.hibernate.type.descriptor.WrapperOptions) s.unwrap(org.hibernate.engine.spi.SharedSessionContractImplementor.class));
            } catch (java.sql.SQLException e) {
                throw new IllegalStateException(e);
            }
        });
        assertEquals(List.of("setNull:2"), calls);
        assertEquals(Types.VARBINARY, email.getSqlType());
    }
}
