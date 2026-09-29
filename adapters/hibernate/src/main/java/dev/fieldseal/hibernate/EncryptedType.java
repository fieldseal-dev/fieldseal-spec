package dev.fieldseal.hibernate;

import dev.fieldseal.core.Fieldseal;
import java.io.Serializable;
import java.math.BigDecimal;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Arrays;
import java.util.Objects;
import org.hibernate.Length;
import org.hibernate.type.descriptor.WrapperOptions;
import org.hibernate.usertype.UserType;
import org.hibernate.usertype.UserTypeCreationContext;

/**
 * The type of an {@link Encrypted} attribute (docs/29 §2.1). It decrypts on read, and on write it
 * binds only a value the adapter's listener sealed: a plain value at this column's JDBC binding is
 * a query parameter or a write path the listener did not see, and is refused. That refusal is the
 * adapter's backstop below every entry point.
 *
 * <p>The Java type is typed {@code Object} because a state array holds a {@link Sealed} value in
 * this attribute's slot between the listener and the statement. The integrator binds each instance
 * to its column and to the client when the session factory is built; an unbound instance refuses
 * every value.
 */
public final class EncryptedType implements UserType<Object> {

    private final Encrypted annotation;
    private final Class<?> javaType;
    private final String attribute;
    private volatile Binding binding;

    private record Binding(ColumnSpec spec, Fieldseal client) {}

    /** Called by Hibernate for an attribute carrying {@link Encrypted}. */
    public EncryptedType(Encrypted annotation, UserTypeCreationContext context) {
        this.annotation = annotation;
        var member = context.getMemberDetails();
        this.javaType = Codec.box(member.getType().determineRawClass().toJavaClass());
        this.attribute = member.resolveAttributeName();
    }

    Encrypted annotation() {
        return annotation;
    }

    Class<?> javaType() {
        return javaType;
    }

    String attribute() {
        return attribute;
    }

    /** Binds this instance to its column; the integrator calls it once. */
    void bind(ColumnSpec spec, Fieldseal client) {
        Binding current = binding;
        if (current != null && current.spec != spec) {
            throw new FieldsealConfigurationException("FS-H001: one EncryptedType instance is "
                    + "mapped to both " + current.spec.label + " and " + spec.label);
        }
        binding = new Binding(spec, client);
    }

    ColumnSpec spec() {
        return bound().spec;
    }

    private Binding bound() {
        Binding b = binding;
        if (b == null) {
            throw new FieldsealConfigurationException("FS-H004: the encrypted attribute '"
                    + attribute + "' was used by a session factory the Fieldseal integrator did "
                    + "not configure (is dev.fieldseal.hibernate.FieldsealIntegrator loaded?)");
        }
        return b;
    }

    @Override
    public int getSqlType() {
        return Types.VARBINARY;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Class<Object> returnedClass() {
        return (Class<Object>) javaType;
    }

    /**
     * Room for the envelope as well as the value: spec §3.2's overhead is about a hundred bytes,
     * which Hibernate's default of 255 would leave to the plaintext. {@code @Column(length = …)}
     * overrides it; Postgres's {@code bytea} ignores it.
     */
    @Override
    public long getDefaultSqlLength() {
        return Length.LONG;
    }

    @Override
    public Object nullSafeGet(ResultSet rs, int position, WrapperOptions options)
            throws SQLException {
        byte[] stored = rs.getBytes(position);
        if (stored == null) {
            return null;
        }
        Binding b = bound();
        byte[] plaintext = b.client.decrypt(stored, b.spec.context(options.getSession()));
        return b.spec.codec.parse(plaintext);
    }

    @Override
    public void nullSafeSet(PreparedStatement st, Object value, int position,
            WrapperOptions options) throws SQLException {
        if (value == null) {
            st.setNull(position, Types.VARBINARY);
            return;
        }
        Binding b = bound();
        if (value instanceof Sealed s && s.spec == b.spec) {
            st.setBytes(position, s.envelope());
            return;
        }
        throw new FieldsealNotSupportedException(b.spec.label + ": a plain value reached the "
                + "encrypted column's JDBC binding. It is either a query parameter (an encrypted "
                + "column cannot be compared in SQL: every envelope is randomized, so the "
                + "comparison would match nothing; query its @BlindIndex through "
                + "FieldsealQueries) or a write path the adapter's listener does not reach "
                + "(an HQL or Criteria update or insert, for one). It is refused rather than "
                + "bound, because binding it would write plaintext or silently mis-serve the "
                + "query (spec §10.2; docs/29 §2.1, §3.3)");
    }

    @Override
    public boolean equals(Object x, Object y) {
        Object a = unwrap(x);
        Object b = unwrap(y);
        if (a instanceof byte[] ba && b instanceof byte[] bb) {
            return Arrays.equals(ba, bb);
        }
        if (a instanceof BigDecimal da && b instanceof BigDecimal db) {
            return da.compareTo(db) == 0;
        }
        return Objects.equals(a, b);
    }

    @Override
    public int hashCode(Object x) {
        Object a = unwrap(x);
        if (a instanceof byte[] ba) {
            return Arrays.hashCode(ba);
        }
        if (a instanceof BigDecimal d) {
            return d.signum() == 0 ? 0 : d.stripTrailingZeros().hashCode();
        }
        return Objects.hashCode(a);
    }

    private static Object unwrap(Object v) {
        return v instanceof Sealed s ? s.plaintext : v;
    }

    @Override
    public Object deepCopy(Object value) {
        return value instanceof byte[] b ? b.clone() : value;
    }

    @Override
    public boolean isMutable() {
        return javaType == byte[].class;
    }

    /**
     * Refused: a second-level or query cache entry would hold the plaintext, and there is no
     * session here to encrypt a tenant-bound column under (docs/29 §1, FS-H006).
     */
    @Override
    public Serializable disassemble(Object value) {
        throw new FieldsealNotSupportedException(label() + ": a second-level or query cache "
                + "entry would hold this encrypted attribute's plaintext (spec §10.2). Do not "
                + "cache entities with encrypted attributes, or query results that select one "
                + "(docs/29 §1)");
    }

    @Override
    public Object assemble(Serializable cached, Object owner) {
        throw new FieldsealNotSupportedException(label() + ": encrypted attributes are never "
                + "cached (docs/29 §1)");
    }

    private String label() {
        Binding b = binding;
        return b == null ? attribute : b.spec.label;
    }
}
