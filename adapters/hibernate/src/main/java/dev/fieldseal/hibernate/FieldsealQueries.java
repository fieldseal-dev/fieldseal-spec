package dev.fieldseal.hibernate;

import dev.fieldseal.core.errors.InvalidArgumentError;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.hibernate.SharedSessionContract;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.persister.entity.EntityPersister;

/**
 * L2 (a): equality over a blind index, re-verified (docs/29 §3.1, spec §7.5).
 *
 * <pre>{@code
 * List<Patient> hits = FieldsealQueries.of(session, Patient.class)
 *         .whereIndex("emailIndex", "ada@example.com")
 *         .where("status", Status.ACTIVE)
 *         .list();
 * }</pre>
 *
 * <p>The query is a Criteria query with each derived index as an ordinary parameter, {@code AND}ed
 * with the ordinary equalities. The index returns candidates, which include rows whose value
 * differs but collides under spec §7.4's truncation; every candidate's decrypted source value is
 * compared with the queried one under the index's own normalizer (spec §7.5, G19), and a row that
 * does not match is dropped. The surface is conjunctive on purpose: under {@code AND} per-term
 * verification is exact, and there is no negation, {@code OR} or pagination (docs/12 §3.2's
 * table gives the reasons).
 *
 * <p>Not thread-safe; build one per query.
 */
public final class FieldsealQueries<T> {

    private record Term(IndexSpec index, List<byte[]> derived, List<byte[]> normalized) {}

    private record Plain(String attribute, Object value) {}

    private final SharedSessionContractImplementor session;
    private final Class<T> type;
    private final FieldsealRuntime runtime;
    private final FieldsealRuntime.EntityPlan plan;
    private final EntityPersister persister;
    private final List<Term> terms = new ArrayList<>();
    private final List<Plain> plains = new ArrayList<>();
    private boolean verify = true;

    private FieldsealQueries(SharedSessionContract session, Class<T> type) {
        this.session = session instanceof SharedSessionContractImplementor s ? s
                : session.unwrap(SharedSessionContractImplementor.class);
        this.type = type;
        SessionFactoryImplementor sf = this.session.getFactory();
        if (!(sf.getSessionFactoryOptions().getCustomSqmTranslatorFactory()
                instanceof FieldsealSqmTranslatorFactory f)) {
            throw new FieldsealConfigurationException("FS-H005: this session factory is not "
                    + "configured for Fieldseal");
        }
        this.runtime = f.runtime();
        this.persister = sf.getMappingMetamodel().getEntityDescriptor(type);
        this.plan = runtime.plan(persister.getEntityName());
    }

    /** A finder over {@code type} in {@code session} (a {@code Session} or a {@code StatelessSession}). */
    public static <T> FieldsealQueries<T> of(SharedSessionContract session, Class<T> type) {
        return new FieldsealQueries<>(session, type);
    }

    /** Rows whose indexed source equals {@code value} under the index's normalizer. */
    public FieldsealQueries<T> whereIndex(String indexAttribute, Object value) {
        return whereIndexIn(indexAttribute, List.of(value));
    }

    /**
     * Rows whose indexed source equals any of {@code values}: spec §7.10's membership, one
     * {@code IN} over the derived index values. An empty collection matches nothing.
     */
    public FieldsealQueries<T> whereIndexIn(String indexAttribute, Collection<?> values) {
        IndexSpec ix = plan == null ? null : plan.index(indexAttribute);
        if (ix == null) {
            throw new FieldsealNotSupportedException(persister.getEntityName() + "."
                    + indexAttribute + " is not a @BlindIndex attribute");
        }
        List<byte[]> derived = new ArrayList<>();
        List<byte[]> normalized = new ArrayList<>();
        for (Object v : values) {
            if (v == null) {
                throw new FieldsealNotSupportedException(ix.label + ": null is not a value; "
                        + "use where(\"" + ix.source.attribute + "\", null) for `is null`");
            }
            byte[] rendered = ix.source.codec.render(v);
            derived.add(Indexing.derive(runtime.client, ix, rendered, ix.context(session)));
            normalized.add(normalize(ix, rendered));
        }
        terms.add(new Term(ix, derived, normalized));
        return this;
    }

    /**
     * An ordinary equality, answered in SQL; {@code null} means {@code is null}. On an encrypted
     * attribute only {@code null} is allowed, since `is [not] null` is exact over envelopes
     * (spec §10.2); an index attribute goes through {@link #whereIndex}.
     */
    public FieldsealQueries<T> where(String attribute, Object value) {
        if (plan != null && plan.index(attribute) != null) {
            throw new FieldsealNotSupportedException(plan.index(attribute).label
                    + " is a blind index: use whereIndex");
        }
        if (plan != null && plan.column(attribute) != null && value != null) {
            throw new FieldsealNotSupportedException(plan.column(attribute).label
                    + " is encrypted: compare it through its @BlindIndex with whereIndex");
        }
        plains.add(new Plain(attribute, value));
        return this;
    }

    /**
     * Return the index's candidates unverified: spec §7.4's bucket, which includes rows whose
     * value differs. The caller takes on spec §7.5. It lifts nothing else.
     */
    public FieldsealQueries<T> candidates() {
        verify = false;
        return this;
    }

    /** The matching rows, verified unless {@link #candidates} was called. */
    public List<T> list() {
        List<T> rows = run();
        if (!verify || terms.isEmpty()) {
            return rows;
        }
        List<T> out = new ArrayList<>(rows.size());
        for (T row : rows) {
            if (matches(row)) {
                out.add(row);
            }
        }
        return out;
    }

    /** The number of matching rows, counted after verification. */
    public long count() {
        return list().size();
    }

    /** The first matching row, if any. The order is the database's: not a sort. */
    public Optional<T> first() {
        List<T> rows = list();
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    /** Whether any row matches. */
    public boolean exists() {
        return !list().isEmpty();
    }

    private List<T> run() {
        CriteriaBuilder cb = session.getCriteriaBuilder();
        CriteriaQuery<T> q = cb.createQuery(type);
        Root<T> root = q.from(type);
        List<Predicate> ps = new ArrayList<>();
        for (Term t : terms) {
            if (t.derived.isEmpty()) {
                return List.of();
            }
            ps.add(t.derived.size() == 1 ? cb.equal(root.get(t.index.attribute), t.derived.get(0))
                    : root.get(t.index.attribute).in(t.derived));
        }
        for (Plain p : plains) {
            ps.add(p.value == null ? cb.isNull(root.get(p.attribute))
                    : cb.equal(root.get(p.attribute), p.value));
        }
        q.select(root).where(ps.toArray(Predicate[]::new));
        var query = session.createSelectionQuery(q);
        // A cached plan would skip translation, and translation is where the walker checks the
        // scope: with no plan cached, the scope cannot leak to a query outside it.
        query.setQueryPlanCacheable(false);
        FinderScope scope = FinderScope.enter();
        try {
            return query.getResultList();
        } finally {
            scope.close();
        }
    }

    private boolean matches(T row) {
        for (Term t : terms) {
            int slot = persister.getPropertyIndex(t.index.source.attribute);
            Object stored = persister.getValue(row, slot);
            if (stored == null) {
                return false;
            }
            byte[] got = normalize(t.index, t.index.source.codec.render(stored));
            boolean any = false;
            for (byte[] want : t.normalized) {
                if (Arrays.equals(got, want)) {
                    any = true;
                    break;
                }
            }
            if (!any) {
                return false;
            }
        }
        return true;
    }

    /**
     * Spec §7.5's comparison form: the value under the index's normalizer, through the core, or
     * its raw bytes where the normalizer refuses it, so that two refused values are equal only
     * byte for byte (G19).
     */
    private static byte[] normalize(IndexSpec ix, byte[] rendered) {
        try {
            return ix.declaration.normalize().normalize(rendered);
        } catch (InvalidArgumentError e) {
            return rendered;
        }
    }
}
