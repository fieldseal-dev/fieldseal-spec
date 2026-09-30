package dev.fieldseal.hibernate;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.hibernate.SessionFactory;
import org.hibernate.engine.spi.SessionFactoryImplementor;

/** Operations on a whole session factory (docs/29 §7). */
public final class FieldsealHibernate {
    private FieldsealHibernate() {}

    /**
     * What {@link #warm} started, and what it could not.
     *
     * @param done completes when the core's {@code warm} does
     * @param skipped the tenant-bound columns and indexes left cold because no tenant was named:
     *     the adapter cannot enumerate a deployment's tenants
     */
    public record Warming(CompletableFuture<Void> done, List<String> skipped) {}

    /**
     * Primes the core's key cache for every declared column and index, for each of {@code
     * tenants} where a column is tenant-bound. Under an envelope provider nothing in the value
     * path may call the KMS (spec §11.2), so something must warm the cache before the first
     * encrypted read or write; index keys are warmed too, because spec §5.2 makes the index key a
     * sibling of the data key rather than something derived from it.
     */
    public static Warming warm(SessionFactory sessionFactory, Collection<?> tenants) {
        FieldsealRuntime runtime = runtime(sessionFactory);
        List<FieldContext> contexts = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (FieldsealRuntime.EntityPlan plan : runtime.plans()) {
            for (ColumnSpec c : plan.columns()) {
                add(contexts, skipped, c.label, c.tenantBound, tenants, t -> c.context(t));
            }
            for (IndexSpec i : plan.indexes()) {
                add(contexts, skipped, i.label, i.source.tenantBound, tenants, t -> i.context(t));
            }
        }
        return new Warming(runtime.client.warm(contexts), List.copyOf(skipped));
    }

    /** The client the adapter built for {@code sessionFactory}. */
    public static Fieldseal client(SessionFactory sessionFactory) {
        return runtime(sessionFactory).client;
    }

    private static void add(List<FieldContext> contexts, List<String> skipped, String label,
            boolean tenantBound, Collection<?> tenants,
            java.util.function.Function<Object, FieldContext> make) {
        if (!tenantBound) {
            contexts.add(make.apply(null));
        } else if (tenants.isEmpty()) {
            skipped.add(label);
        } else {
            for (Object t : tenants) {
                contexts.add(make.apply(t));
            }
        }
    }

    private static FieldsealRuntime runtime(SessionFactory sessionFactory) {
        SessionFactoryImplementor sf = sessionFactory.unwrap(SessionFactoryImplementor.class);
        if (sf.getSessionFactoryOptions().getCustomSqmTranslatorFactory()
                instanceof FieldsealSqmTranslatorFactory f) {
            return f.runtime();
        }
        throw new FieldsealConfigurationException("FS-H005: this session factory is not "
                + "configured for Fieldseal");
    }
}
