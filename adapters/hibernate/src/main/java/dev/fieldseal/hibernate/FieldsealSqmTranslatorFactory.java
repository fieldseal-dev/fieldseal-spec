package dev.fieldseal.hibernate;

import org.hibernate.engine.spi.LoadQueryInfluencers;
import org.hibernate.query.spi.QueryOptions;
import org.hibernate.query.spi.QueryParameterBindings;
import org.hibernate.query.sqm.internal.DomainParameterXref;
import org.hibernate.query.sqm.sql.SqmTranslator;
import org.hibernate.query.sqm.sql.SqmTranslatorFactory;
import org.hibernate.query.sqm.sql.StandardSqmTranslatorFactory;
import org.hibernate.query.sqm.tree.SqmDmlStatement;
import org.hibernate.query.sqm.tree.select.SqmSelectStatement;
import org.hibernate.sql.ast.spi.SqlAstCreationContext;
import org.hibernate.sql.ast.tree.MutationStatement;
import org.hibernate.sql.ast.tree.select.SelectStatement;

/**
 * The query-side refusals (docs/29 §3.3). Configure it as {@code hibernate.query.sqm.translator};
 * the integrator refuses to start without it (FS-H005). Every HQL and Criteria statement passes
 * through here as a semantic tree before any SQL is generated, and {@link RefusalWalker} refuses
 * the shapes spec §10.2 forbids. It then hands the statement to the translator Hibernate would
 * have used: the dialect's, or the standard one.
 */
public final class FieldsealSqmTranslatorFactory implements SqmTranslatorFactory {

    private static final SqmTranslatorFactory STANDARD = new StandardSqmTranslatorFactory();
    /** Statements walked, process-wide: pins which paths reach this factory (docs/29 §1). */
    static final java.util.concurrent.atomic.AtomicLong WALKED =
            new java.util.concurrent.atomic.AtomicLong();
    private volatile FieldsealRuntime runtime;

    /** Instantiated by Hibernate from the setting. */
    public FieldsealSqmTranslatorFactory() {}

    void bind(FieldsealRuntime runtime) {
        this.runtime = runtime;
    }

    FieldsealRuntime runtime() {
        FieldsealRuntime r = runtime;
        if (r == null) {
            throw new FieldsealConfigurationException("FS-H005: the Fieldseal query translator "
                    + "is configured but the Fieldseal integrator did not run for this session "
                    + "factory");
        }
        return r;
    }

    @Override
    public SqmTranslator<SelectStatement> createSelectTranslator(
            SqmSelectStatement<?> statement, QueryOptions queryOptions,
            DomainParameterXref domainParameterXref, QueryParameterBindings bindings,
            LoadQueryInfluencers influencers, SqlAstCreationContext creationContext,
            boolean deduplicateSelectionItems) {
        WALKED.incrementAndGet();
        statement.accept(new RefusalWalker(runtime(), FinderScope.active()));
        return delegate(creationContext).createSelectTranslator(statement, queryOptions,
                domainParameterXref, bindings, influencers, creationContext,
                deduplicateSelectionItems);
    }

    @Override
    public SqmTranslator<? extends MutationStatement> createMutationTranslator(
            SqmDmlStatement<?> statement, QueryOptions queryOptions,
            DomainParameterXref domainParameterXref, QueryParameterBindings bindings,
            LoadQueryInfluencers influencers, SqlAstCreationContext creationContext) {
        WALKED.incrementAndGet();
        statement.accept(new RefusalWalker(runtime(), false));
        return delegate(creationContext).createMutationTranslator(statement, queryOptions,
                domainParameterXref, bindings, influencers, creationContext);
    }

    private static SqmTranslatorFactory delegate(SqlAstCreationContext creationContext) {
        SqmTranslatorFactory dialects = creationContext.getDialect().getSqmTranslatorFactory();
        return dialects != null ? dialects : STANDARD;
    }
}
