package dev.fieldseal.hibernate;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.IndexDeclaration;
import org.hibernate.engine.spi.SharedSessionContractImplementor;

/** One {@link BlindIndex} attribute, as the integrator resolved it. Immutable. */
final class IndexSpec {
    final String attribute;
    /** {@code Entity.attribute}, for messages. */
    final String label;
    final ColumnSpec source;
    final String indexId;
    final IndexDeclaration declaration;

    IndexSpec(String attribute, String label, ColumnSpec source, IndexDeclaration declaration) {
        this.attribute = attribute;
        this.label = label;
        this.source = source;
        this.indexId = declaration.indexId();
        this.declaration = declaration;
    }

    FieldContext context(SharedSessionContractImplementor session) {
        return source.context(session).forIndex(indexId);
    }

    FieldContext context(Object tenant) {
        return source.context(tenant).forIndex(indexId);
    }
}
