package dev.fieldseal.hibernate;

import dev.fieldseal.core.Fieldseal;

/**
 * Configures the client the adapter builds (docs/29 §4.1). The builder it receives already carries
 * every index the entities declare; the configurer adds the key provider, the suites and the read
 * mode, and the adapter builds it, so that the core's construction-time validation runs against
 * the indexes actually declared. Replacing the indexes is refused at startup (FS-H004).
 */
@FunctionalInterface
public interface FieldsealConfigurer {
    void configure(Fieldseal.Builder builder);
}
