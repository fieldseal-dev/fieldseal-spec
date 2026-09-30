package dev.fieldseal.hibernate;

import dev.fieldseal.core.Fieldseal;
import java.util.List;
import java.util.Map;

/**
 * What the integrator resolved for one session factory: the client it built, and every entity's
 * encrypted and index attributes. The listener, the query walker and the finder read it; nothing
 * changes it after the session factory is built.
 */
final class FieldsealRuntime {

    /** An entity's encrypted and index attributes. */
    record EntityPlan(String entityName, List<ColumnSpec> columns, List<IndexSpec> indexes) {
        ColumnSpec column(String attribute) {
            for (ColumnSpec c : columns) {
                if (c.attribute.equals(attribute)) {
                    return c;
                }
            }
            return null;
        }

        IndexSpec index(String attribute) {
            for (IndexSpec i : indexes) {
                if (i.attribute.equals(attribute)) {
                    return i;
                }
            }
            return null;
        }
    }

    final Fieldseal client;
    private final Map<String, EntityPlan> plans;

    FieldsealRuntime(Fieldseal client, Map<String, EntityPlan> plans) {
        this.client = client;
        this.plans = Map.copyOf(plans);
    }

    /** The plan for {@code entityName}, or null if it has no encrypted attribute. */
    EntityPlan plan(String entityName) {
        return plans.get(entityName);
    }

    Iterable<EntityPlan> plans() {
        return plans.values();
    }

    /** The encrypted attribute {@code entity.attribute}, or null. */
    ColumnSpec column(String entityName, String attribute) {
        EntityPlan p = plans.get(entityName);
        return p == null ? null : p.column(attribute);
    }

    /** The index attribute {@code entity.attribute}, or null. */
    IndexSpec index(String entityName, String attribute) {
        EntityPlan p = plans.get(entityName);
        return p == null ? null : p.index(attribute);
    }
}
