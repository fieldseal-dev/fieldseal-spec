package dev.fieldseal.hibernate;

import dev.fieldseal.core.Fieldseal;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.event.spi.PreInsertEvent;
import org.hibernate.event.spi.PreInsertEventListener;
import org.hibernate.event.spi.PreUpdateEvent;
import org.hibernate.event.spi.PreUpdateEventListener;
import org.hibernate.event.spi.PreUpsertEvent;
import org.hibernate.event.spi.PreUpsertEventListener;
import org.hibernate.persister.entity.EntityPersister;

/**
 * The write path (docs/29 §2.1). Before Hibernate binds an {@code INSERT}, {@code UPDATE} or
 * upsert, this replaces each encrypted attribute's state entry with a {@link Sealed} value and
 * writes each blind index, to the state entry and to the entity. The state array is the one the
 * statement binds and the one Hibernate keeps as its dirty-checking snapshot, which the adapter's
 * tests pin ({@code HibernateBehaviourTest}); the entity keeps its plaintext.
 */
final class SealingListener
        implements PreInsertEventListener, PreUpdateEventListener, PreUpsertEventListener {
    private static final long serialVersionUID = 1L;

    private final transient FieldsealRuntime runtime;
    /** Property positions per entity, resolved from the persister on first use. */
    private final transient Map<String, Slots> slots = new ConcurrentHashMap<>();

    private record Slots(int[] columns, int[] indexes, int[] sources) {}

    SealingListener(FieldsealRuntime runtime) {
        this.runtime = runtime;
    }

    @Override
    public boolean onPreInsert(PreInsertEvent event) {
        seal(event.getPersister(), event.getEntity(), event.getState(), null,
                event.getSession());
        return false;
    }

    @Override
    public boolean onPreUpdate(PreUpdateEvent event) {
        seal(event.getPersister(), event.getEntity(), event.getState(), event.getOldState(),
                event.getSession());
        return false;
    }

    @Override
    public boolean onPreUpsert(PreUpsertEvent event) {
        seal(event.getPersister(), event.getEntity(), event.getState(), null, event.getSession());
        return false;
    }

    private void seal(EntityPersister persister, Object entity, Object[] state, Object[] old,
            SharedSessionContractImplementor session) {
        FieldsealRuntime.EntityPlan plan = runtime.plan(persister.getEntityName());
        if (plan == null) {
            return;
        }
        Slots s = slots.computeIfAbsent(plan.entityName(), n -> resolve(plan, persister));
        Fieldseal client = runtime.client;

        // Every index first, from the plaintext still in the state array: the index and the
        // envelope are derived from the same rendering, and sealing replaces that plaintext.
        for (int i = 0; i < plan.indexes().size(); i++) {
            IndexSpec ix = plan.indexes().get(i);
            int src = s.sources[i];
            Object value = plain(state[src]);
            byte[] index;
            if (value == null) {
                index = null; // spec §10.2: the sibling is NULL exactly when its source is
            } else if (old != null && old[s.indexes[i]] != null
                    && sameValue(ix.source, value, plain(old[src]))) {
                // Unchanged source: keep the stored index rather than pay Argon2id again. This
                // also undoes an assignment the application made to the sibling itself.
                index = ((byte[]) old[s.indexes[i]]).clone();
            } else {
                index = Indexing.derive(client, ix, ix.source.codec.render(value),
                        ix.context(session));
            }
            state[s.indexes[i]] = index;
            persister.setValue(entity, s.indexes[i], index == null ? null : index.clone());
        }

        for (int i = 0; i < plan.columns().size(); i++) {
            ColumnSpec col = plan.columns().get(i);
            int slot = s.columns[i];
            Object value = state[slot];
            if (value == null || value instanceof Sealed) {
                continue;
            }
            byte[] envelope = client.encrypt(col.codec.render(value), col.context(session));
            state[slot] = new Sealed(col, value, envelope);
        }
    }

    private static Object plain(Object v) {
        return v instanceof Sealed s ? s.plaintext : v;
    }

    /** Equal as spec §3.6 renders them: the index is a function of the rendering. */
    private static boolean sameValue(ColumnSpec col, Object a, Object b) {
        return b != null && java.util.Arrays.equals(col.codec.render(a), col.codec.render(b));
    }

    private static Slots resolve(FieldsealRuntime.EntityPlan plan, EntityPersister persister) {
        String[] names = persister.getPropertyNames();
        int[] columns = new int[plan.columns().size()];
        for (int i = 0; i < columns.length; i++) {
            columns[i] = position(names, plan.columns().get(i).attribute, plan.entityName());
        }
        int[] indexes = new int[plan.indexes().size()];
        int[] sources = new int[indexes.length];
        for (int i = 0; i < indexes.length; i++) {
            IndexSpec ix = plan.indexes().get(i);
            indexes[i] = position(names, ix.attribute, plan.entityName());
            sources[i] = position(names, ix.source.attribute, plan.entityName());
        }
        return new Slots(columns, indexes, sources);
    }

    private static int position(String[] names, String attribute, String entity) {
        for (int i = 0; i < names.length; i++) {
            if (names[i].equals(attribute)) {
                return i;
            }
        }
        throw new IllegalStateException(entity + " has no property " + attribute);
    }
}
