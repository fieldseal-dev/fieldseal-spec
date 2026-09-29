package dev.fieldseal.hibernate;

import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.IndexDeclaration;
import dev.fieldseal.core.ValidatedIndex;
import dev.fieldseal.core.errors.ConfigurationError;
import java.lang.reflect.AnnotatedElement;
import java.nio.ByteBuffer;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.spi.BootstrapContext;
import org.hibernate.engine.config.spi.ConfigurationService;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.mapping.BasicValue;
import org.hibernate.mapping.Collection;
import org.hibernate.mapping.Column;
import org.hibernate.mapping.Component;
import org.hibernate.mapping.PersistentClass;
import org.hibernate.mapping.Property;
import org.hibernate.mapping.UniqueKey;
import org.hibernate.mapping.Value;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;
import org.hibernate.type.CustomType;

/**
 * Wires the adapter into a session factory and runs docs/29 §5's startup checks. Loaded by
 * Hibernate through {@code META-INF/services}. A session factory with no {@link Encrypted}
 * attribute is left untouched.
 */
public final class FieldsealIntegrator implements Integrator {

    @Override
    public void integrate(Metadata metadata, BootstrapContext bootstrapContext,
            SessionFactoryImplementor sessionFactory) {
        Map<String, EntityDraft> drafts = new LinkedHashMap<>();
        for (PersistentClass pc : metadata.getEntityBindings()) {
            EntityDraft d = scan(pc);
            if (d != null) {
                drafts.put(pc.getEntityName(), d);
            }
        }
        if (drafts.isEmpty()) {
            return;
        }

        if (!(sessionFactory.getSessionFactoryOptions().getCustomSqmTranslatorFactory()
                instanceof FieldsealSqmTranslatorFactory translator)) {
            throw new FieldsealConfigurationException("FS-H005: entities with encrypted "
                    + "attributes need hibernate.query.sqm.translator = "
                    + FieldsealSqmTranslatorFactory.class.getName() + ". Without it every "
                    + "query-side refusal but the binding guard is absent, silently "
                    + "(docs/29 §3.3). FieldsealSettings.apply(...) sets it");
        }

        // Build the specs and the index declarations.
        Map<String, FieldsealRuntime.EntityPlan> plans = new LinkedHashMap<>();
        List<IndexDeclaration> declarations = new ArrayList<>();
        Map<EncryptedType, ColumnSpec> types = new IdentityHashMap<>();
        for (EntityDraft d : drafts.values()) {
            List<ColumnSpec> columns = new ArrayList<>();
            Set<String> columnUuids = new HashSet<>();
            for (Property p : d.encrypted) {
                EncryptedType t = encryptedType(p.getValue());
                String label = d.simpleName + "." + p.getName();
                byte[] columnUuid = uuid(t.annotation().column(), label, "column");
                if (!columnUuids.add(java.util.HexFormat.of().formatHex(columnUuid))) {
                    throw new FieldsealConfigurationException("FS-H001: " + label + " reuses a "
                            + "column UUID of " + d.simpleName + " (spec §6.1: unique within "
                            + "the table)");
                }
                Codec codec = Codec.of(t.javaType(), label);
                if (codec == null) {
                    throw new FieldsealConfigurationException("FS-H009: " + label + " is a "
                            + t.javaType().getName() + ", which spec §3.6 has no logical type "
                            + "for. Supported: " + Codec.SUPPORTED + ". Store a String you "
                            + "render yourself (docs/29 §2.2)");
                }
                ColumnSpec spec = new ColumnSpec(d.pc.getEntityName(), p.getName(), label,
                        d.tableUuid, columnUuid, t.annotation().tenantBound(), codec);
                if (types.put(t, spec) != null) {
                    throw new FieldsealConfigurationException("FS-H001: one EncryptedType "
                            + "instance is mapped twice (" + label + ")");
                }
                columns.add(spec);
            }
            FieldsealRuntime.EntityPlan draftPlan =
                    new FieldsealRuntime.EntityPlan(d.pc.getEntityName(), columns, List.of());
            List<IndexSpec> indexes = new ArrayList<>();
            for (Map.Entry<Property, BlindIndex> e : d.indexes.entrySet()) {
                Property p = e.getKey();
                BlindIndex a = e.getValue();
                String label = d.simpleName + "." + p.getName();
                ColumnSpec source = draftPlan.column(a.source());
                if (source == null) {
                    throw new FieldsealConfigurationException("FS-H003: " + label + " indexes '"
                            + a.source() + "', which is not an @Encrypted attribute of "
                            + d.simpleName);
                }
                if (javaType(p, d.pc) != byte[].class) {
                    throw new FieldsealConfigurationException("FS-H003: " + label + " is a "
                            + "@BlindIndex and must be a byte[] (spec §7.11's raw index bytes)");
                }
                IndexDeclaration decl = declaration(a, source, label);
                try {
                    Fieldseal.validateIndexDeclaration(decl);
                } catch (ConfigurationError ce) {
                    throw new FieldsealConfigurationException("FS-H003: " + label + ": the core "
                            + "refused the index declaration: " + ce.getMessage(), ce);
                }
                declarations.add(decl);
                indexes.add(new IndexSpec(p.getName(), label, source, decl));
            }
            plans.put(d.pc.getEntityName(),
                    new FieldsealRuntime.EntityPlan(d.pc.getEntityName(), columns, indexes));
        }

        Fieldseal client = client(sessionFactory, declarations);
        FieldsealRuntime runtime = new FieldsealRuntime(client, plans);
        types.forEach((t, spec) -> t.bind(spec, client));
        translator.bind(runtime);

        SealingListener listener = new SealingListener(runtime);
        EventListenerRegistry listeners =
                sessionFactory.getServiceRegistry().requireService(EventListenerRegistry.class);
        listeners.appendListeners(EventType.PRE_INSERT, listener);
        listeners.appendListeners(EventType.PRE_UPDATE, listener);
        listeners.appendListeners(EventType.PRE_UPSERT, listener);
    }

    @Override
    public void disintegrate(SessionFactoryImplementor sessionFactory,
            SessionFactoryServiceRegistry serviceRegistry) {}

    // ---- scanning ----------------------------------------------------------------------------

    private static final class EntityDraft {
        PersistentClass pc;
        String simpleName;
        byte[] tableUuid;
        final List<Property> encrypted = new ArrayList<>();
        final Map<Property, BlindIndex> indexes = new LinkedHashMap<>();
    }

    private static EntityDraft scan(PersistentClass pc) {
        String simple = pc.getMappedClass() == null ? pc.getEntityName()
                : pc.getMappedClass().getSimpleName();
        EntityDraft d = new EntityDraft();
        d.pc = pc;
        d.simpleName = simple;

        if (pc.getIdentifier() != null && touches(pc.getIdentifier(), pc, null)) {
            throw new FieldsealConfigurationException("FS-H002: the identifier of " + simple
                    + " is encrypted or a blind index; spec §7.10 forbids uniqueness and "
                    + "identity over a randomized column");
        }
        for (Property p : pc.getPropertyClosure()) {
            Value v = p.getValue();
            String label = simple + "." + p.getName();
            if (v instanceof Component || v instanceof Collection) {
                if (touches(v, pc, p)) {
                    throw new FieldsealConfigurationException("FS-H008: " + label + " is an "
                            + "embeddable or a collection holding an encrypted or index "
                            + "attribute, which v0 does not support (docs/29 §9)");
                }
                continue;
            }
            BlindIndex bi = annotation(p, pc, BlindIndex.class);
            boolean enc = encryptedType(v) != null;
            if (!enc && bi == null) {
                continue;
            }
            if (enc && bi != null) {
                throw new FieldsealConfigurationException("FS-H003: " + label + " is both "
                        + "@Encrypted and a @BlindIndex");
            }
            if (pc.getVersion() == p || p.isNaturalIdentifier() || unique(v, pc)) {
                throw new FieldsealConfigurationException("FS-H002: " + label + " is the "
                        + "version, a natural id, unique or in a unique constraint. Uniqueness "
                        + "cannot hold over randomized envelopes, and over a truncated blind "
                        + "index spec §7.4 makes collisions mandatory (spec §7.10, G12)");
            }
            if (enc) {
                d.encrypted.add(p);
            } else {
                d.indexes.put(p, bi);
            }
        }
        if (d.encrypted.isEmpty() && d.indexes.isEmpty()) {
            return null;
        }

        if (pc.getSuperclass() != null || pc.hasSubclasses()) {
            throw new FieldsealConfigurationException("FS-H008: " + simple + " is in an "
                    + "entity inheritance hierarchy and has encrypted or index attributes, "
                    + "which v0 does not support (docs/29 §9)");
        }
        FieldsealTable table = pc.getMappedClass() == null ? null
                : pc.getMappedClass().getAnnotation(FieldsealTable.class);
        if (table == null) {
            throw new FieldsealConfigurationException("FS-H001: " + simple + " has encrypted "
                    + "attributes and no @FieldsealTable (spec §6.1: the table surrogate is a "
                    + "literal in the source, never derived from a name)");
        }
        d.tableUuid = uuid(table.value(), simple, "table");
        if (pc.isCached()) {
            throw new FieldsealConfigurationException("FS-H006: " + simple + " is second-level "
                    + "cacheable and has encrypted attributes. The cache would hold their "
                    + "plaintext (spec §10.2); v0 refuses it (docs/29 §1)");
        }
        if (!d.indexes.isEmpty() && pc.useDynamicUpdate()) {
            throw new FieldsealConfigurationException("FS-H007: " + simple + " uses "
                    + "@DynamicUpdate and has a blind index. Hibernate chooses the updated "
                    + "columns before the adapter writes the index sibling, so the index would "
                    + "go stale: a silent lookup miss (docs/29 §5)");
        }
        return d;
    }

    /** Whether {@code v}, or anything nested in it, is encrypted or a blind index. */
    private static boolean touches(Value v, PersistentClass pc, Property owner) {
        if (encryptedType(v) != null) {
            return true;
        }
        if (v instanceof Component c) {
            for (Property p : c.getProperties()) {
                if (touches(p.getValue(), pc, p)
                        || annotationOn(p, c.getComponentClass(), BlindIndex.class) != null) {
                    return true;
                }
            }
            return false;
        }
        if (v instanceof Collection c) {
            return touches(c.getElement(), pc, owner);
        }
        return owner != null && annotation(owner, pc, BlindIndex.class) != null;
    }

    static EncryptedType encryptedType(Value v) {
        if (v instanceof BasicValue bv && bv.getType() instanceof CustomType<?> ct
                && ct.getUserType() instanceof EncryptedType t) {
            return t;
        }
        return null;
    }

    private static boolean unique(Value v, PersistentClass pc) {
        List<Column> cols = v.getColumns();
        for (Column c : cols) {
            if (c.isUnique()) {
                return true;
            }
        }
        for (UniqueKey uk : pc.getTable().getUniqueKeys().values()) {
            for (Column c : uk.getColumns()) {
                if (cols.contains(c)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static <A extends java.lang.annotation.Annotation> A annotation(Property p,
            PersistentClass pc, Class<A> type) {
        return annotationOn(p, pc.getMappedClass(), type);
    }

    private static <A extends java.lang.annotation.Annotation> A annotationOn(Property p,
            Class<?> owner, Class<A> type) {
        if (owner == null) {
            return null;
        }
        try {
            var member = p.getGetter(owner).getMember();
            if (member instanceof AnnotatedElement el && el.getAnnotation(type) != null) {
                return el.getAnnotation(type);
            }
        } catch (RuntimeException e) {
            // No getter Hibernate can build (a synthetic or dynamic property): no annotation.
        }
        for (Class<?> c = owner; c != null && c != Object.class; c = c.getSuperclass()) {
            try {
                A a = c.getDeclaredField(p.getName()).getAnnotation(type);
                if (a != null) {
                    return a;
                }
            } catch (NoSuchFieldException e) {
                // Look further up.
            }
        }
        return null;
    }

    private static Class<?> javaType(Property p, PersistentClass pc) {
        try {
            return p.getGetter(pc.getMappedClass()).getReturnTypeClass();
        } catch (RuntimeException e) {
            return p.getType().getReturnedClass();
        }
    }

    // ---- declarations ------------------------------------------------------------------------

    private static IndexDeclaration declaration(BlindIndex a, ColumnSpec source, String label) {
        IndexDeclaration.Builder b = IndexDeclaration.builder(source.tableUuid(),
                        source.columnUuid())
                .indexId(a.id())
                .idf(a.idf())
                .normalize(a.normalize())
                .truncateBits(a.truncateBits())
                .projectedPopulation(a.projectedPopulation())
                .skewed(a.skewed())
                .onUnindexable(a.onUnindexable());
        if (a.argon2TimeCost() != 0 || a.argon2MemoryKib() != 0) {
            b.argon2(new IndexDeclaration.Argon2Params(
                    a.argon2TimeCost() == 0 ? 3 : a.argon2TimeCost(),
                    a.argon2MemoryKib() == 0 ? 32768 : a.argon2MemoryKib()));
        }
        b.cardinalityOverride(override(a.cardinalityOverride(), label));
        b.unindexableOverride(override(a.unindexableOverride(), label));
        return b.build();
    }

    private static IndexDeclaration.ReviewedOverride override(ReviewedOverride o, String label) {
        if (o.reason().isEmpty() && o.approvedBy().isEmpty() && o.date().isEmpty()) {
            return null;
        }
        LocalDate date = null;
        if (!o.date().isEmpty()) {
            try {
                date = LocalDate.parse(o.date());
            } catch (DateTimeParseException e) {
                throw new FieldsealConfigurationException("FS-H003: " + label + ": the "
                        + "override's date '" + o.date() + "' is not an ISO-8601 date", e);
            }
        }
        return new IndexDeclaration.ReviewedOverride(o.reason(), o.approvedBy(), date);
    }

    private static byte[] uuid(String text, String where, String what) {
        UUID u;
        try {
            u = UUID.fromString(text);
        } catch (IllegalArgumentException e) {
            u = null;
        }
        if (u == null || !u.toString().equals(text.toLowerCase(java.util.Locale.ROOT))) {
            throw new FieldsealConfigurationException("FS-H001: " + where + "'s " + what
                    + " UUID '" + text + "' is not a UUID in the 8-4-4-4-12 form");
        }
        return ByteBuffer.allocate(16).putLong(u.getMostSignificantBits())
                .putLong(u.getLeastSignificantBits()).array();
    }

    // ---- the client --------------------------------------------------------------------------

    private static Fieldseal client(SessionFactoryImplementor sf,
            List<IndexDeclaration> declared) {
        Object setting = sf.getServiceRegistry().requireService(ConfigurationService.class)
                .getSettings().get(FieldsealSettings.CLIENT);
        Fieldseal client;
        if (setting instanceof FieldsealConfigurer configurer) {
            Fieldseal.Builder b = Fieldseal.builder().indexes(declared);
            configurer.configure(b);
            try {
                client = b.build();
            } catch (ConfigurationError e) {
                throw new FieldsealConfigurationException("FS-H004: the core refused the "
                        + "client configuration: " + e.getMessage(), e);
            }
        } else if (setting instanceof Fieldseal f) {
            client = f;
        } else {
            throw new FieldsealConfigurationException("FS-H004: " + FieldsealSettings.CLIENT
                    + " must be a FieldsealConfigurer or a Fieldseal client, and is "
                    + (setting == null ? "not set" : "a " + setting.getClass().getName()));
        }
        Map<String, ValidatedIndex> want = new HashMap<>();
        for (IndexDeclaration d : declared) {
            ValidatedIndex v = Fieldseal.validateIndexDeclaration(d);
            want.put(v.registryKey(), v);
        }
        if (!client.indexes().equals(want)) {
            throw new FieldsealConfigurationException("FS-H004: the client's index registry "
                    + "differs from the indexes the entities declare. A missing index fails "
                    + "every lookup on its column; an extra one derives values under rules no "
                    + "entity states, and nothing raises (docs/12 §5, E006). Declared: "
                    + want.keySet() + "; client: " + client.indexes().keySet());
        }
        return client;
    }
}
