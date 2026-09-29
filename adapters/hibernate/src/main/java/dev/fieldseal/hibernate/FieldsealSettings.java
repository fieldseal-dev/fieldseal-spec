package dev.fieldseal.hibernate;

import dev.fieldseal.core.Fieldseal;
import java.util.Map;
import org.hibernate.cfg.QuerySettings;

/** The adapter's settings (docs/29 §4.1). */
public final class FieldsealSettings {
    private FieldsealSettings() {}

    /**
     * A {@link FieldsealConfigurer}, or a prebuilt {@link Fieldseal} whose index registry equals
     * the declared one exactly (FS-H004). Required when any entity has an encrypted attribute.
     */
    public static final String CLIENT = "dev.fieldseal.hibernate.client";

    /**
     * Puts both settings the adapter needs into {@code settings}: {@link #CLIENT}, and this
     * adapter's query translator as {@code hibernate.query.sqm.translator} (FS-H005).
     */
    public static Map<String, Object> apply(Map<String, Object> settings, Object client) {
        settings.put(CLIENT, client);
        settings.put(QuerySettings.SEMANTIC_QUERY_TRANSLATOR,
                FieldsealSqmTranslatorFactory.class.getName());
        return settings;
    }
}
