package dev.fieldseal.core.internal.context;

import java.util.regex.Pattern;

/**
 * The spec §6.1 {@code purpose} grammar:
 *
 * <pre>
 * purpose  = "encrypt" / "index:" index-id
 * index-id = 1*32( %x61-7A / %x30-39 / "-" )
 * </pre>
 *
 * <p>An identifier outside it is refused as a configuration error when its index is declared,
 * never at call time (spec §6.1). That refusal belongs to index declaration (S5). By the time a
 * purpose reaches {@link CanonicalContext#encode} it came from the core, so a bad one there is a
 * bug in the core and is treated as one.
 */
public final class Purpose {

    public static final String ENCRYPT = "encrypt";

    public static final String INDEX_PREFIX = "index:";

    private static final Pattern INDEX_ID = Pattern.compile("[a-z0-9-]{1,32}");

    private Purpose() {}

    /** Whether {@code purpose} is in the spec §6.1 grammar. */
    public static boolean isValid(String purpose) {
        if (ENCRYPT.equals(purpose)) {
            return true;
        }
        return purpose != null && purpose.startsWith(INDEX_PREFIX)
                && isValidIndexId(purpose.substring(INDEX_PREFIX.length()));
    }

    /** Whether {@code indexId} is a spec §6.1 {@code index-id}. */
    public static boolean isValidIndexId(String indexId) {
        return indexId != null && INDEX_ID.matcher(indexId).matches();
    }
}
