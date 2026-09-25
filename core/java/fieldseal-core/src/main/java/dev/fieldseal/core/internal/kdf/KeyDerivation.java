package dev.fieldseal.core.internal.kdf;

import dev.fieldseal.core.internal.registry.Suite;
import java.nio.charset.StandardCharsets;

/**
 * The two derivations spec §5 and §7 build on the suite KDF. Both take {@code canonical_context}
 * already encoded: {@code kdf} may not depend on {@code context} (docs/09 §1), so {@code api}
 * encodes it and passes the bytes.
 */
public final class KeyDerivation {

    /** spec §7.2's fixed salt: 18 ASCII bytes. */
    static final byte[] INDEX_SALT = "fieldseal-index-v1".getBytes(StandardCharsets.US_ASCII);

    /** spec §7.2: the index key is 32 bytes. */
    public static final int INDEX_KEY_LEN = 32;

    private KeyDerivation() {}

    /**
     * spec §5.3: {@code record_key = KDF(tenant_dek, salt = key_id ‖ msg_seed,
     * info = canonical_context(ctx), suite.key_length)}. The caller erases the result
     * (docs/09 §3.1 step 13, §3.2 step 6).
     */
    public static byte[] recordKey(Suite suite, byte[] tenantDek, byte[] keyId, byte[] msgSeed,
            byte[] canonicalContext) {
        return Hkdf.derive(tenantDek, recordKeySalt(keyId, msgSeed), canonicalContext,
                suite.keyLen());
    }

    /** {@code key_id ‖ msg_seed}: the spec §5.3 salt, exposed so that the harness can assert it. */
    public static byte[] recordKeySalt(byte[] keyId, byte[] msgSeed) {
        byte[] salt = new byte[keyId.length + msgSeed.length];
        System.arraycopy(keyId, 0, salt, 0, keyId.length);
        System.arraycopy(msgSeed, 0, salt, keyId.length, msgSeed.length);
        return salt;
    }

    /**
     * spec §7.2: {@code index_key = KDF(tenant_index_key, salt = "fieldseal-index-v1",
     * info = canonical_context(ctx with purpose = "index:<id>", row_id = null), 32)}. The caller
     * supplies that {@code info}; {@code context.CanonicalContext.encodeForIndexKey} builds it.
     */
    public static byte[] indexKey(byte[] tenantIndexKey, byte[] canonicalContextWithoutRow) {
        // A copy, as Commitment passes its label: the constant is never handed out.
        return Hkdf.derive(tenantIndexKey, INDEX_SALT.clone(), canonicalContextWithoutRow,
                INDEX_KEY_LEN);
    }

    /** The spec §7.2 salt, for the harness to assert; a copy. */
    public static byte[] indexSalt() {
        return INDEX_SALT.clone();
    }
}
