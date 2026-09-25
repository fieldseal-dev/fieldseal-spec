package dev.fieldseal.core;

import dev.fieldseal.core.errors.ConfigurationError;
import dev.fieldseal.core.errors.KeyUnavailableError;
import dev.fieldseal.core.internal.kdf.Hkdf;
import dev.fieldseal.core.keyprovider.EnvelopeHeader;
import dev.fieldseal.core.keyprovider.KeyMaterial;
import dev.fieldseal.core.keyprovider.KeyProvider;
import dev.fieldseal.core.keyprovider.KeyRequest;
import dev.fieldseal.core.keyprovider.WrappedKeyStore;
import dev.fieldseal.core.keyprovider.Wrapper;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * The three key providers spec §8 requires every implementation to ship (docs/09 §8.2).
 *
 * <p>They are built here, in the api package, rather than in {@code keyprovider}: docs/09 §1 lets
 * {@code keyprovider} depend on {@code errors} only, and the derived provider needs {@code kdf}
 * while the envelope provider needs {@code cache}. The api package may depend on everything, so it
 * assembles them, and {@code keyprovider} keeps the SPI (docs/07 §7, 2026-09-25).
 *
 * <p>Each returns a fresh copy of its key material on every call (docs/09 §8.1).
 */
public final class KeyProviders {

    private KeyProviders() {}

    /**
     * A fixed DEK and a fixed index key under one {@code key_id}. <b>For tests and development
     * only</b> (spec §8): a client built with it warns through its {@code onWarning} hook unless
     * {@code FIELDSEAL_TEST_MODE=1}.
     *
     * <p>Two keys, not one, because spec §8 forbids returning the DEK for an index purpose: the
     * index key is the DEK's sibling (spec §5.2), and they must differ.
     *
     * @throws ConfigurationError if a key is empty, the keys are equal, or {@code keyId} is not
     *     16 bytes
     */
    public static KeyProvider staticKeys(byte[] dek, byte[] indexKey, byte[] keyId) {
        return new StaticProvider(dek, indexKey, keyId);
    }

    /**
     * Keys derived per tenant from one root secret, by HKDF-SHA-512 (spec §8: "an approved KDF";
     * docs/09 §8.2). The DEK, the index key and the {@code key_id} each take their own salt, so
     * the index key is a sibling of the DEK and never equal to it (spec §5.2). No I/O. There is
     * one key version per tenant; rotating the root secret is a new provider.
     *
     * @throws ConfigurationError if {@code rootSecret} is shorter than 32 bytes
     */
    public static KeyProvider derived(byte[] rootSecret) {
        return new DerivedProvider(rootSecret);
    }

    /**
     * KMS-wrapped keys, the production path (spec §8). {@code store} lists each tenant's
     * wrapped keys and {@code wrapper} unwraps them, both from {@code warm} only. The value path
     * reads the client's DEK cache and never waits on the KMS: a key that was not warmed, or has
     * aged out or used up its budget, is {@code KEY_UNAVAILABLE} until the next {@code warm}.
     * That is the fail-closed degradation mode (spec §8.1).
     *
     * <p>The provider this returns is unbound. A client built with it, and with a {@link
     * CachePolicy}, binds it to a cache of its own; called directly, it serves nothing.
     */
    public static KeyProvider envelope(Wrapper wrapper, WrappedKeyStore store) {
        if (wrapper == null || store == null) {
            throw new ConfigurationError("the envelope provider needs a Wrapper and a"
                    + " WrappedKeyStore");
        }
        return new EnvelopeProvider.Unbound(wrapper, store);
    }

    static final class StaticProvider implements KeyProvider {
        private final byte[] dek;
        private final byte[] indexKey;
        private final byte[] keyId;

        StaticProvider(byte[] dek, byte[] indexKey, byte[] keyId) {
            if (dek == null || dek.length == 0 || indexKey == null || indexKey.length == 0) {
                throw new ConfigurationError("the static provider needs a DEK and an index key");
            }
            if (Arrays.equals(dek, indexKey)) {
                throw new ConfigurationError("the index key must differ from the DEK (spec §8,"
                        + " §5.2)");
            }
            if (keyId == null || keyId.length != KeyMaterial.KEY_ID_LEN) {
                throw new ConfigurationError("keyId must be 16 bytes (spec §3.1)");
            }
            this.dek = dek.clone();
            this.indexKey = indexKey.clone();
            this.keyId = keyId.clone();
        }

        @Override
        public KeyMaterial encryptionKey(KeyRequest request) {
            return new KeyMaterial((request.isIndex() ? indexKey : dek).clone(), keyId.clone());
        }

        @Override
        public List<byte[]> decryptionKeys(EnvelopeHeader header) {
            return Arrays.equals(header.keyId(), keyId) ? List.of(dek.clone()) : List.of();
        }
    }

    static final class DerivedProvider implements KeyProvider {
        static final int MIN_ROOT = 32;
        private static final byte[] DEK_SALT = ascii("fieldseal-derived-dek-v1");
        private static final byte[] INDEX_SALT = ascii("fieldseal-derived-index-v1");
        private static final byte[] KEY_ID_SALT = ascii("fieldseal-derived-key-id-v1");
        private final byte[] root;

        DerivedProvider(byte[] rootSecret) {
            if (rootSecret == null || rootSecret.length < MIN_ROOT) {
                throw new ConfigurationError("the derived provider's root secret must be at"
                        + " least " + MIN_ROOT + " bytes");
            }
            this.root = rootSecret.clone();
        }

        /** {@code 0x00} for no tenant, {@code 0x01 ‖ tenant} otherwise: injective. */
        private static byte[] scope(byte[] tenant) {
            if (tenant == null) {
                return new byte[] {0};
            }
            byte[] s = new byte[tenant.length + 1];
            s[0] = 1;
            System.arraycopy(tenant, 0, s, 1, tenant.length);
            return s;
        }

        private byte[] keyId(byte[] scope) {
            return Hkdf.derive(root, KEY_ID_SALT.clone(), scope, KeyMaterial.KEY_ID_LEN);
        }

        @Override
        public KeyMaterial encryptionKey(KeyRequest request) {
            byte[] scope = scope(request.tenantId());
            byte[] salt = (request.isIndex() ? INDEX_SALT : DEK_SALT).clone();
            return new KeyMaterial(Hkdf.derive(root, salt, scope, 32), keyId(scope));
        }

        @Override
        public List<byte[]> decryptionKeys(EnvelopeHeader header) {
            byte[] scope = scope(header.context().tenantId());
            if (!Arrays.equals(keyId(scope), header.keyId())) {
                return List.of();
            }
            return List.of(Hkdf.derive(root, DEK_SALT.clone(), scope, 32));
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /** Used only by the unbound envelope provider's refusal. */
    static KeyUnavailableError unbound() {
        return new KeyUnavailableError("this envelope provider is not bound to a cache: pass it"
                + " to Fieldseal.builder() with a cachePolicy");
    }

    /** The unbound provider's {@code warm}: nothing to warm into. */
    static CompletableFuture<Void> failed(RuntimeException e) {
        return CompletableFuture.failedFuture(e);
    }
}
