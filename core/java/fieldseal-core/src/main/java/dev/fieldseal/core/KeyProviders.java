package dev.fieldseal.core;

import dev.fieldseal.core.errors.ConfigurationError;
import dev.fieldseal.core.internal.cache.DekCache;
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
import java.util.concurrent.Executor;
import java.util.function.LongSupplier;

/**
 * The three key providers spec §8 requires every implementation to ship (docs/09 §8.2).
 *
 * <p>They are built here, in the api package, rather than in {@code keyprovider}: docs/09 §1 lets
 * {@code keyprovider} depend on {@code errors} only, and the derived provider needs {@code kdf}
 * while the envelope provider needs {@code cache}. The api package may depend on everything, so it
 * assembles them, and {@code keyprovider} keeps the SPI (docs/07 §7, 2026-09-25). The envelope
 * provider is built bound to a cache of its own (#192, which revised the 2026-09-25 decision to
 * bind it per client).
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
     * wrapped keys and {@code wrapper} unwraps them, both from {@code warm} only, on the shared
     * default warm pool. The value path reads this provider's DEK cache, built from {@code policy},
     * and never waits on the KMS: a key that was not warmed, or has aged out or used up its budget,
     * is {@code KEY_UNAVAILABLE} until the next {@code warm}. That is the fail-closed degradation
     * mode (spec §8.1).
     *
     * <p>Each {@code warm} of a slot refreshes every version the store lists, evicts the versions it
     * no longer lists, and makes the first listed version active for writes, in that order and only
     * once the whole list has loaded. A failed warm never changes which key writes go out under,
     * and a version dropped from the store stops decrypting at the next successful warm of its
     * slot.
     *
     * <p><b>The cache belongs to the provider</b> (#192). Every client built with this provider
     * shares it, as docs/09 §8.3 keys the cache by provider scope: a key is unwrapped once
     * however many clients use it, its max-uses budget counts every client's encryptions, and its
     * capacity is shared too, so one client's warms can evict another client's keys. Size {@code
     * capacity} for every tenant the sharing clients serve. A client that needs a cache of its own
     * is built with a provider of its own. Called directly, the provider works as it does inside a
     * client.
     *
     * @throws ConfigurationError if any argument is null: the cache limits are security parameters
     *     with no default (spec §5.5)
     */
    public static KeyProvider envelope(Wrapper wrapper, WrappedKeyStore store, CachePolicy policy) {
        return envelopeWithClock(wrapper, store, policy, EnvelopeProvider.WARM_POOL,
                System::nanoTime);
    }

    /**
     * {@link #envelope(Wrapper, WrappedKeyStore, CachePolicy)}, with {@code warm}'s key-store and
     * KMS calls, which block, run on {@code warmExecutor} rather than the shared default pool of
     * four daemon threads. Pass one to size it or to isolate this provider. A same-thread executor
     * ({@code Runnable::run}) makes {@code warm} block its caller until the keys are loaded; its
     * failures still arrive through the returned future. Null is refused rather than taken as the
     * default: a null executor is more likely a caller's bug than a request for the shared pool.
     *
     * @throws ConfigurationError if any argument is null
     */
    public static KeyProvider envelope(Wrapper wrapper, WrappedKeyStore store, CachePolicy policy,
            Executor warmExecutor) {
        return envelopeWithClock(wrapper, store, policy, warmExecutor, System::nanoTime);
    }

    /** Test seam: the cache's clock. */
    static KeyProvider envelopeWithClock(Wrapper wrapper, WrappedKeyStore store,
            CachePolicy policy, Executor warmExecutor, LongSupplier nanoClock) {
        if (wrapper == null || store == null) {
            throw new ConfigurationError("the envelope provider needs a Wrapper and a"
                    + " WrappedKeyStore");
        }
        if (policy == null) {
            throw new ConfigurationError("the envelope provider needs a CachePolicy: max-age,"
                    + " max-uses and capacity are security parameters with no default (spec §5.5)");
        }
        if (warmExecutor == null) {
            throw new ConfigurationError("the envelope provider's warmExecutor may not be null;"
                    + " use the three-argument envelope() for the default");
        }
        if (nanoClock == null) {
            throw new ConfigurationError("the envelope provider's cache needs a clock");
        }
        return new EnvelopeProvider(wrapper, store, new DekCache(policy.toLimits(), nanoClock),
                warmExecutor);
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
}
