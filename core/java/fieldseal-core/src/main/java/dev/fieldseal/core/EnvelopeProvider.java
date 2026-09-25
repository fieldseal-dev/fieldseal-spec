package dev.fieldseal.core;

import dev.fieldseal.core.errors.KeyUnavailableError;
import dev.fieldseal.core.internal.cache.DekCache;
import dev.fieldseal.core.keyprovider.EnvelopeHeader;
import dev.fieldseal.core.keyprovider.KeyMaterial;
import dev.fieldseal.core.keyprovider.KeyProvider;
import dev.fieldseal.core.keyprovider.KeyRequest;
import dev.fieldseal.core.keyprovider.WrappedKeyStore;
import dev.fieldseal.core.keyprovider.Wrapper;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The envelope provider bound to one client's {@link DekCache} (docs/09 §8.2). The value path
 * reads the cache and nothing else; {@link #warm} is the only place {@link WrappedKeyStore} and
 * {@link Wrapper} are called.
 */
final class EnvelopeProvider implements KeyProvider {

    /** What {@link KeyProviders#envelope} returns: a description, until a client binds it. */
    record Unbound(Wrapper wrapper, WrappedKeyStore store) implements KeyProvider {
        @Override
        public KeyMaterial encryptionKey(KeyRequest request) {
            throw KeyProviders.unbound();
        }

        @Override
        public List<byte[]> decryptionKeys(EnvelopeHeader header) {
            throw KeyProviders.unbound();
        }

        @Override
        public CompletableFuture<Void> warm(Collection<KeyRequest> requests) {
            return KeyProviders.failed(KeyProviders.unbound());
        }
    }

    private static final String SCOPE = "envelope";
    private static final HexFormat HEX = HexFormat.of();

    private final Wrapper wrapper;
    private final WrappedKeyStore store;
    private final DekCache cache;
    /** Per slot, the version {@code warm} last found active-for-write. */
    private final Map<DekCache.Slot, String> active = new ConcurrentHashMap<>();

    EnvelopeProvider(Unbound spec, DekCache cache) {
        this.wrapper = spec.wrapper();
        this.store = spec.store();
        this.cache = cache;
    }

    private static DekCache.Slot slot(KeyRequest r) {
        byte[] t = r.tenantId();
        return new DekCache.Slot(SCOPE, t == null ? "-" : "t" + HEX.formatHex(t),
                r.isIndex() ? DekCache.Role.INDEX : DekCache.Role.DEK);
    }

    @Override
    public KeyMaterial encryptionKey(KeyRequest request) {
        DekCache.Slot slot = slot(request);
        String version = active.get(slot);
        if (version == null) {
            throw new KeyUnavailableError("no key has been warmed for " + request
                    + "; the envelope provider fails closed on a cache miss (spec §8.1)");
        }
        byte[][] hit = cache.takeForEncrypt(new DekCache.Key(slot, version)).orElseThrow(
                () -> new KeyUnavailableError("the cached key for " + request + " has aged out"
                        + " or used up its budget; warm it again (spec §5.5, §8.1)"));
        return new KeyMaterial(hit[0], hit[1]);
    }

    /** The envelope's version first, then the active one, then any other fresh version. */
    @Override
    public List<byte[]> decryptionKeys(EnvelopeHeader header) {
        DekCache.Slot slot = slot(header.context());
        Map<String, byte[]> fresh = cache.candidates(slot);
        List<byte[]> out = new ArrayList<>();
        String wanted = HEX.formatHex(header.keyId());
        String current = active.get(slot);
        for (String v : new String[] {wanted, current}) {
            if (v != null && fresh.containsKey(v)) {
                out.add(fresh.remove(v));
            }
        }
        out.addAll(fresh.values());
        return out;
    }

    /**
     * For each request, every valid version the store lists, unwrapped once however many callers
     * ask at the same time. The first version listed becomes active-for-write for its slot once it
     * is cached. A failure completes the future exceptionally and caches nothing.
     */
    @Override
    public CompletableFuture<Void> warm(Collection<KeyRequest> requests) {
        List<KeyRequest> todo = List.copyOf(requests);
        return CompletableFuture.runAsync(() -> {
            for (KeyRequest r : todo) {
                DekCache.Slot slot = slot(r);
                List<WrappedKeyStore.WrappedKey> versions = store.keys(r);
                for (int i = 0; i < versions.size(); i++) {
                    WrappedKeyStore.WrappedKey w = versions.get(i);
                    if (w == null || w.keyId() == null
                            || w.keyId().length != KeyMaterial.KEY_ID_LEN || w.blob() == null) {
                        throw new KeyUnavailableError("the key store returned a malformed"
                                + " wrapped key for " + r);
                    }
                    String version = HEX.formatHex(w.keyId());
                    cache.load(new DekCache.Key(slot, version), w.keyId(),
                            () -> wrapper.unwrap(w.blob())).join();
                    if (i == 0) {
                        active.put(slot, version);
                    }
                }
            }
        });
    }
}
