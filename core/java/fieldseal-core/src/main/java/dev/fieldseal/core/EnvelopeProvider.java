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
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

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

    /**
     * The default for {@code warm} (#192): daemon threads, so an application need not shut it
     * down, created per {@code warm} in progress and gone after a minute idle. Not the ForkJoin
     * common pool, whose threads the application's other async work needs (on two CPUs or fewer,
     * {@code CompletableFuture} skips that pool and starts a thread per task).
     */
    static final Executor WARM_POOL = Executors.newCachedThreadPool(new ThreadFactory() {
        private final AtomicInteger n = new AtomicInteger();

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "fieldseal-warm-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        }
    });

    private static final String SCOPE = "envelope";
    private static final HexFormat HEX = HexFormat.of();

    private final Wrapper wrapper;
    private final WrappedKeyStore store;
    private final DekCache cache;
    private final Executor warmExecutor;
    /** Per slot, the version {@code warm} last found active-for-write. */
    private final Map<DekCache.Slot, String> active = new ConcurrentHashMap<>();

    EnvelopeProvider(Unbound spec, DekCache cache, Executor warmExecutor) {
        this.wrapper = spec.wrapper();
        this.store = spec.store();
        this.cache = cache;
        this.warmExecutor = warmExecutor;
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
     * For each request, in order: every version the store lists is unwrapped (once, however many
     * callers ask at the same time) and cached, replacing an entry it already had, which restarts
     * that key's age and use budget. Only when the whole list has loaded does the slot change:
     * versions the store no longer lists are evicted and erased, so a version dropped from the
     * store stops decrypting, and the first version listed becomes active for writes. A slot the
     * store lists nothing for is emptied.
     *
     * <p><b>On failure</b> the future completes exceptionally. Slots completed before the failure
     * keep their new state. The failing slot keeps its active version and every version it had,
     * so a failed warm never changes which key writes go out under; versions it did unwrap stay
     * cached, as the store listed them as valid.
     */
    @Override
    public CompletableFuture<Void> warm(Collection<KeyRequest> requests) {
        List<KeyRequest> todo = List.copyOf(requests);
        return CompletableFuture.runAsync(() -> {
            for (KeyRequest r : todo) {
                warmSlot(r);
            }
        }, warmExecutor);
    }

    private void warmSlot(KeyRequest r) {
        DekCache.Slot slot = slot(r);
        List<WrappedKeyStore.WrappedKey> versions = store.keys(r);
        if (versions == null) {
            throw new KeyUnavailableError("the key store returned no list for " + r);
        }
        java.util.Set<String> listed = new java.util.LinkedHashSet<>();
        for (WrappedKeyStore.WrappedKey w : versions) {
            if (w == null || w.keyId() == null || w.keyId().length != KeyMaterial.KEY_ID_LEN
                    || w.blob() == null) {
                throw new KeyUnavailableError("the key store returned a malformed wrapped key"
                        + " for " + r);
            }
            listed.add(HEX.formatHex(w.keyId()));
        }
        for (WrappedKeyStore.WrappedKey w : versions) {
            cache.load(new DekCache.Key(slot, HEX.formatHex(w.keyId())), w.keyId(),
                    () -> wrapper.unwrap(w.blob())).join();
        }
        cache.retain(slot, listed);
        if (listed.isEmpty()) {
            active.remove(slot);
        } else {
            active.put(slot, listed.iterator().next());
        }
    }
}
