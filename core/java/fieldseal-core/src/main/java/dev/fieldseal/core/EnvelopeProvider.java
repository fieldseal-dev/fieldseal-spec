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
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

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

    /** The default warm pool's bound (review of #199). */
    static final int WARM_THREADS = 4;

    /**
     * The default for {@code warm} (#192): at most {@value #WARM_THREADS} threads, shared by every
     * client in the process, so clients share one thread budget and a warm beyond it waits its
     * turn; it is never refused. Daemon threads, so an application need not shut the pool down,
     * and each exits after a minute idle. They do not inherit the creating thread's inheritable
     * thread-locals, so a request's context is not handed to a {@code Wrapper} that did not ask
     * for it. Not the ForkJoin common pool, whose threads the application's other async work
     * needs (on two CPUs or fewer, {@code CompletableFuture} skips that pool and starts a thread
     * per task). The pool holds no client's state or configuration (docs/09 §10; docs/27 §5.5).
     */
    static final Executor WARM_POOL = warmPool();

    /** A new pool configured as {@link #WARM_POOL} is. Package-private, for a test. */
    static Executor warmPool() {
        ThreadPoolExecutor pool = new ThreadPoolExecutor(WARM_THREADS, WARM_THREADS,
                1, TimeUnit.MINUTES, new LinkedBlockingQueue<>(),
                Thread.ofPlatform().daemon().name("fieldseal-warm-", 1)
                        .inheritInheritableThreadLocals(false).factory());
        pool.allowCoreThreadTimeOut(true);
        return pool;
    }

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
