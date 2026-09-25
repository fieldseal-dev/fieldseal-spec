package dev.fieldseal.core.keyprovider;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * The key-provider SPI (spec §8; docs/09 §8.1), which callers implement. The three shipped
 * providers come from {@code dev.fieldseal.core.KeyProviders}.
 *
 * <p><b>No network I/O on the value path.</b> {@link #encryptionKey} and {@link #decryptionKeys}
 * run inside {@code encrypt}, {@code decrypt} and {@code rotate}, which spec §11.1 makes
 * synchronous and I/O-free. All fetching belongs in {@link #warm} or in the provider's own
 * background refresh (docs/09 §3.6).
 *
 * <p><b>Ownership (docs/09 §8.1, normative).</b> What these methods return is owned by the
 * provider. The core never writes to it, never erases it, and keeps no reference to it past the
 * call that obtained it. A provider that wants its material erased erases it itself. Returning a
 * fresh copy is the safe default, and is what the shipped providers do.
 *
 * <p><b>Failures.</b> Any exception a provider throws from these two methods reaches the caller
 * as {@code KEY_UNAVAILABLE}, with the provider's exception as its cause. So does returning
 * nothing, an empty key, or a {@code key_id} that is not 16 bytes.
 */
public interface KeyProvider {

    /**
     * The key for a write (spec §8). For purpose {@code "encrypt"}, the tenant DEK in its
     * active-for-write version. For purpose {@code "index:<id>"}, the tenant index key: never
     * the DEK (spec §8, §5.2).
     */
    KeyMaterial encryptionKey(KeyRequest request);

    /**
     * Candidate DEKs for a read, in preference order: every currently valid version, active
     * first (spec §8, §5.6). An empty list is {@code KEY_UNAVAILABLE}. Calls here are reads of
     * what the provider holds and never count as uses of a key (docs/09 §8.1).
     */
    List<byte[]> decryptionKeys(EnvelopeHeader header);

    /**
     * Fetches and caches key material for {@code requests} ahead of the value path (docs/09
     * §3.6). A failure is reported through the future and leaves the provider as it was: it must
     * not poison a cache. The default does nothing, for a provider that holds its keys already.
     */
    default CompletableFuture<Void> warm(Collection<KeyRequest> requests) {
        return CompletableFuture.completedFuture(null);
    }
}
