package dev.fieldseal.core;

import dev.fieldseal.core.keyprovider.KeyRequest;
import dev.fieldseal.core.keyprovider.WrappedKeyStore;
import dev.fieldseal.core.keyprovider.Wrapper;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** A counting stand-in KMS for the envelope provider's tests. */
final class Wrappers {

    private Wrappers() {}

    /** "Wraps" by XOR with 0x5A, and counts unwraps. */
    static final class Identity implements Wrapper {
        final AtomicInteger unwraps = new AtomicInteger();
        volatile RuntimeException failWith;

        @Override
        public byte[] wrap(byte[] dek) {
            byte[] out = dek.clone();
            for (int i = 0; i < out.length; i++) {
                out[i] ^= 0x5A;
            }
            return out;
        }

        @Override
        public byte[] unwrap(byte[] blob) {
            unwraps.incrementAndGet();
            if (failWith != null) {
                throw failWith;
            }
            return wrap(blob);
        }
    }

    /** One tenant-agnostic store: version 1 active, version 0 still valid; counts lookups. */
    static final class Store implements WrappedKeyStore {
        final AtomicInteger lookups = new AtomicInteger();
        final Identity kms;
        final byte[] v1Id = Fixtures.bytes(16, 1);
        final byte[] v0Id = Fixtures.bytes(16, 0);
        final byte[] v1 = Fixtures.bytes(32, 0x31);
        final byte[] v0 = Fixtures.bytes(32, 0x30);
        final byte[] index = Fixtures.bytes(32, 0x49);

        Store(Identity kms) {
            this.kms = kms;
        }

        @Override
        public List<WrappedKey> keys(KeyRequest request) {
            lookups.incrementAndGet();
            if (request.isIndex()) {
                return List.of(new WrappedKey(v1Id, kms.wrap(index)));
            }
            return List.of(new WrappedKey(v1Id, kms.wrap(v1)), new WrappedKey(v0Id, kms.wrap(v0)));
        }
    }
}
