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
        /** When set, unwrapping exactly this blob fails. */
        volatile byte[] failOnBlob;

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
            if (failOnBlob != null && java.util.Arrays.equals(failOnBlob, blob)) {
                throw new IllegalStateException("kms refused this blob");
            }
            return wrap(blob);
        }
    }

    /**
     * One tenant-agnostic store: by default version 1 active and version 0 still valid. The DEK
     * list can be replaced between warms, and lookups are counted.
     */
    static final class Store implements WrappedKeyStore {
        final AtomicInteger lookups = new AtomicInteger();
        final Identity kms;
        final byte[] v2Id = Fixtures.bytes(16, 2);
        final byte[] v1Id = Fixtures.bytes(16, 1);
        final byte[] v0Id = Fixtures.bytes(16, 0);
        final byte[] v2 = Fixtures.bytes(32, 0x32);
        final byte[] v1 = Fixtures.bytes(32, 0x31);
        final byte[] v0 = Fixtures.bytes(32, 0x30);
        final byte[] index = Fixtures.bytes(32, 0x49);
        volatile List<WrappedKey> deks;

        Store(Identity kms) {
            this.kms = kms;
            this.deks = List.of(version(v1Id, v1), version(v0Id, v0));
        }

        WrappedKey version(byte[] id, byte[] key) {
            return new WrappedKey(id, kms.wrap(key));
        }

        @Override
        public List<WrappedKey> keys(KeyRequest request) {
            lookups.incrementAndGet();
            if (request.isIndex()) {
                return List.of(new WrappedKey(v1Id, kms.wrap(index)));
            }
            return deks;
        }
    }
}
