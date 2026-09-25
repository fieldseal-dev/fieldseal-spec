package dev.fieldseal.core;

import dev.fieldseal.core.keyprovider.EnvelopeHeader;
import dev.fieldseal.core.keyprovider.KeyMaterial;
import dev.fieldseal.core.keyprovider.KeyProvider;
import dev.fieldseal.core.keyprovider.KeyRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Contexts, a spy provider and a client builder for the api tests. */
final class Fixtures {

    static final byte[] TABLE = bytes(16, 0x11);
    static final byte[] COLUMN = bytes(16, 0x22);
    static final byte[] TENANT = "tenant-0001".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    static final byte[] DEK = bytes(32, 0x42);
    static final byte[] INDEX_KEY = bytes(32, 0x43);
    static final byte[] KEY_ID = bytes(16, 0x07);

    private Fixtures() {}

    static byte[] bytes(int n, int v) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) v);
        return b;
    }

    static FieldContext ctx() {
        return FieldContext.of(TABLE, COLUMN).withTenant(TENANT);
    }

    /**
     * A builder armed in code, reading an empty environment, so no test depends on the
     * machine's {@code FIELDSEAL_ARM_PROVISIONAL_SUITES} or {@code FIELDSEAL_TEST_MODE}.
     */
    static Fieldseal.Builder builder(KeyProvider p) {
        return Fieldseal.builder().keyProvider(p).allowedSuites(Set.of(0xFF01)).writeSuite(0xFF01)
                .armProvisionalSuites(true).environment(Map.<String, String>of()::get)
                .onWarning(w -> { });
    }

    /**
     * A provider that hands out its own arrays, not copies, and records every call: what the
     * ownership test watches, and what the seam tests count.
     */
    static class SpyProvider implements KeyProvider {
        final byte[] dek = DEK.clone();
        final byte[] indexKey = INDEX_KEY.clone();
        final byte[] keyId = KEY_ID.clone();
        final List<Object> calls = new ArrayList<>();
        RuntimeException failWith;

        @Override
        public KeyMaterial encryptionKey(KeyRequest request) {
            calls.add(request);
            if (failWith != null) {
                throw failWith;
            }
            return new KeyMaterial(request.isIndex() ? indexKey : dek, keyId);
        }

        @Override
        public List<byte[]> decryptionKeys(EnvelopeHeader header) {
            calls.add(header);
            if (failWith != null) {
                throw failWith;
            }
            return Arrays.equals(header.keyId(), keyId) ? List.of(dek) : List.of();
        }
    }
}
