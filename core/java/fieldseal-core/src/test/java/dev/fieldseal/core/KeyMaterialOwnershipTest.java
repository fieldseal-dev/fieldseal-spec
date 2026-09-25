package dev.fieldseal.core;

import static dev.fieldseal.core.Fixtures.builder;
import static dev.fieldseal.core.Fixtures.ctx;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.FieldsealError;
import dev.fieldseal.core.internal.kdf.KeyDerivation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The {@code key-material-ownership} pin (docs/14 §4, G17), both halves:
 *
 * <ul>
 *   <li><b>Provider-owned material is never written</b> (docs/09 §8.1): a provider that hands out
 *       its own arrays, not copies, finds them byte-identical after every operation, on success
 *       and on each failure path;
 *   <li><b>the core erases what it derives</b> (docs/09 §3.1 step 13, §3.2 step 6): every record
 *       key the pipeline derived is all zeroes once the operation returns or throws.
 * </ul>
 */
class KeyMaterialOwnershipTest {

    private static final byte[] PT = "a value".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private final List<byte[]> derived = new ArrayList<>();

    private Fieldseal client(Fixtures.SpyProvider p) {
        return builder(p).recordKeys((suite, dek, keyId, seed, cc) -> {
            byte[] rk = KeyDerivation.recordKey(suite, dek, keyId, seed, cc);
            derived.add(rk);
            return rk;
        }).build();
    }

    private void assertAllErased() {
        assertTrue(derived.size() > 0, "no record key was derived");
        for (byte[] rk : derived) {
            assertArrayEquals(new byte[rk.length], rk, "a record key survived its operation");
        }
    }

    @Test
    void providerArraysAreNeverWritten() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        Fieldseal fs = client(p);
        byte[] env = fs.encrypt(PT, ctx());
        assertArrayEquals(PT, fs.decrypt(env, ctx()));
        fs.rotate(env, ctx());
        byte[] flipped = env.clone();
        flipped[63] ^= 1;
        assertThrows(FieldsealError.class, () -> fs.decrypt(flipped, ctx()));
        assertThrows(FieldsealError.class, () -> fs.decrypt(env, ctx().withTenant(null)));
        assertArrayEquals(Fixtures.DEK, p.dek);
        assertArrayEquals(Fixtures.INDEX_KEY, p.indexKey);
        assertArrayEquals(Fixtures.KEY_ID, p.keyId);
    }

    @Test
    void everyRecordKeyIsErasedOnEveryPath() {
        Fixtures.SpyProvider p = new Fixtures.SpyProvider();
        Fieldseal fs = client(p);
        byte[] env = fs.encrypt(PT, ctx());
        fs.decrypt(env, ctx());
        fs.rotate(env, ctx());
        byte[] flipped = env.clone();
        flipped[63] ^= 1;
        assertThrows(FieldsealError.class, () -> fs.decrypt(flipped, ctx()));
        assertThrows(FieldsealError.class, () -> fs.decrypt(env, ctx().withTenant(null)));
        assertEquals(6, derived.size(), "encrypt, decrypt, rotate (2), tag failure, commitment");
        assertAllErased();
    }
}
