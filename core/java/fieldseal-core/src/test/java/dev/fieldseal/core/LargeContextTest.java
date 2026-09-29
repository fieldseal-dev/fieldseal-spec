package dev.fieldseal.core;

import static dev.fieldseal.core.Fixtures.COLUMN;
import static dev.fieldseal.core.Fixtures.TABLE;
import static dev.fieldseal.core.Fixtures.builder;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.fieldseal.core.errors.CommitmentInvalidError;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * G14 (#43; spec §6.1; docs/27 §5.2): {@code tenant_id} and {@code row_id} are unbounded, so the
 * KDF {@code info} is too, and some platform HKDFs cap it (spec §6.1 names Node at 1,024 bytes and
 * OpenSSL 3.0–3.5 at 32 KiB). This core writes its HKDF over {@code Mac}, which caps nothing. These
 * tests use 70,000-byte fields, past both caps, and check that the end of each field reaches the
 * derivation, not only that the value path does not throw. Only the last byte is varied, so a
 * derivation that skipped a byte in the middle would pass them; a cap, the platform failure G14 is
 * about, would not.
 */
class LargeContextTest {

    private static final int FIELD = 70_000;
    private static final byte[] PT = "123-45-6789".getBytes(StandardCharsets.US_ASCII);

    /** A 70,000-byte field; {@code last} is its final byte, the one the neighbour changes. */
    private static byte[] field(int fill, int last) {
        byte[] b = Fixtures.bytes(FIELD, fill);
        b[FIELD - 1] = (byte) last;
        return b;
    }

    private static FieldContext large(int tenantLast, int rowLast) {
        return FieldContext.of(TABLE, COLUMN).withTenant(field(0x54, tenantLast))
                .withRow(field(0x52, rowLast));
    }

    private static Fieldseal client() {
        return builder(new Fixtures.SpyProvider()).indexes(List.of(Fixtures.emailIndex().build()))
                .build();
    }

    @Test
    void encryptDecryptAndRotateRoundTrip() {
        Fieldseal fs = client();
        FieldContext ctx = large(1, 1);
        byte[] env = fs.encrypt(PT, ctx);
        assertArrayEquals(PT, fs.decrypt(env, ctx));
        assertArrayEquals(PT, fs.decrypt(fs.rotate(env, ctx), ctx));
    }

    /**
     * The last byte of a 70,000-byte {@code tenant_id} changes the index key. An HKDF that stopped
     * reading {@code info} early would give both tenants one key, and so one index for every value.
     */
    @Test
    void theLastTenantByteReachesTheIndexKey() {
        Fieldseal fs = client();
        List<String> a = new ArrayList<>();
        List<String> b = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            String value = "user" + i + "@example.com";
            a.add(Arrays.toString(fs.blindIndex(value, large(1, 1).forIndex("email-eq"))));
            b.add(Arrays.toString(fs.blindIndex(value, large(2, 1).forIndex("email-eq"))));
        }
        // Truncated to 15 bits, one pair may collide by chance; eight cannot.
        assertFalse(a.equals(b), "two tenants differing in their last byte derived one index key");
    }

    /**
     * The last byte of each large field changes the record key, so the commitment refuses. Were it
     * cut from {@code info}, the record key would match and only the AAD, which carries the whole
     * context, would refuse: {@code TAG_INVALID}, not {@code COMMITMENT_INVALID}.
     */
    @Test
    void theLastByteOfEitherFieldReachesTheRecordKey() {
        Fieldseal fs = client();
        byte[] env = fs.encrypt(PT, large(1, 1));
        assertThrows(CommitmentInvalidError.class, () -> fs.decrypt(env, large(2, 1)), "tenant");
        assertThrows(CommitmentInvalidError.class, () -> fs.decrypt(env, large(1, 2)), "row");
    }
}
