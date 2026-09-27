package dev.fieldseal.core.testing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.KeyProviders;
import dev.fieldseal.core.ReadMode;
import dev.fieldseal.core.errors.FieldsealError;
import dev.fieldseal.core.errors.InvalidArgumentError;
import dev.fieldseal.core.errors.ModeViolationError;
import dev.fieldseal.core.errors.SuiteProvisionalError;
import dev.fieldseal.core.internal.testing.MaterialsSeam;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@code encrypt_with_materials}, armed: this module's {@code test} task sets {@code
 * FIELDSEAL_TEST_MODE=1}. Whether it reproduces the pinned envelopes is the harness's question
 * ({@code EnvelopeVectorsTest}); this class asks whether it is the production pipeline, and
 * whether the materials stay on this path alone. The unarmed half is {@link UnarmedTest}.
 */
class FieldsealTestingTest {

    private static final byte[] SEED = fill(32, 0x5e);
    private static final byte[] NONCE = fill(12, 0x0c);
    private static final FieldContext CTX = FieldContext.of(fill(16, 0x11), fill(16, 0x22));
    private static final byte[] ADA = "Ada".getBytes(StandardCharsets.US_ASCII);

    private static byte[] fill(int n, int v) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) v);
        return b;
    }

    @BeforeAll
    static void armed() {
        assertEquals("1", System.getenv(FieldsealTesting.ARMING_VARIABLE),
                "the testing module's test task arms the seam");
    }

    private static Fieldseal.Builder builder() {
        return Fieldseal.builder()
                .keyProvider(KeyProviders.staticKeys(fill(32, 0x42), fill(32, 0x43), fill(16, 7)))
                .allowedSuites(Set.of(0xFF01)).writeSuite(0xFF01).armProvisionalSuites(true)
                .onWarning(w -> { });
    }

    private static byte[] seal(Fieldseal fs, byte[] plaintext, FieldContext ctx) {
        return FieldsealTesting.encryptWithMaterials(fs, plaintext, ctx, SEED, NONCE);
    }

    @Test
    void theMaterialsAreTheEnvelopes() {
        Fieldseal fs = builder().build();
        byte[] env = seal(fs, ADA, CTX);
        // spec §3.1: fmt_ver, suite_id, key_id, then msg_seed at 19 and the nonce at 51.
        assertArrayEquals(SEED, Arrays.copyOfRange(env, 19, 51));
        assertArrayEquals(NONCE, Arrays.copyOfRange(env, 51, 63));
        assertArrayEquals(env, seal(fs, ADA, CTX), "deterministic under fixed materials");
        assertArrayEquals(ADA, fs.decrypt(env, CTX), "the production decrypt reads it");
    }

    /** The client's own encrypt is untouched: the materials never reach it. */
    @Test
    void productionEncryptStillDrawsFreshEntropy() {
        Fieldseal fs = builder().build();
        byte[] fixed = seal(fs, ADA, CTX);
        byte[] a = fs.encrypt(ADA, CTX);
        byte[] b = fs.encrypt(ADA, CTX);
        assertFalse(Arrays.equals(Arrays.copyOfRange(a, 19, 63), Arrays.copyOfRange(b, 19, 63)));
        assertFalse(Arrays.equals(Arrays.copyOfRange(fixed, 19, 51),
                Arrays.copyOfRange(a, 19, 51)));
        assertFalse(Arrays.equals(Arrays.copyOfRange(fixed, 51, 63),
                Arrays.copyOfRange(a, 51, 63)));
    }

    /** api-boundary-order holds on this path too: it is encrypt, not a copy of it. */
    @Test
    void theApiBoundaryOrderIsEncrypts() {
        Fieldseal readonly = builder().readMode(ReadMode.READONLY).build();
        assertThrows(ModeViolationError.class, () -> seal(readonly, null, null));
        Fieldseal unarmed = builder().armProvisionalSuites(false).build();
        if (!unarmed.provisionalArmed()) {
            assertThrows(SuiteProvisionalError.class, () -> seal(unarmed, null, null));
        }
        Fieldseal fs = builder().build();
        FieldsealError e = assertThrows(InvalidArgumentError.class, () -> seal(fs, null, null));
        assertEquals("the plaintext is null", e.getMessage());
        e = assertThrows(InvalidArgumentError.class, () -> seal(fs, new byte[1], null));
        assertEquals("the field context is null", e.getMessage());
        assertThrows(InvalidArgumentError.class,
                () -> seal(fs, new byte[1], CTX.forIndex("email-eq")));
    }

    @Test
    void wrongMaterialsAreRefused() {
        Fieldseal fs = builder().build();
        assertThrows(InvalidArgumentError.class,
                () -> FieldsealTesting.encryptWithMaterials(fs, ADA, CTX, new byte[31], NONCE));
        assertThrows(InvalidArgumentError.class,
                () -> FieldsealTesting.encryptWithMaterials(fs, ADA, CTX, SEED, new byte[24]));
        assertThrows(InvalidArgumentError.class,
                () -> FieldsealTesting.encryptWithMaterials(fs, ADA, CTX, null, NONCE));
        assertThrows(InvalidArgumentError.class,
                () -> FieldsealTesting.encryptWithMaterials(null, ADA, CTX, SEED, NONCE));
    }

    /** The seam hands the encryptor out only with the types it was installed with. */
    @Test
    void theSeamChecksItsTypes() {
        assertThrows(IllegalStateException.class,
                () -> MaterialsSeam.encryptor(Object.class, FieldContext.class));
    }
}
