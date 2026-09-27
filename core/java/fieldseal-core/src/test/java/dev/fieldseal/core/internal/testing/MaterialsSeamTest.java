package dev.fieldseal.core.internal.testing;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.errors.ConfigurationError;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The core's half of the docs/08 §6 gate. This module's test task never sets {@code
 * FIELDSEAL_TEST_MODE}, so here the seam is unarmed, and the armed half is the testing module's.
 */
class MaterialsSeamTest {

    @Test
    void onlyTheByteExactOneArms() {
        for (String v : new String[] {null, "", "0", "true", "yes", " 1", "1 ", "01", "1\n"}) {
            Map<String, String> env =
                    v == null ? Map.of() : Map.of(MaterialsSeam.ARMING_VARIABLE, v);
            ConfigurationError e = assertThrows(ConfigurationError.class,
                    () -> MaterialsSeam.requireArmed(env::get), String.valueOf(v));
            assertTrue(e.getMessage().contains("FIELDSEAL_TEST_MODE=1")
                    && e.getMessage().contains("non-conformant"), e.getMessage());
        }
        assertDoesNotThrow(() -> MaterialsSeam.requireArmed(
                Map.of(MaterialsSeam.ARMING_VARIABLE, "1")::get));
    }

    /** Unarmed, the encryptor is not handed out at all, whatever the caller asks for. */
    @Test
    void theEncryptorIsRefusedUnarmed() {
        assertNotEquals("1", System.getenv(MaterialsSeam.ARMING_VARIABLE),
                "this test needs the unarmed process environment");
        Fieldseal.builder(); // the api's static initializer installs the encryptor
        assertThrows(ConfigurationError.class,
                () -> MaterialsSeam.encryptor(Fieldseal.class, FieldContext.class));
    }

    /** Once the api has installed its encryptor, nothing can replace it. */
    @Test
    void theEncryptorIsInstalledOnce() {
        Fieldseal.builder();
        assertThrows(IllegalStateException.class, () -> MaterialsSeam.install(Object.class,
                Object.class, (c, p, x, s, n) -> new byte[0]));
    }
}
