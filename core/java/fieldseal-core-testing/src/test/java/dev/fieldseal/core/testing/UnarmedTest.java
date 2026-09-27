package dev.fieldseal.core.testing;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.KeyProviders;
import dev.fieldseal.core.errors.ConfigurationError;
import java.util.Set;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * docs/08 §6's negative test for the unarmed state, in a process that really is unarmed: the
 * {@code unarmedTest} task runs this class alone, with {@code FIELDSEAL_TEST_MODE} removed from
 * its environment, and {@code test} excludes it.
 */
@Tag("unarmed")
class UnarmedTest {

    @Test
    void encryptWithMaterialsRefusesBeforeAnythingElse() {
        assertNotEquals("1", System.getenv(FieldsealTesting.ARMING_VARIABLE),
                "unarmedTest removes the variable");
        Fieldseal fs = Fieldseal.builder()
                .keyProvider(KeyProviders.staticKeys(new byte[32], new byte[] {1}, new byte[16]))
                .allowedSuites(Set.of(0xFF01)).writeSuite(0xFF01).armProvisionalSuites(true)
                .onWarning(w -> { }).build();
        FieldContext ctx = FieldContext.of(new byte[16], new byte[16]);
        ConfigurationError e = assertThrows(ConfigurationError.class,
                () -> FieldsealTesting.encryptWithMaterials(fs, new byte[1], ctx, new byte[32],
                        new byte[12]));
        assertTrue(e.getMessage().contains("FIELDSEAL_TEST_MODE=1"), e.getMessage());
        // Before any argument is looked at: a null client is still the gate's refusal.
        assertThrows(ConfigurationError.class,
                () -> FieldsealTesting.encryptWithMaterials(null, null, null, null, null));
    }
}
