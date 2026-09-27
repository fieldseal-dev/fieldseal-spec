package dev.fieldseal.core.testing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.fieldseal.core.errors.InvalidArgumentError;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * {@code encrypt_with_materials} in an armed JVM that has never initialized {@code Fieldseal}: the
 * {@code freshJvmTest} task runs this class alone, in a process of its own. A null client must
 * reach the api's own refusal, not the seam's "not installed" state (#219 review): that holds
 * only because {@link FieldsealTesting} initializes the api class itself, since a class literal
 * does not (JLS §12.4.1). Nothing here may touch {@code Fieldseal} before the call.
 */
@Tag("fresh")
class FreshJvmTest {

    @Test
    void aNullClientIsTheApisRefusalInAJvmThatNeverBuiltOne() {
        assertEquals("1", System.getenv(FieldsealTesting.ARMING_VARIABLE),
                "freshJvmTest arms the seam");
        InvalidArgumentError e = assertThrows(InvalidArgumentError.class,
                () -> FieldsealTesting.encryptWithMaterials(null, new byte[1], null, new byte[32],
                        new byte[12]));
        assertEquals("the client is null", e.getMessage());
    }
}
