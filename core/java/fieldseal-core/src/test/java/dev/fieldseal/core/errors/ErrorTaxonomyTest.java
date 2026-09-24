package dev.fieldseal.core.errors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/** docs/09 §9: exactly the spec §9 taxonomy, plus the two codes docs/27 §4 adds. */
class ErrorTaxonomyTest {

    /** spec §9's table, in its order. */
    private static final List<String> SPEC_9 = List.of("UNKNOWN_FORMAT_VERSION",
            "SUITE_NOT_ALLOWED", "KEY_UNAVAILABLE", "AAD_MISMATCH", "TAG_INVALID",
            "COMMITMENT_INVALID", "NOT_CIPHERTEXT", "MODE_VIOLATION", "LENGTH_EXCEEDED",
            "SUITE_PROVISIONAL");

    private static FieldsealError instance(Class<?> c) throws ReflectiveOperationException {
        if (c == ModeViolationError.class) {
            return new ModeViolationError("encrypt", "readonly");
        }
        if (c == SuiteProvisionalError.class) {
            return new SuiteProvisionalError(0xFF01, "armProvisionalSuites(true)");
        }
        if (c == LengthExceededError.class) {
            return new LengthExceededError("plaintext", 1L << 31);
        }
        return (FieldsealError) c.getConstructor(String.class).newInstance("m");
    }

    @Test
    void oneFinalSubclassPerCodeAndNoOther() throws ReflectiveOperationException {
        Class<?>[] permitted = FieldsealError.class.getPermittedSubclasses();
        Set<String> codes = new TreeSet<>();
        for (Class<?> c : permitted) {
            assertTrue(Modifier.isFinal(c.getModifiers()), c + " is not final");
            assertTrue(codes.add(instance(c).code()), "duplicate code from " + c);
        }
        Set<String> expected = new TreeSet<>(SPEC_9);
        expected.addAll(List.of("INVALID_ARGUMENT", "CONFIGURATION_ERROR"));
        assertEquals(expected, codes);
        assertEquals(expected.size(), permitted.length);
    }

    /** spec §9: the message names both the rejected operation and the active mode. */
    @Test
    void modeViolationNamesTheOperationAndTheMode() {
        String m = new ModeViolationError("rotate", "readonly").getMessage();
        assertTrue(m.contains("rotate") && m.contains("readonly"), m);
    }

    /** spec §9, §4.8: the message names the suite, the variable, and the in-code form. */
    @Test
    void suiteProvisionalNamesTheSuiteAndBothArmingForms() {
        String m = new SuiteProvisionalError(0xFF01, "Fieldseal.builder().armProvisionalSuites(true)")
                .getMessage();
        for (String part : List.of("0xFF01", "FIELDSEAL_ARM_PROVISIONAL_SUITES=1",
                "armProvisionalSuites(true)")) {
            assertTrue(m.contains(part), m);
        }
    }
}
