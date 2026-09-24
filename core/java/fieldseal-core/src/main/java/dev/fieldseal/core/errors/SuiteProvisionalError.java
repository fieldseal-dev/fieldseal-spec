package dev.fieldseal.core.errors;

/**
 * spec §9: the write suite is provisional (spec §4.8) and provisional use has not been armed.
 * Spec §9 requires the message to name the provisional {@code suite_id} and the arming mechanism
 * the deployment failed to set, and asks that it name the in-code form too; the constructor
 * builds it from both.
 */
public final class SuiteProvisionalError extends FieldsealError {

    private static final long serialVersionUID = 1L;

    /** The spec §4.8 environment variable, which arms if and only if its value is exactly "1". */
    public static final String ARMING_VARIABLE = "FIELDSEAL_ARM_PROVISIONAL_SUITES";

    /** @param inCodeForm this binding's in-code arming form, named in the message */
    public SuiteProvisionalError(int suiteId, String inCodeForm) {
        super(String.format("suite 0x%04X is provisional and unreviewed (spec §4.8); to write"
                + " under it, set %s=1 or arm it in code with %s", suiteId, ARMING_VARIABLE,
                inCodeForm));
    }

    @Override
    public String code() {
        return "SUITE_PROVISIONAL";
    }
}
