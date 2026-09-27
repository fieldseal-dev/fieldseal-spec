package dev.fieldseal.core.testing;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.errors.ConfigurationError;
import dev.fieldseal.core.internal.testing.MaterialsSeam;

/**
 * docs/08 §6's determinism injection, for reproducing the {@code envelope/} vectors.
 *
 * <p><b>This is not for production.</b> In the words of {@code vectors/README.md}: "an
 * implementation that accepts a caller-supplied nonce or seed outside of vector-test mode is
 * non-conformant." A fixed {@code msg_seed} or nonce repeated under one key voids spec §3.1 and
 * §4.4's guarantees. So every method here refuses to run unless the environment variable {@code
 * FIELDSEAL_TEST_MODE} is exactly {@code 1}, and the core checks the same variable again before it
 * encrypts, so the gate holds on the class path too, where a qualified export does not bind.
 */
public final class FieldsealTesting {

    /** docs/08 §6's arming variable. Only the byte-exact value {@code 1} arms. */
    public static final String ARMING_VARIABLE = MaterialsSeam.ARMING_VARIABLE;

    static {
        // A class literal does not initialize its class (JLS §12.4.1), and Fieldseal's static
        // initializer is what installs the encryptor. Without this, an armed process that has
        // never built a client and passes a null one would get the seam's IllegalStateException
        // instead of the api's InvalidArgumentError (#219 review).
        try {
            Class.forName(Fieldseal.class.getName(), true, Fieldseal.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private FieldsealTesting() {}

    /**
     * {@code encrypt_with_materials(plaintext, ctx, msg_seed, nonce) -> envelope} (docs/08 §6),
     * under {@code client}'s configuration and key provider. The whole production pipeline runs,
     * the same checks in the same order, the same KDF, AAD and commitment, except that the
     * envelope's {@code msg_seed} and nonce are the ones given rather than the CSPRNG's.
     *
     * @param msgSeed 32 bytes
     * @param nonce the write suite's nonce length (12 bytes for {@code 0xFF01})
     * @throws ConfigurationError unless {@code FIELDSEAL_TEST_MODE=1}, before anything else
     */
    public static byte[] encryptWithMaterials(Fieldseal client, byte[] plaintext,
            FieldContext ctx, byte[] msgSeed, byte[] nonce) {
        return MaterialsSeam.encryptor(Fieldseal.class, FieldContext.class)
                .encrypt(client, plaintext, ctx, msgSeed, nonce);
    }
}
