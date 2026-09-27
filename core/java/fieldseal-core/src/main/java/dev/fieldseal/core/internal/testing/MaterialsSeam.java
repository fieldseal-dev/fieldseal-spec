package dev.fieldseal.core.internal.testing;

import dev.fieldseal.core.errors.ConfigurationError;
import java.util.function.Function;

/**
 * The core's half of docs/09 §1's {@code testing} module: the one route by which a caller's
 * {@code msg_seed} and nonce reach the encrypt pipeline (docs/08 §6). The other half, {@code
 * encrypt_with_materials}, is the separate module {@code dev.fieldseal.core.testing}, the only
 * module this package is exported to.
 *
 * <p><b>The gate is here, not only there.</b> A qualified export binds only on the module path.
 * On the class path, where most JVM applications run, every public class is reachable, so this
 * class refuses to hand out the encryptor unless {@code FIELDSEAL_TEST_MODE=1}, and the api's
 * implementation checks again before it encrypts.
 *
 * <p><b>Why a hook.</b> The encryptor is the api's, which docs/09 §1 lets no module import. So
 * the api installs it here once, from its static initializer, typed by parameters this package
 * does not need to name, and the testing module asks for it with the api's types.
 */
public final class MaterialsSeam {

    /** docs/08 §6's arming variable. Only the byte-exact value {@code 1} arms. */
    public static final String ARMING_VARIABLE = "FIELDSEAL_TEST_MODE";

    /**
     * Encrypts {@code plaintext} under {@code client}'s configuration and {@code ctx}, drawing
     * the envelope's {@code msg_seed} and nonce from the caller instead of the CSPRNG.
     */
    @FunctionalInterface
    public interface Encryptor<C, X> {
        byte[] encrypt(C client, byte[] plaintext, X ctx, byte[] msgSeed, byte[] nonce);
    }

    private static Encryptor<?, ?> installed;
    private static Class<?> clientType;
    private static Class<?> contextType;

    private MaterialsSeam() {}

    /**
     * Called once, by the api's static initializer. A second call is refused, so that nothing
     * can replace the encryptor once the api has installed it.
     */
    public static synchronized <C, X> void install(Class<C> client, Class<X> ctx,
            Encryptor<C, X> encryptor) {
        if (client == null || ctx == null || encryptor == null) {
            throw new IllegalArgumentException("install takes two types and an encryptor");
        }
        if (installed != null) {
            throw new IllegalStateException("the materials encryptor is already installed");
        }
        installed = encryptor;
        clientType = client;
        contextType = ctx;
    }

    /**
     * The installed encryptor, typed as the caller's client and context classes.
     *
     * @throws ConfigurationError unless {@code FIELDSEAL_TEST_MODE=1}
     * @throws IllegalStateException if the api has not been initialized, which a caller holding a
     *     client cannot observe, or if the types are not the ones it was installed with
     */
    @SuppressWarnings("unchecked")
    public static synchronized <C, X> Encryptor<C, X> encryptor(Class<C> client, Class<X> ctx) {
        requireArmed();
        if (installed == null) {
            throw new IllegalStateException("the api has not installed its encryptor");
        }
        if (client != clientType || ctx != contextType) {
            throw new IllegalStateException("the encryptor takes " + clientType.getName() + " and "
                    + contextType.getName());
        }
        return (Encryptor<C, X>) installed;
    }

    /** @throws ConfigurationError unless the process environment arms the seam */
    public static void requireArmed() {
        requireArmed(System::getenv);
    }

    static void requireArmed(Function<String, String> environment) {
        if (!"1".equals(environment.apply(ARMING_VARIABLE))) {
            throw new ConfigurationError("encrypt_with_materials is armed only by "
                    + ARMING_VARIABLE + "=1 (docs/08 §6): an implementation that accepts a"
                    + " caller-supplied nonce or seed outside of vector-test mode is"
                    + " non-conformant");
        }
    }
}
