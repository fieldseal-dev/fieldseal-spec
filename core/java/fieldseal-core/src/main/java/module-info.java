/**
 * The Fieldseal Java core (docs/27).
 *
 * <p>Exports the three public packages of docs/27 §3 to everyone, and one package to one module:
 * {@code internal.testing}, the seam {@code encrypt_with_materials} enters (docs/08 §6), to
 * {@code dev.fieldseal.core.testing} only. The other {@code internal.*} packages are not exported,
 * so no caller can reach them. ModuleDescriptorTest pins this list.
 *
 * <p>javac cannot see the testing module when it compiles this one, which depends on it no other
 * way, so the qualified export's "module not found" lint is suppressed here and nowhere else.
 */
@SuppressWarnings("module")
module dev.fieldseal.core {
    // Argon2id only (docs/27 §2); read by internal.blindindex and nothing else.
    requires org.bouncycastle.provider;

    exports dev.fieldseal.core;
    exports dev.fieldseal.core.errors;
    exports dev.fieldseal.core.keyprovider;
    // docs/08 §6: armed only by FIELDSEAL_TEST_MODE=1, which MaterialsSeam checks itself.
    exports dev.fieldseal.core.internal.testing to dev.fieldseal.core.testing;
}
