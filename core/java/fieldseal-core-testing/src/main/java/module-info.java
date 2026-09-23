/**
 * The testing seam (docs/08 §6; docs/27 §3), a separate artifact so that it
 * is never exported from {@code dev.fieldseal.core}.
 *
 * <p>No exports until S6: {@code exports dev.fieldseal.core.testing} arrives
 * with {@code encrypt_with_materials} and its arming gate, the package's
 * first type. javac refuses to export a package that has none.
 */
module dev.fieldseal.core.testing {
    requires dev.fieldseal.core;
}
