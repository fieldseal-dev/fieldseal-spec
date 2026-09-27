/**
 * The testing seam (docs/08 §6; docs/27 §3), a separate artifact so that it is never exported
 * from {@code dev.fieldseal.core}. It reads the one package the core exports to it alone, and
 * exports {@code encrypt_with_materials}, which is armed only by {@code FIELDSEAL_TEST_MODE=1}.
 */
module dev.fieldseal.core.testing {
    requires transitive dev.fieldseal.core;

    exports dev.fieldseal.core.testing;
}
