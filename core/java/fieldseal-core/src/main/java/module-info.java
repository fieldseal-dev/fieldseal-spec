/**
 * The Fieldseal Java core (docs/27).
 *
 * <p>Exports the three public packages of docs/27 §3 and nothing else. The
 * {@code internal.*} packages are not exported, so no caller can reach them.
 *
 * <p>docs/27 §3 also names one qualified export to
 * {@code dev.fieldseal.core.testing}, for the {@code encrypt_with_materials}
 * seam (docs/08 §6). It is added at S6, with the seam it exports: the
 * package it names does not exist before then. ModuleDescriptorTest pins
 * this list, so the addition is a deliberate test change.
 */
module dev.fieldseal.core {
    exports dev.fieldseal.core;
    exports dev.fieldseal.core.errors;
    exports dev.fieldseal.core.keyprovider;
}
