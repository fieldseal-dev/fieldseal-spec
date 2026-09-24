/**
 * Module {@code testing} (docs/09 §1; docs/08 §6): {@code encrypt_with_materials},
 * armed only by {@code FIELDSEAL_TEST_MODE=1}. Built at S6 (docs/27 §8).
 *
 * <p>A separate artifact, so it is never exported from the main module. Nothing
 * depends on it: the core does not declare it, which the build enforces.
 */
package dev.fieldseal.core.testing;
