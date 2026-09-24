package dev.fieldseal.core.internal.kdf;

// Bite fixture for DependencyRulesTest. Test sources only: never part of the module.
// Violates the "kdf" rule: kdf may not depend on keyprovider (docs/09 §1).
final class BiteFixture {
    dev.fieldseal.core.keyprovider.BiteTarget target;
}
