package dev.fieldseal.core.internal.commitment;

// Bite fixture for DependencyRulesTest. Test sources only: never part of the module.
// Violates the "commitment" rule: commitment may not depend on keyprovider (docs/09 §1).
final class BiteFixture {
    dev.fieldseal.core.keyprovider.BiteTarget target;
}
