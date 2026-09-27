package dev.fieldseal.core.internal.testing;

// Bite fixture for DependencyRulesTest. Test sources only: never part of the module.
// Violates the "testing" rule: the seam may depend on errors only (DependencyRules.TESTING).
final class BiteFixture {
    dev.fieldseal.core.internal.registry.BiteTarget target;
}
