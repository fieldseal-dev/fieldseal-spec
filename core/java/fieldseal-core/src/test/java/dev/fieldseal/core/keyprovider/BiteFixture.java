package dev.fieldseal.core.keyprovider;

// Bite fixture for DependencyRulesTest. Test sources only: never part of the module.
// Violates the "keyprovider" rule: keyprovider may depend on errors only (docs/09 §1).
final class BiteFixture {
    dev.fieldseal.core.internal.registry.BiteTarget target;
}
