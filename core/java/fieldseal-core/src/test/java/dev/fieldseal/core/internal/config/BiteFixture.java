package dev.fieldseal.core.internal.config;

// Bite fixture for DependencyRulesTest. Test sources only: never part of the module.
// Violates "no-module-imports-api" and nothing else: docs/09 §1 gives config no
// rule of its own, so this is the only rule that can catch it.
final class BiteFixture {
    dev.fieldseal.core.BiteTarget target;
}
