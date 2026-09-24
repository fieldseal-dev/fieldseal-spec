package dev.fieldseal.corex;

// Bite fixture for DependencyRulesTest. Test sources only: never part of the module.
// Violates "layout" from outside the root: dev.fieldseal.corex shares the root's
// prefix but is not under it, so a rule scoped to "dev.fieldseal.core.." misses it.
final class BiteFixture {}
