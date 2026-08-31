/**
 * Construction-time gates (`docs/13` §4.1, spec §7.2/§7.4/§7.6).
 *
 * These are the core's refusals, run against the columns this schema actually
 * declares, and surfaced with the column that caused them attached. The adapter
 * deliberately keeps no second copy of any gate -- `client.ts` calls the core's
 * own `validateIndexDeclaration`, one declaration at a time, purely so a
 * failure can name the column instead of the index id.
 *
 * The `on_unindexable: "bucket"` case is here because the coverage matrix
 * claimed it and cited the fixture rather than a test. The report generator
 * (`tests/report.ts`) refuses a row that claims behaviour and names no test,
 * which is how this gap surfaced -- the anti-drift mechanism doing the thing it
 * exists for, on its first run.
 */

import { describe, expect, it } from "vitest";

import { FieldsealConfigurationError, fieldsealExtension } from "../src/index.ts";
import { fieldsealFieldMap } from "./fixture/generated/fieldseal-map.ts";
import { keyProvider, SUITE } from "./helpers.ts";

const CEREMONY = {
  model: "Person",
  field: "legalName",
  reason: "Fixture: a legal name must stay findable.",
  approvedBy: "adapters/prisma test fixture",
  date: "2026-08-27",
};

function build(overrides: Record<string, unknown> = {}) {
  return fieldsealExtension({
    fieldMap: fieldsealFieldMap,
    keyProvider: keyProvider(),
    allowedSuites: [SUITE],
    writeSuite: SUITE,
    armProvisionalSuites: true,
    onWarning: () => {},
    ...overrides,
  });
}

describe("declaration gates run at construction (docs/13 §4.1)", () => {
  it('refuses `on_unindexable: "bucket"` without the §7.2 ceremony', () => {
    // `Person.legalName` declares bucket mode. docs/09 §7.2 gates it behind the
    // same {reason, approvedBy, date} approval spec §7.6 requires for a
    // cardinality override, because bucketing puts every value the normalizer
    // refuses into one index value on purpose -- a decision a person signs for,
    // not one a schema comment makes.
    expect(() => build()).toThrow(FieldsealConfigurationError);
    // And it names the column, which is the whole reason the adapter validates
    // one declaration at a time: the core identifies a declaration by its
    // `indexId`, which is "exact" on nearly every column here.
    expect(() => build()).toThrow(/Person\.legalName/);
  });

  it("constructs once the ceremony is supplied in code", () => {
    // In code, passed to fieldsealExtension() -- never in a `///` comment. The
    // point of the ceremony is that a human reviewed and approved it, and a
    // schema comment is not where that review happens.
    expect(() => build({ unindexableOverride: [CEREMONY] })).not.toThrow();
  });

  it("refuses an override that names a column with no declared index", () => {
    // Not harmless: it is a recorded human approval pointing at the wrong
    // place, while the column it was meant for stays ungated.
    expect(() =>
      build({
        unindexableOverride: [CEREMONY, { ...CEREMONY, field: "note" }],
      }),
    ).toThrow(/Person\.note, which has no declared blind index/);
    expect(() =>
      build({
        unindexableOverride: [CEREMONY],
        cardinalityOverride: [{ ...CEREMONY, model: "Visit", field: "patientId" }],
      }),
    ).toThrow(/cardinalityOverride names Visit\.patientId/);
  });

  it("refuses the same column listed twice in one override", () => {
    expect(() => build({ unindexableOverride: [CEREMONY, CEREMONY] })).toThrow(
      /more than once/,
    );
  });
});
