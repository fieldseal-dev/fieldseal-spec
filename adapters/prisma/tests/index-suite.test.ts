/**
 * The index's declared suite (spec §7.2, §7.8; #213).
 *
 * A blind-index declaration names its own suite, and the index-key context's
 * `suite_id` is that declared suite -- never the client's write suite. This
 * adapter reads it from the schema (`suite_id:` in the `@fieldseal(index: ...)`
 * annotation), requires it with no default, and passes it to the core's
 * `IndexDeclaration` untouched. Whether the number names a registered suite is
 * the core's gate (AD-1), and the one place this file checks the adapter's own
 * behaviour on that is that the core's refusal arrives with the column named.
 *
 * What is NOT here: a registry check against a supplied core client (the
 * Django adapter's E006). This adapter has no `client` option (docs/13 §2), so
 * there is no supplied registry to compare; the declarations always come from
 * the schema, and `Fieldseal.indexes` is read below only to prove what the
 * core reports.
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { indexRegistryKey, type FieldContext } from "@fieldseal/core";

import { buildClient } from "../src/client.ts";
import { uuidBytes } from "../src/context.ts";
import { parseAnnotations } from "../src/annotations.ts";
import { type FieldInput, type ModelInput, resolveModel } from "../src/declarations.ts";
import { FieldsealConfigurationError, fieldsealExtension } from "../src/index.ts";
import { type FieldMap, resolveMap } from "../src/fieldmap.ts";
import { fieldsealFieldMap } from "./fixture/generated/fieldseal-map.ts";
import {
  clearDb,
  INDEX_SUITE_FF02,
  keyProvider,
  loose,
  makeClient,
  rawColumn,
  SUITE,
} from "./helpers.ts";

const CEREMONY = {
  model: "Person",
  field: "legalName",
  reason: "Fixture: a legal name must stay findable.",
  approvedBy: "adapters/prisma test fixture",
  date: "2026-08-27",
};

const CLIENT_OPTS = {
  keyProvider: keyProvider(),
  allowedSuites: [SUITE],
  writeSuite: SUITE,
  armProvisionalSuites: true,
  unindexableOverride: [CEREMONY],
  onWarning: () => {},
};

/** The fixture map with `Patient.alias`'s index declared under `suiteId`. */
function aliasMap(suiteId: number | undefined): FieldMap {
  return {
    ...fieldsealFieldMap,
    models: fieldsealFieldMap.models.map((m) =>
      m.model !== "Patient"
        ? m
        : {
            ...m,
            indexes: m.indexes.map((i) => {
              if (i.source !== "alias") return i;
              const { suiteId: _drop, ...rest } = i;
              return (suiteId === undefined ? rest : { ...rest, suiteId }) as typeof i;
            }),
          },
    ),
  };
}

// --- the declaration: required, no default (item 1) -------------------------

const UUID_A = "018f3c2e-0000-7000-8000-0000000000aa";
const UUID_C = "018f3c2e-0000-7000-8000-000000000001";

const field = (over: Partial<FieldInput> & { name: string }): FieldInput => ({
  type: "Bytes",
  kind: "scalar",
  isList: false,
  isRequired: false,
  ...over,
});

function declare(suiteClause: string) {
  const model: ModelInput = {
    name: "Patient",
    documentation: `@fieldseal(table_uuid: "${UUID_A}")`,
    fields: [
      field({
        name: "email",
        documentation: `@fieldseal(encrypted, column_uuid: "${UUID_C}")`,
      }),
      field({
        name: "emailBidx",
        documentation:
          `@fieldseal(index: "email", ${suiteClause}idf: "hmac-sha512", ` +
          `normalize: "nfc-casefold-v1", truncate_bits: 15, projected_population: 100000)`,
      }),
    ],
  };
  return resolveModel(model, parseAnnotations);
}

describe("an index declares its suite (spec §7.2, #213)", () => {
  it("reads the suite from the declaration, as a hex string or an integer", () => {
    expect(declare('suite_id: "0xFF01", ').indexes[0]!.suiteId).toBe(0xff01);
    expect(declare('suite_id: 0xFF02, ').indexes[0]!.suiteId).toBe(0xff02);
    expect(declare("suite_id: 65281, ").indexes[0]!.suiteId).toBe(0xff01);
  });

  it("refuses a declaration with no suite, naming the model and field", () => {
    expect(() => declare("")).toThrow(FieldsealConfigurationError);
    expect(() => declare("")).toThrow(/Patient\.emailBidx: an index declares no suite_id/);
    expect(() => declare("")).toThrow(/State the suite explicitly/);
    expect(() => declare("")).toThrow(/never taken from the client's writeSuite/);
  });

  it("refuses a suite_id that is not a suite identifier literal", () => {
    expect(() => declare('suite_id: "banana", ')).toThrow(
      /Patient\.emailBidx: suite_id "banana" is not a suite identifier literal/,
    );
  });
});

describe("the extension refuses a map whose index has no suite (spec §7.2)", () => {
  it("names the model and field, and never completes it from writeSuite", () => {
    // `writeSuite` is 0xFF01 and the allow-list contains it: a default taken
    // from either would make this construct. It must not.
    const build = () =>
      fieldsealExtension({ fieldMap: aliasMap(undefined), ...CLIENT_OPTS });
    expect(build).toThrow(FieldsealConfigurationError);
    expect(build).toThrow(/Patient\.alias .*declares no suite_id/);
    expect(build).toThrow(/State the suite explicitly/);
  });

  it("passes the core's own refusal of an unregistered suite, with the column named", () => {
    const build = () =>
      fieldsealExtension({ fieldMap: aliasMap(0x0001), ...CLIENT_OPTS });
    expect(build).toThrow(FieldsealConfigurationError);
    expect(build).toThrow(/Patient\.alias/);
    expect(build).toThrow(/suiteId 0x0001 is not a registered suite/);
  });

  it("refuses a suite that is not a 16-bit identifier, with the core's message", () => {
    expect(() =>
      fieldsealExtension({ fieldMap: aliasMap(0x1_0000), ...CLIENT_OPTS }),
    ).toThrow(/is not a 16-bit suite identifier/);
  });

  it("accepts 0xFF02 as a declared suite although it is not a write suite", () => {
    expect(() =>
      fieldsealExtension({ fieldMap: aliasMap(INDEX_SUITE_FF02), ...CLIENT_OPTS }),
    ).not.toThrow();
  });
});

// --- what the core reports (items 2 and 4's source of truth) ----------------

describe("the core client reports each index's declared suite", () => {
  it("reports 0xFF01 for every index but Patient.alias, which is 0xFF02", () => {
    const map = resolveMap(fieldsealFieldMap);
    const core = buildClient(map, CLIENT_OPTS);
    const bySuite = new Map<string, number>();
    for (const [key, v] of core.indexes) bySuite.set(key, v.suiteId);

    const alias = fieldsealFieldMap.models.find((m) => m.model === "Patient")!;
    const aliasKey = indexRegistryKey(
      uuidBytes(alias.tableUuid!),
      uuidBytes(alias.encrypted.find((e) => e.field === "alias")!.columnUuid),
      "exact",
    );
    expect(bySuite.get(aliasKey)).toBe(0xff02);
    const others = [...bySuite.entries()].filter(([k]) => k !== aliasKey);
    expect(others.length).toBeGreaterThan(0);
    for (const [, s] of others) expect(s).toBe(0xff01);
  });
});

// --- 0xFF02 end to end through the Prisma client (item 5) -------------------

const { base, prisma } = makeClient();
const lp = loose(prisma);

beforeEach(async () => {
  await clearDb(base);
});
afterAll(async () => {
  await base.$disconnect();
});

/** What a core client derives for `value` under `Patient.alias`, declared under `suiteId`. */
function derive(suiteId: number, value: string): string {
  const core = buildClient(resolveMap(aliasMap(suiteId)), CLIENT_OPTS);
  const m = fieldsealFieldMap.models.find((x) => x.model === "Patient")!;
  const ctx: FieldContext = {
    tableUuid: uuidBytes(m.tableUuid!),
    columnUuid: uuidBytes(m.encrypted.find((e) => e.field === "alias")!.columnUuid),
    tenantId: null,
    rowId: null,
    purpose: "index:exact",
  };
  return Buffer.from(core.blindIndex(value, ctx)).toString("hex");
}

const patient = (alias: string, over: Record<string, unknown> = {}) => ({
  email: "owner@example.com",
  note: "n",
  age: 1,
  plainName: "Owner",
  alias,
  ...over,
});

describe("an index declared under 0xFF02 on a client that writes 0xFF01 (spec §7.2, #213)", () => {
  // Chosen so that the two derivations differ in their 15 truncated bits; the
  // test asserts that rather than assuming it.
  const VALUE = "ada@example.com";

  it("creates, and finds the row by equality", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient(VALUE) });
    expect(row["alias"]).toBe(VALUE);

    const found = await lp["patient"]!["findMany"]!({ where: { alias: VALUE } });
    expect((found as unknown as Array<{ id: string }>).map((r) => r.id)).toEqual([row["id"]]);

    const none = await lp["patient"]!["findMany"]!({ where: { alias: "nobody@example.com" } });
    expect(none).toEqual([]);
  });

  it("stores the core's 0xFF02 derivation, which differs from the 0xFF01 one", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient(VALUE) });
    const stored = Buffer.from(
      (await rawColumn(base, "Patient", "aliasBidx", row["id"] as string)) as Uint8Array,
    ).toString("hex");

    expect(stored).toBe(derive(0xff02, VALUE));
    // The same value under an otherwise identical index declared under 0xFF01.
    // The write suite did not reach the index: a different declared suite is a
    // different index key, so these bytes cannot be the stored ones.
    expect(derive(0xff01, VALUE)).not.toBe(stored);
  });

  it("leaves a 0xFF01-declared index on the same row under 0xFF01", async () => {
    const row = await lp["patient"]!["create"]!({ data: patient(VALUE, { email: VALUE }) });
    const emailBidx = Buffer.from(
      (await rawColumn(base, "Patient", "emailBidx", row["id"] as string)) as Uint8Array,
    ).toString("hex");

    const core = buildClient(resolveMap(fieldsealFieldMap), CLIENT_OPTS);
    const m = fieldsealFieldMap.models.find((x) => x.model === "Patient")!;
    const ctx: FieldContext = {
      tableUuid: uuidBytes(m.tableUuid!),
      columnUuid: uuidBytes(m.encrypted.find((e) => e.field === "email")!.columnUuid),
      tenantId: null,
      rowId: null,
      purpose: "index:exact",
    };
    expect(emailBidx).toBe(Buffer.from(core.blindIndex(VALUE, ctx)).toString("hex"));
  });
});
