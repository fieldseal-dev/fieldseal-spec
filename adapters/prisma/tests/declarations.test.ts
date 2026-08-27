/**
 * Declaration resolution: what the generator refuses at `prisma generate`.
 *
 * This is the Prisma analogue of Django's system checks. Django reports
 * declaration problems at startup through `django.core.checks`; Prisma has no
 * such framework, and this adapter answers the same need one step earlier, at
 * generate time -- which is strictly better, because a schema that cannot be
 * declared correctly never produces a client at all.
 *
 * The boundary tested here is structural only. The §7.4 band, the §7.6
 * cardinality gate, the Argon2 minima and the §7.2 bucket ceremony belong to
 * the core and are asserted in `client.test.ts`.
 */

import { describe, expect, it } from "vitest";

import { parseAnnotations } from "../src/annotations.ts";
import { type FieldInput, type ModelInput, resolveModel } from "../src/declarations.ts";
import { buildFieldMap } from "../src/generator/emit.ts";

const UUID_A = "018f3c2e-0000-7000-8000-0000000000aa";
const UUID_C = "018f3c2e-0000-7000-8000-000000000001";

const field = (over: Partial<FieldInput> & { name: string }): FieldInput => ({
  type: "Bytes",
  kind: "scalar",
  isList: false,
  isRequired: false,
  ...over,
});

const model = (over: Partial<ModelInput> & { name: string }): ModelInput => ({
  documentation: `@fieldseal(table_uuid: "${UUID_A}")`,
  fields: [],
  ...over,
});

const resolve = (m: ModelInput) => resolveModel(m, parseAnnotations);

const encField = (name = "email", extra = "") =>
  field({ name, documentation: `@fieldseal(encrypted, column_uuid: "${UUID_C}"${extra})` });

const idxField = (name = "emailBidx", source = "email", extra = "") =>
  field({
    name,
    documentation:
      `@fieldseal(index: "${source}", idf: "hmac-sha512", ` +
      `normalize: "nfc-casefold-v1", truncate_bits: 15, ` +
      `projected_population: 100000${extra})`,
  });

describe("resolution", () => {
  it("resolves a model with nothing declared to a relation-only entry", () => {
    // Not dropped: a write can reach an encrypted column *through* an
    // undeclared model, so its relation edges must stay walkable, and a model
    // missing from the map is a runtime staleness error, not a passthrough.
    const m = resolve(
      model({
        name: "Plain",
        documentation: null,
        fields: [
          field({ name: "patient", type: "Patient", kind: "object", relationName: "X2P" }),
        ],
      }),
    );
    expect(m.tableUuid).toBeNull();
    expect(m.encrypted).toEqual([]);
    expect(m.indexes).toEqual([]);
    expect(m.relations).toEqual([{ field: "patient", model: "Patient", isList: false }]);
  });

  it("resolves an encrypted column with its defaults", () => {
    const m = resolve(model({ name: "Patient", fields: [encField()] }))!;
    expect(m.tableUuid).toBe(UUID_A);
    expect(m.encrypted[0]).toMatchObject({
      field: "email",
      columnUuid: UUID_C,
      storage: "binary",
      valueType: "string",
      tenantBound: false,
      noun: "email",
    });
  });

  it("records the relation graph, which the visitor walks", () => {
    const m = resolve(
      model({
        name: "Patient",
        fields: [
          encField(),
          field({ name: "visits", type: "Visit", kind: "object", isList: true, relationName: "P2V" }),
        ],
      }),
    )!;
    expect(m.relations).toEqual([{ field: "visits", model: "Visit", isList: true }]);
  });

  it("defaults `as` to string, so a text column does not round-trip as a Buffer", () => {
    const m = resolve(model({ name: "P", fields: [encField()] }))!;
    expect(m.encrypted[0]?.valueType).toBe("string");
  });

  it("reads an explicit `as`", () => {
    const m = resolve(model({ name: "P", fields: [encField("age", ', as: "int"')] }))!;
    expect(m.encrypted[0]?.valueType).toBe("int");
  });
});

describe("refusals", () => {
  it("refuses a model with an encrypted column and no table_uuid", () => {
    expect(() =>
      resolve(model({ name: "P", documentation: null, fields: [encField()] })),
    ).toThrow(/table_uuid/);
  });

  it("explains why the surrogate may not be derived from the name", () => {
    expect(() =>
      resolve(model({ name: "P", documentation: null, fields: [encField()] })),
    ).toThrow(/rename would make every existing row undecryptable/);
  });

  it("refuses a malformed uuid", () => {
    expect(() =>
      resolve(
        model({
          name: "P",
          fields: [field({ name: "e", documentation: '@fieldseal(encrypted, column_uuid: "nope")' })],
        }),
      ),
    ).toThrow(/must be a UUID/);
  });

  it("refuses an index naming a column that is not encrypted", () => {
    expect(() =>
      resolve(model({ name: "P", fields: [encField(), idxField("xBidx", "nosuch")] })),
    ).toThrow(/not an encrypted column/);
  });

  it("refuses two index siblings over one column (G19 one-equality)", () => {
    expect(() =>
      resolve(
        model({
          name: "P",
          fields: [encField(), idxField("aBidx"), idxField("bBidx")],
        }),
      ),
    ).toThrow(/exactly one equality/);
  });

  it("refuses an index sibling that is not Bytes (spec §7.11)", () => {
    expect(() =>
      resolve(
        model({
          name: "P",
          fields: [encField(), { ...idxField(), type: "String" } as FieldInput],
        }),
      ),
    ).toThrow(/§7\.11/);
  });

  it("refuses a required index sibling, which callers could never satisfy", () => {
    // Prisma's generated create input makes every non-optional column
    // mandatory, so a required sibling would force callers to supply the one
    // value the adapter refuses to accept from them.
    expect(() =>
      resolve(
        model({
          name: "P",
          fields: [encField(), { ...idxField(), isRequired: true } as FieldInput],
        }),
      ),
    ).toThrow(/must be optional/);
  });

  it("refuses a String value column without base64 storage", () => {
    expect(() =>
      resolve(
        model({ name: "P", fields: [{ ...encField(), type: "String" } as FieldInput] }),
      ),
    ).toThrow(/must declare storage: "base64"/);
  });

  it("refuses base64 on a Bytes column, which pays 33% for nothing", () => {
    expect(() =>
      resolve(model({ name: "P", fields: [encField("e", ', storage: "base64"')] })),
    ).toThrow(/for nothing/);
  });

  it("refuses an unknown normalizer, naming portability", () => {
    expect(() =>
      resolve(
        model({
          name: "P",
          fields: [
            encField(),
            field({
              name: "eBidx",
              documentation:
                '@fieldseal(index: "email", idf: "hmac-sha512", normalize: "my-own", ' +
                "truncate_bits: 15, projected_population: 100000)",
            }),
          ],
        }),
      ),
    ).toThrow(/identifier IS the definition/);
  });

  it("refuses an unknown `as` type", () => {
    expect(() =>
      resolve(model({ name: "P", fields: [encField("e", ', as: "money"')] })),
    ).toThrow(/as must be one of/);
  });

  it("refuses a half-specified Argon2 cost", () => {
    expect(() =>
      resolve(
        model({ name: "P", fields: [encField(), idxField("eBidx", "email", ", argon2_time_cost: 3")] }),
      ),
    ).toThrow(/together or not at all/);
  });

  it("reports every problem at once, not just the first", () => {
    // A schema with four mistakes should take one `prisma generate` to find.
    let message = "";
    try {
      resolve(
        model({
          name: "P",
          documentation: null,
          fields: [
            field({ name: "a", documentation: '@fieldseal(encrypted, column_uuid: "bad1")' }),
            field({ name: "b", documentation: '@fieldseal(encrypted, column_uuid: "bad2")' }),
          ],
        }),
      );
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/P\.a/);
    expect(message).toMatch(/P\.b/);
    expect(message).toMatch(/table_uuid/);
  });
});

describe("buildFieldMap", () => {
  it("aggregates problems across models", () => {
    let message = "";
    try {
      buildFieldMap(
        {
          models: [
            model({ name: "A", documentation: null, fields: [encField()] }),
            model({ name: "B", documentation: null, fields: [encField()] }),
          ],
        },
        "test",
      );
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/2 model\(s\) have declaration errors/);
  });

  it("emits every model, declared or not -- an omitted model was a bypass", () => {
    const map = buildFieldMap(
      {
        models: [
          model({ name: "Plain", documentation: null }),
          model({ name: "Patient", fields: [encField()] }),
        ],
      },
      "test",
    );
    expect(map.models.map((m) => m.model)).toEqual(["Plain", "Patient"]);
    const plain = map.models.find((m) => m.model === "Plain")!;
    expect(plain.tableUuid).toBeNull();
    expect(plain.encrypted).toEqual([]);
  });
});

describe("uniqueness refusals (spec §7.10)", () => {
  it("refuses @unique on an encrypted column", () => {
    expect(() =>
      resolve(model({ name: "P", fields: [{ ...encField(), isUnique: true } as FieldInput] })),
    ).toThrow(/cannot be @unique or @id/);
  });

  it("refuses @id on an encrypted column", () => {
    expect(() =>
      resolve(model({ name: "P", fields: [{ ...encField(), isId: true } as FieldInput] })),
    ).toThrow(/cannot be @unique or @id/);
  });

  it("refuses @unique on an index sibling, naming the delayed data loss", () => {
    // §7.4 mandates collisions, so a UNIQUE sibling starts rejecting
    // legitimate distinct values as the table fills.
    expect(() =>
      resolve(
        model({ name: "P", fields: [encField(), { ...idxField(), isUnique: true } as FieldInput] }),
      ),
    ).toThrow(/rejecting legitimate distinct values/);
  });

  it("refuses an encrypted column inside a @@unique group", () => {
    expect(() =>
      resolve(
        model({
          name: "P",
          fields: [field({ name: "org" }), encField()],
          uniqueFields: [["org", "email"]],
        }),
      ),
    ).toThrow(/part of a @@unique or @@id/);
  });

  it("refuses an index sibling inside a compound @@id", () => {
    expect(() =>
      resolve(
        model({
          name: "P",
          fields: [encField(), idxField()],
          primaryKey: { fields: ["emailBidx", "email"] },
        }),
      ),
    ).toThrow(/part of a @@unique or @@id/);
  });
});
