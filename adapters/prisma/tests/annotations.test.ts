/**
 * The `///` annotation grammar.
 */

import { describe, expect, it } from "vitest";

import { parseAnnotations } from "../src/annotations.ts";
import { FieldsealConfigurationError } from "../src/index.ts";

const site = { model: "Patient", field: "email" };
const one = (doc: string) => {
  const anns = parseAnnotations(doc, site);
  expect(anns).toHaveLength(1);
  return anns[0]!;
};

describe("parsing", () => {
  it("reads bare flags and key: value pairs", () => {
    const a = one('@fieldseal(encrypted, column_uuid: "018f3c2e-0000-7000-8000-000000000001")');
    expect(a.flags.has("encrypted")).toBe(true);
    expect(a.values.get("column_uuid")).toBe("018f3c2e-0000-7000-8000-000000000001");
  });

  it("reads a declaration split across several /// lines", () => {
    // The case that matters and would otherwise be found in production.
    // Prisma strips the `/// ` prefix and joins the lines with `\n`, so a
    // multi-line declaration -- which docs/13 §1's own example is -- arrives as
    // one string containing newlines. Measured against Prisma 7.10.0.
    const doc =
      '@fieldseal(index: "email", index_id: "exact", idf: "hmac-sha512",\n' +
      'normalize: "nfc-casefold-v1", truncate_bits: 15,\n' +
      "projected_population: 100000)";
    const a = one(doc);
    expect(a.values.get("index")).toBe("email");
    expect(a.values.get("truncate_bits")).toBe(15);
    expect(a.values.get("projected_population")).toBe(100000);
    expect(a.values.get("normalize")).toBe("nfc-casefold-v1");
  });

  it("reads integers as numbers and bare words as strings", () => {
    const a = one("@fieldseal(index: email, truncate_bits: 15, idf: hmac-sha512)");
    expect(a.values.get("truncate_bits")).toBe(15);
    expect(a.values.get("idf")).toBe("hmac-sha512");
  });

  it("keeps commas inside quoted values", () => {
    const a = one('@fieldseal(encrypted, noun: "given name, legal")');
    expect(a.values.get("noun")).toBe("given name, legal");
  });

  it("ignores a doc comment that is not a fieldseal declaration", () => {
    expect(parseAnnotations("The patient's email address.", site)).toEqual([]);
    expect(parseAnnotations(null, site)).toEqual([]);
    expect(parseAnnotations(undefined, site)).toEqual([]);
  });

  it("reads a doc comment that mixes prose and a declaration", () => {
    const a = one('The email.\n@fieldseal(encrypted, column_uuid: "x")');
    expect(a.flags.has("encrypted")).toBe(true);
  });
});

describe("refusals", () => {
  it("refuses an unterminated declaration rather than ignoring it", () => {
    // Ignoring it would leave the column unencrypted with nothing raised --
    // the silent skip the whole design refuses.
    expect(() => parseAnnotations('@fieldseal(encrypted, column_uuid: "x"', site)).toThrow(
      FieldsealConfigurationError,
    );
    expect(() => parseAnnotations('@fieldseal(encrypted, column_uuid: "x"', site)).toThrow(
      /not closed/,
    );
  });

  it("refuses an unterminated string", () => {
    expect(() => parseAnnotations('@fieldseal(column_uuid: "x)', site)).toThrow(
      /not closed|unterminated/,
    );
  });

  it("refuses a repeated key, because there is no defined winner", () => {
    expect(() => parseAnnotations('@fieldseal(a: "1", a: "2")', site)).toThrow(
      /appears more than once/,
    );
  });

  it("refuses a repeated flag", () => {
    expect(() => parseAnnotations("@fieldseal(encrypted, encrypted)", site)).toThrow(
      /appears more than once/,
    );
  });

  it("refuses a key with no value", () => {
    expect(() => parseAnnotations("@fieldseal(column_uuid:)", site)).toThrow(/has no value/);
  });

  it("names the model and field in every message", () => {
    expect(() => parseAnnotations('@fieldseal(a: "1", a: "2")', site)).toThrow(/Patient\.email/);
  });
});
