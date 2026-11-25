/**
 * What a codec refusal says (#299), and what it never says.
 *
 * A value the codec refuses was either decrypted from an envelope (the key,
 * the context and the commitment all verified) or, in `permissive` and
 * `readonly`, passed through unread because it was not an envelope (spec
 * §10.3). The two have different causes and different fixes, so the message
 * says which. Neither carries the value: spec §9, "Error messages MUST NOT
 * include plaintext".
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import type { ReadMode } from "@fieldseal/core";

import { fromBytes, toBytes } from "../src/codec.ts";
import { FieldsealNotSupported, type EncryptedFieldDecl, type FieldMap } from "../src/index.ts";
import { clearDb, loose, makeClient, setColumn } from "./helpers.ts";
import { fieldsealFieldMap } from "./fixture/generated/fieldseal-map.ts";

const { base, prisma } = makeClient();
const lp = loose(prisma);

beforeEach(async () => {
  await clearDb(base);
});
afterAll(async () => {
  await base.$disconnect();
});

const PASS_THROUGH: ReadMode[] = ["permissive", "readonly"];
const ALL: ReadMode[] = ["strict", ...PASS_THROUGH];

const patient = (over: Record<string, unknown> = {}) => ({
  email: "ada@example.com",
  note: "a note",
  age: 36,
  plainName: "Ada",
  ...over,
});

/** The fixture map with `Patient.age` declared `as: "string"` instead of `int`. */
function ageAsString(): FieldMap {
  const map = structuredClone(fieldsealFieldMap) as FieldMap & {
    models: { model: string; encrypted: { field: string }[] }[];
  };
  const age = map.models.find((m) => m.model === "Patient")!.encrypted.find((e) => e.field === "age")!;
  (age as { valueType: string }).valueType = "string";
  return map;
}

async function refusal(mode: ReadMode, id: string): Promise<string> {
  const { base: b, prisma: p } = makeClient({ readMode: mode });
  try {
    const err = await p["patient"].findUnique({ where: { id } }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(FieldsealNotSupported);
    return (err as Error).message;
  } finally {
    await b.$disconnect();
  }
}

describe("a passed-through value the codec refuses (#299)", () => {
  it.each(PASS_THROUGH)(
    "%s: says legacy plaintext, never that an envelope was read, and never the value",
    async (mode) => {
      const row = await lp["patient"]!["create"]!({ data: patient() });
      const id = row.id as string;
      await setColumn(base, "Patient", "age", id, Buffer.from("SECRET-abc", "utf8"));
      const msg = await refusal(mode, id);
      expect(msg).toContain("Patient.age");
      expect(msg).toContain("`int`");
      expect(msg).toContain("not an envelope");
      expect(msg).toContain("legacy plaintext");
      expect(msg).toContain("spec §10.3");
      expect(msg).toContain("backfill");
      expect(msg).not.toContain("authentic");
      expect(msg).not.toContain("decrypted value");
      expect(msg).not.toContain("SECRET");
      expect(msg).not.toContain("abc");
    },
  );

  it("a legacy datetime with microseconds gets the same wording and no digits", () => {
    const decl = { field: "v", valueType: "datetime" } as unknown as EncryptedFieldDecl;
    const bytes = Buffer.from("2026-10-05T12:34:56.123456Z", "utf8");
    const passed = errorOf(() => fromBytes(bytes, decl, "Event.at", true));
    expect(passed).toContain("Event.at");
    expect(passed).toContain("not an envelope");
    expect(passed).toContain("legacy plaintext");
    expect(passed).toContain("microseconds");
    expect(passed).not.toContain("123456");
    expect(passed).not.toContain("authentic");
    const decrypted = errorOf(() => fromBytes(bytes, decl, "Event.at", false));
    expect(decrypted).toContain("microsecond");
    expect(decrypted).not.toContain("123456");
    expect(decrypted).not.toContain("legacy plaintext");
  });
});

describe("a decrypted envelope the codec refuses (#299)", () => {
  it.each(ALL)("%s: still says the envelope was authentic, and never the value", async (mode) => {
    // An envelope for `age` whose plaintext is the string bytes: written
    // through a client that declares the column `as: "string"`.
    const { base: wb, prisma: wp } = makeClient({ fieldMap: ageAsString() });
    let id: string;
    try {
      const row = await loose(wp)["patient"]!["create"]!({ data: patient({ age: "SECRET-forty-two" }) });
      id = row.id as string;
    } finally {
      await wb.$disconnect();
    }
    const msg = await refusal(mode, id);
    expect(msg).toContain("Patient.age");
    expect(msg).toContain("the decrypted value is not spec §3.6's canonical `int` rendering");
    expect(msg).toContain("The envelope was authentic");
    expect(msg).not.toContain("legacy plaintext");
    expect(msg).not.toContain("SECRET");
    expect(msg).not.toContain("forty");
  });
});

describe("a write the codec refuses never carries the value (spec §9)", () => {
  const decl = (valueType: string) => ({ field: "v", valueType }) as unknown as EncryptedFieldDecl;
  it.each<[string, unknown, string[]]>([
    // 2^53 + 2 is exactly representable, so it is what a message quoting the
    // value would print.
    ["int beyond 2^53", 2 ** 53 + 2, ["9007199254740994", "900719925474"]],
    ["decimal not finite", "NaN-SECRET", ["SECRET"]],
    ["date not at UTC midnight", new Date("1985-03-17T10:30:00.000Z"), ["1985", "03-17", "10:30"]],
    ["date out of range", new Date("+010000-01-01T00:00:00.000Z"), ["10000", "+01"]],
    ["datetime out of range", new Date("+010000-06-01T12:00:00.000Z"), ["10000", "06-01"]],
  ])("%s", (_name, value, leaks) => {
    const type =
      _name.startsWith("int") ? "int" : _name.startsWith("decimal") ? "decimal"
        : _name.startsWith("datetime") ? "datetime" : "date";
    const msg = errorOf(() => toBytes(value, decl(type), "Patient.v"));
    expect(msg).toContain("Patient.v");
    for (const leak of leaks) expect(msg).not.toContain(leak);
  });
});

function errorOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    return (e as Error).message;
  }
  throw new Error("expected a refusal");
}
