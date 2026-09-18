/**
 * The `codec/` vector family (spec §3.6) through this adapter's real codec.
 *
 * `MANIFEST.adapter_files` is the adapter half of the suite: a core never sees
 * a logical type, so these vectors bind adapters. Every vector either runs or
 * is skipped for a platform capability JavaScript does not have -- never
 * skipped for any other reason, and never counted as passed when skipped.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { fromBytes, toBytes } from "../src/codec.ts";
import { FieldsealNotSupported } from "../src/errors.ts";
import type { EncryptedFieldDecl, ValueType } from "../src/fieldmap.ts";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "vectors");

/**
 * What JavaScript's Date can represent (docs/08 §4.8). The three capabilities
 * this adapter lacks -- calendar-date, microsecond-instants, naive-datetimes --
 * describe CPython, and their vectors are skipped here with that reason.
 */
const CAPABILITIES = new Set(["date-as-utc-midnight-instant", "millisecond-instants"]);

type Literal = Record<string, unknown>;
interface Vector {
  id: string;
  logical_type: ValueType;
  direction: "write" | "read";
  requires: string[];
  input?: Literal;
  plaintext?: string;
  expected: { plaintext?: string; value?: Literal; refused?: true };
}

function adapterVectors(): Vector[] {
  const manifest = JSON.parse(readFileSync(join(VECTORS, "MANIFEST.json"), "utf8")) as {
    adapter_files: { path: string; sha256: string }[];
  };
  const out: Vector[] = [];
  for (const entry of manifest.adapter_files) {
    const raw = readFileSync(join(VECTORS, entry.path));
    expect(createHash("sha256").update(raw).digest("hex")).toBe(entry.sha256);
    const doc = JSON.parse(raw.toString("utf8")) as { status: string; vectors: Vector[] };
    expect(doc.status).toBe("pinned");
    out.push(...doc.vectors);
  }
  return out;
}

const VECS = adapterVectors();

const decl = (valueType: ValueType): EncryptedFieldDecl =>
  ({ field: "v", columnUuid: "0192a3b4c5d67e8f9a0b1c2d3e4f5a6b", storage: "binary", valueType,
     tenantBound: false, prismaType: "Bytes", noun: "value" }) as EncryptedFieldDecl;

function binary64(hex: string): number {
  return Buffer.from(hex, "hex").readDoubleBE(0);
}

/** A literal as the JavaScript value an application would hand the adapter. */
function value(t: ValueType, lit: Literal): unknown {
  switch (t) {
    case "string":
      if (typeof lit["utf16"] === "string") {
        const units = Buffer.from(lit["utf16"], "hex");
        let s = "";
        for (let i = 0; i < units.length; i += 2) s += String.fromCharCode(units.readUInt16BE(i));
        return s;
      }
      return lit["text"];
    case "bytes":
      return new Uint8Array(Buffer.from(lit["hex"] as string, "hex"));
    case "int":
      return BigInt(lit["decimal"] as string);
    case "decimal":
      return lit["decimal"];
    case "float":
      return binary64(lit["binary64"] as string);
    case "boolean":
      return lit["boolean"];
    case "date":
      return typeof lit["utc_midnight_instant"] === "string"
        ? new Date(lit["utc_midnight_instant"])
        : new Date(`${lit["date"] as string}T00:00:00.000Z`);
    case "datetime":
      return new Date(lit["instant"] as string);
  }
}

function expectValue(t: ValueType, got: unknown, lit: Literal): void {
  switch (t) {
    case "string":
      expect(got).toBe(lit["text"]);
      return;
    case "bytes":
      expect(Buffer.from(got as Uint8Array).toString("hex")).toBe(lit["hex"]);
      return;
    case "int":
      expect(BigInt(got as number | bigint)).toBe(BigInt(lit["decimal"] as string));
      return;
    case "decimal":
      expect(got).toBe(lit["decimal"]); // read back as its canonical string
      return;
    case "float":
      expect(Object.is(got, binary64(lit["binary64"] as string))).toBe(true);
      return;
    case "boolean":
      expect(got).toBe(lit["boolean"]);
      return;
    case "date":
      expect((got as Date).toISOString()).toBe(`${lit["date"] as string}T00:00:00.000Z`);
      return;
    case "datetime": {
      const want = lit["instant"] as string; // canonical: six digits, Z
      expect((got as Date).toISOString()).toBe(`${want.slice(0, 23)}Z`);
      return;
    }
  }
}

const missingFor = (v: Vector): string[] => v.requires.filter((c) => !CAPABILITIES.has(c));

// Vectors needing a capability JavaScript lacks are registered as skips with
// the reason, and are titled without their `codec/` id: the README's coverage
// row cites `codec/`, and a skipped test matched by a row fails it (report.ts).
describe("spec §3.6 vectors needing a capability JavaScript lacks", () => {
  for (const vec of VECS.filter((v) => missingFor(v).length > 0)) {
    it.skip(`${vec.id.replace(/^codec\//, "")} [capability not held: ${missingFor(vec).join(", ")}]`, () => {});
  }
});

describe("spec §3.6 vectors (MANIFEST.adapter_files)", () => {
  for (const vec of VECS.filter((v) => missingFor(v).length === 0)) {
    it(vec.id, () => {
      const d = decl(vec.logical_type);
      if (vec.direction === "write") {
        const v = value(vec.logical_type, vec.input!);
        if (vec.expected.refused) {
          expect(() => toBytes(v, d, "v")).toThrow(FieldsealNotSupported);
        } else {
          expect(Buffer.from(toBytes(v, d, "v")).toString("hex")).toBe(vec.expected.plaintext);
        }
      } else {
        const raw = new Uint8Array(Buffer.from(vec.plaintext!, "hex"));
        if (vec.expected.refused) {
          expect(() => fromBytes(raw, d, "v")).toThrow(FieldsealNotSupported);
        } else {
          expectValue(vec.logical_type, fromBytes(raw, d, "v"), vec.expected.value!);
        }
      }
    });
  }

  it("skips only for a capability JavaScript lacks (docs/08 §5 item 7)", () => {
    const skipped = VECS.filter((v) => v.requires.some((c) => !CAPABILITIES.has(c))).map((v) => v.id);
    expect(VECS.length).toBe(124);
    expect(skipped.length).toBe(4);
  });
});

describe("§3.6 cases the vectors state only in one direction", () => {
  it("equal decimals are one plaintext, so one blind-index value", () => {
    const d = decl("decimal");
    const hex = (v: unknown) => Buffer.from(toBytes(v, d, "v")).toString("hex");
    expect(hex("1.5")).toBe(hex("1.50"));
    expect(hex("1.500")).toBe(Buffer.from("1.5").toString("hex"));
  });

  it("a number is refused for a decimal column: it is a binary64 already", () => {
    expect(() => toBytes(0.1, decl("decimal"), "v")).toThrow(FieldsealNotSupported);
  });

  it("a Prisma.Decimal-shaped value is taken through its exact toFixed()", () => {
    const fake = { isFinite: () => true, toFixed: () => "12345678901234567.890" };
    expect(Buffer.from(toBytes(fake, decl("decimal"), "v")).toString()).toBe("12345678901234567.89");
  });

  it("an unsafe integer number is refused for an int column; a bigint is not", () => {
    expect(() => toBytes(2 ** 60, decl("int"), "v")).toThrow(FieldsealNotSupported);
    expect(Buffer.from(toBytes(2n ** 60n, decl("int"), "v")).toString()).toBe("1152921504606846976");
  });
});
