/**
 * Value <-> bytes, and envelope <-> column.
 *
 * Two conversions, deliberately separated because they fail differently.
 *
 * **The codec** turns an application value into the plaintext bytes that get
 * encrypted, under the column's declared `as:` type -- one of spec §3.6's eight
 * logical types -- and back. The rendering is §3.6's, byte for byte, and the
 * `codec/` vector family pins it (`MANIFEST.adapter_files`). Before §3.6 it was
 * this file's own choice, and it disagreed with the Django adapter on four of
 * eight types (G25, #123): a date written by Django came back from here as an
 * instant and was rewritten as one, which Django then could not read.
 *
 * Both directions refuse rather than coerce. A value §3.6 does not admit is
 * refused on write; bytes that are not the canonical rendering are refused on
 * read, because the envelope was authentic and a coerced value would hide
 * that the row was written by something else. Two refusals are specific to
 * JavaScript and are stated in §3.6: a `datetime` whose microseconds this
 * platform's `Date` cannot hold, and a `date` that is not exactly at the UTC
 * midnight this adapter uses to represent a calendar date.
 *
 * **The storage form** turns the envelope into what the column holds: raw
 * bytes for `Bytes`, base64 ASCII for a `String` column carrying
 * `storage: "base64"`. A consumer handed the wrong one fails at the length
 * gate with an error pointing at the envelope rather than at the column.
 *
 * Never pickle, never revive a stored value into a live object: a deserializer
 * that can construct arbitrary objects turns a decryption boundary into a
 * code-execution boundary.
 */

import { FieldsealNotSupported } from "./errors.ts";
import type { EncryptedFieldDecl } from "./fieldmap.ts";

const INT = /^(0|-?[1-9][0-9]*)$/;
const DECIMAL_CANONICAL = /^-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$/;
/** Decimal notation a caller may write: sign, digits, point, exponent. */
const DECIMAL_INPUT = /^([+-]?)([0-9]*)(?:\.([0-9]*))?(?:[eE]([+-]?[0-9]+))?$/;
const FLOAT = /^-?[0-9]+(\.[0-9]+)?(e[+-][0-9]+)?$/;
const DATE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/;
const DATETIME = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})Z$/;
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Application value -> plaintext bytes, under the declared `as:` type. */
export function toBytes(value: unknown, decl: EncryptedFieldDecl, label: string): Uint8Array {
  const enc = (s: string) => Buffer.from(s, "ascii");
  switch (decl.valueType) {
    case "string":
      if (typeof value === "string") {
        // Buffer.from would write U+FFFD for an unpaired surrogate without a
        // word; §3.6 refuses it.
        const at = unpairedSurrogateAt(value);
        if (at >= 0) {
          throw refuseWrite(label, "string", `it contains an unpaired surrogate at index ${at}, which has no UTF-8 encoding`);
        }
        return Buffer.from(value, "utf8");
      }
      break;
    case "bytes":
      if (value instanceof Uint8Array) return value;
      break;
    case "int":
      if (typeof value === "bigint") return enc(value.toString());
      if (typeof value === "number" && Number.isInteger(value)) {
        if (!Number.isSafeInteger(value)) {
          throw refuseWrite(label, "int", `${value} is beyond 2^53, where a number may already have been rounded; pass a bigint`);
        }
        return enc(BigInt(value).toString());
      }
      break;
    case "decimal": {
      const text = decimalText(value);
      if (text === null) break;
      const canon = canonicalDecimal(text);
      if (canon === null) throw refuseWrite(label, "decimal", `${JSON.stringify(text)} is not a finite decimal`);
      return enc(canon);
    }
    case "float":
      if (typeof value === "number") {
        if (!Number.isFinite(value)) throw refuseWrite(label, "float", `${value} is not finite`);
        return enc(renderFloat(value));
      }
      break;
    case "boolean":
      if (typeof value === "boolean") return enc(value ? "true" : "false");
      break;
    case "date":
      if (value instanceof Date && !Number.isNaN(value.getTime())) {
        const iso = value.toISOString();
        if (!iso.endsWith("T00:00:00.000Z")) {
          throw refuseWrite(label, "date", `${iso} is not exactly UTC midnight, which is how this adapter represents a calendar date; it is refused rather than truncated to a day`);
        }
        if (!inYearRange(value)) throw refuseWrite(label, "date", `${iso} is outside years 0001-9999`);
        return enc(iso.slice(0, 10));
      }
      break;
    case "datetime":
      if (value instanceof Date && !Number.isNaN(value.getTime())) {
        if (!inYearRange(value)) throw refuseWrite(label, "datetime", `${value.toISOString()} is outside years 0001-9999`);
        const iso = value.toISOString(); // YYYY-MM-DDTHH:MM:SS.sssZ in range
        return enc(`${iso.slice(0, 23)}000Z`);
      }
      break;
  }
  throw new FieldsealNotSupported(
    `${label}: declared \`as: "${decl.valueType}"\` but was given ` +
      `${describe(value)}. The adapter refuses rather than coercing: the byte ` +
      `rendering is spec §3.6's, what a reader in another language must decode, ` +
      `and a coerced value decrypts cleanly into the wrong thing. Either write the ` +
      `declared type, or change \`as:\` -- which is a new plaintext encoding for ` +
      `every row already written.${hint(decl.valueType)}`,
  );
}

/** Plaintext bytes -> application value, under the declared `as:` type. */
export function fromBytes(plaintext: Uint8Array, decl: EncryptedFieldDecl, label: string): unknown {
  const buf = Buffer.from(plaintext);
  switch (decl.valueType) {
    case "bytes":
      return buf;
    case "string":
      try {
        return STRICT_UTF8.decode(buf);
      } catch {
        break;
      }
    case "int": {
      const s = buf.toString("latin1");
      if (!INT.test(s)) break;
      const n = Number(s);
      return Number.isSafeInteger(n) ? n : BigInt(s);
    }
    case "decimal": {
      const s = buf.toString("latin1");
      if (s === "-0" || !DECIMAL_CANONICAL.test(s)) break;
      return s;
    }
    case "float": {
      const s = buf.toString("latin1");
      if (!FLOAT.test(s)) break;
      const n = Number(s);
      if (!Number.isFinite(n) || renderFloat(n) !== s) break;
      return n;
    }
    case "boolean": {
      const s = buf.toString("latin1");
      if (s === "true") return true;
      if (s === "false") return false;
      break;
    }
    case "date": {
      const m = DATE.exec(buf.toString("latin1"));
      if (m === null) break;
      const d = utc(+m[1]!, +m[2]!, +m[3]!, 0, 0, 0, 0);
      if (d === null) break;
      return d;
    }
    case "datetime": {
      const m = DATETIME.exec(buf.toString("latin1"));
      if (m === null) break;
      const micros = m[7]!;
      if (!micros.endsWith("000")) {
        // §3.6: a Date holds milliseconds. Truncating .123456 to .123 is what
        // Node would do silently; refuse instead.
        throw new FieldsealNotSupported(
          `${label}: the stored instant carries microseconds (.${micros}) that a ` +
            `JavaScript Date cannot hold. Spec §3.6 refuses rather than truncating; ` +
            `the row was written by a platform with microsecond instants.`,
        );
      }
      const d = utc(+m[1]!, +m[2]!, +m[3]!, +m[4]!, +m[5]!, +m[6]!, +micros.slice(0, 3));
      if (d === null) break;
      return d;
    }
  }
  // The bytes decrypted -- so the key, the context and the commitment were all
  // right -- and then were not the canonical rendering of the declared type.
  // Returning a coerced value would hide it.
  throw new FieldsealNotSupported(
    `${label}: the decrypted value is not spec §3.6's canonical \`${decl.valueType}\` ` +
      `rendering. The envelope was authentic, so this is not tampering: the row ` +
      `was written by something that does not render §3.6, or the column's ` +
      `declared type changed after it was written. Changing \`as:\` is a new ` +
      `plaintext encoding and needs a backfill, not an edit.`,
  );
}

/**
 * Spec §3.6 `float`: ECMA-262 Number::toString, which `String()` is, except
 * that negative zero keeps its sign -- `String(-0)` is `"0"`.
 */
function renderFloat(x: number): string {
  return Object.is(x, -0) ? "-0" : String(x);
}

/** The text of a decimal the caller handed over, or null for a wrong type. */
function decimalText(value: unknown): string | null {
  if (typeof value === "string") return value;
  // Prisma.Decimal (decimal.js): toFixed() with no argument is its exact,
  // exponent-free form. A number is refused: it is a binary64 already.
  if (
    typeof value === "object" && value !== null &&
    typeof (value as { toFixed?: unknown }).toFixed === "function" &&
    typeof (value as { isFinite?: unknown }).isFinite === "function"
  ) {
    const d = value as { toFixed(): string; isFinite(): boolean };
    return d.isFinite() ? d.toFixed() : "NaN";
  }
  return null;
}

/**
 * Spec §3.6 canonical decimal, by string arithmetic alone -- no binary64 ever
 * touches the digits. Null when `text` is not decimal notation or not finite.
 */
function canonicalDecimal(text: string): string | null {
  const m = DECIMAL_INPUT.exec(text);
  if (m === null) return null;
  const [, sign, ip = "", fp = "", e = "0"] = m;
  if (ip === "" && fp === "") return null; // ".", "", "e5"
  let digits = (ip + fp).replace(/^0+/, "");
  if (digits === "") return "0";
  let exp = Number(e) - fp.length; // value = digits * 10^exp
  if (!Number.isSafeInteger(exp)) return null;
  const stripped = digits.replace(/0+$/, "");
  exp += digits.length - stripped.length;
  digits = stripped;
  let body: string;
  if (exp >= 0) {
    body = digits + "0".repeat(exp);
  } else {
    const point = digits.length + exp;
    body = point > 0 ? `${digits.slice(0, point)}.${digits.slice(point)}` : `0.${"0".repeat(-point)}${digits}`;
  }
  return (sign === "-" ? "-" : "") + body;
}

/**
 * Index of the first unpaired UTF-16 surrogate, or -1. By hand rather than
 * `String.prototype.isWellFormed`, which is ES2024 and outside this package's
 * `lib`; the TypeScript core scans the same way (`normalize.ts`).
 */
function unpairedSurrogateAt(s: string): number {
  for (let i = 0; i < s.length; i++) {
    const unit = s.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
      return i;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) return i;
  }
  return -1;
}

function inYearRange(d: Date): boolean {
  const y = d.getUTCFullYear();
  return y >= 1 && y <= 9999;
}

/** A UTC Date from components, or null unless every component survives. */
function utc(y: number, mo: number, d: number, h: number, mi: number, s: number, ms: number): Date | null {
  if (y < 1) return null;
  const out = new Date(0);
  // setUTCFullYear, not Date.UTC: Date.UTC maps years 0-99 to 1900-1999.
  out.setUTCFullYear(y, mo - 1, d);
  out.setUTCHours(h, mi, s, ms);
  // A rollover (February 30, hour 24, second 60) changes a component.
  const ok =
    out.getUTCFullYear() === y && out.getUTCMonth() === mo - 1 && out.getUTCDate() === d &&
    out.getUTCHours() === h && out.getUTCMinutes() === mi && out.getUTCSeconds() === s;
  return ok ? out : null;
}

function refuseWrite(label: string, type: string, why: string): FieldsealNotSupported {
  return new FieldsealNotSupported(`${label}: \`as: "${type}"\` refuses this value: ${why} (spec §3.6).`);
}

function hint(type: string): string {
  if (type === "decimal") return " A decimal is written as a string or a Prisma.Decimal, and read back as its canonical string.";
  if (type === "date") return " A date is written and read as a Date at exactly UTC midnight.";
  return "";
}

/** Envelope -> the value written to the column. */
export function toColumn(envelope: Uint8Array, decl: EncryptedFieldDecl): Uint8Array | string {
  return decl.storage === "base64"
    ? Buffer.from(envelope).toString("base64")
    : Buffer.from(envelope);
}

/** Column value -> envelope bytes, or `null` if this does not look stored. */
export function fromColumn(stored: unknown, decl: EncryptedFieldDecl): Uint8Array | null {
  if (stored === null || stored === undefined) return null;
  if (decl.storage === "base64") {
    return typeof stored === "string" ? Buffer.from(stored, "base64") : null;
  }
  return stored instanceof Uint8Array ? Buffer.from(stored) : null;
}

function describe(v: unknown): string {
  if (v === null) return "null";
  if (v === undefined) return "undefined";
  if (Array.isArray(v)) return "an array";
  if (v instanceof Uint8Array) return "bytes";
  return typeof v === "object" ? `a ${v.constructor?.name ?? "object"}` : `a ${typeof v}`;
}
