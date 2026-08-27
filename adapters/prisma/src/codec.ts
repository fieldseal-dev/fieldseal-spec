/**
 * Value <-> bytes, and envelope <-> column.
 *
 * Two conversions, deliberately separated because they fail differently.
 *
 * **The codec** turns an application value into the plaintext bytes that get
 * encrypted, under the column's declared `as:` type. This is an adapter
 * decision that no core test can see: a core round trip is handed bytes and
 * gives bytes back, so nothing in the vector suite pins that an `int` column's
 * value is its decimal ASCII. A consumer in another language decodes whatever
 * this chose, which is why the cross-language producer (`docs/14` §3) exercises
 * every declared type rather than only text.
 *
 * The renderings are deliberately the dullest portable ones -- decimal ASCII
 * for numbers, `true`/`false`, ISO-8601 UTC for instants -- because the
 * consumer is a different language, not this one. Anything cleverer (a
 * platform integer encoding, a locale-aware date) is a cross-language
 * divergence waiting to be discovered by a decrypt that succeeds and returns
 * the wrong value.
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

/** Application value -> plaintext bytes, under the declared `as:` type. */
export function toBytes(value: unknown, decl: EncryptedFieldDecl, label: string): Uint8Array {
  const enc = (s: string) => Buffer.from(s, "utf8");
  switch (decl.valueType) {
    case "string":
      if (typeof value === "string") return enc(value);
      break;
    case "bytes":
      if (value instanceof Uint8Array) return value;
      break;
    case "int":
      if (typeof value === "bigint") return enc(value.toString());
      if (typeof value === "number" && Number.isInteger(value)) return enc(String(value));
      break;
    case "float":
      if (typeof value === "number" && Number.isFinite(value)) return enc(String(value));
      break;
    case "boolean":
      if (typeof value === "boolean") return enc(value ? "true" : "false");
      break;
    case "datetime":
      if (value instanceof Date && !Number.isNaN(value.getTime())) {
        return enc(value.toISOString());
      }
      break;
  }
  throw new FieldsealNotSupported(
    `${label}: declared \`as: "${decl.valueType}"\` but was given ` +
      `${describe(value)}. The adapter refuses rather than coercing: the byte ` +
      `rendering it picks is what a reader in another language must decode, and ` +
      `a coerced value decrypts cleanly into the wrong thing. Either write the ` +
      `declared type, or change \`as:\` -- which is a new plaintext encoding for ` +
      `every row already written.`,
  );
}

/** Plaintext bytes -> application value, under the declared `as:` type. */
export function fromBytes(plaintext: Uint8Array, decl: EncryptedFieldDecl, label: string): unknown {
  const buf = Buffer.from(plaintext);
  switch (decl.valueType) {
    case "bytes":
      return buf;
    case "string":
      return buf.toString("utf8");
    case "int": {
      const s = buf.toString("utf8");
      if (!/^-?\d+$/.test(s)) break;
      const n = Number(s);
      return Number.isSafeInteger(n) ? n : BigInt(s);
    }
    case "float": {
      const n = Number(buf.toString("utf8"));
      if (Number.isNaN(n)) break;
      return n;
    }
    case "boolean": {
      const s = buf.toString("utf8");
      if (s === "true") return true;
      if (s === "false") return false;
      break;
    }
    case "datetime": {
      const d = new Date(buf.toString("utf8"));
      if (Number.isNaN(d.getTime())) break;
      return d;
    }
  }
  // The bytes decrypted -- so the key, the context and the commitment were all
  // right -- and then did not parse as the declared type. That is a declaration
  // that changed after the row was written, and returning a coerced value would
  // hide it.
  throw new FieldsealNotSupported(
    `${label}: the decrypted value does not parse as \`as: "${decl.valueType}"\`. ` +
      `The envelope was authentic, so this is not tampering: the column's ` +
      `declared type changed after this row was written. Changing \`as:\` is a ` +
      `new plaintext encoding and needs a backfill, not an edit.`,
  );
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
