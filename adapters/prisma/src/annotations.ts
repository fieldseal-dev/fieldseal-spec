/**
 * The `///` annotation grammar (`docs/13` §1).
 *
 * Prisma has no schema extension point, so a declaration is a doc comment:
 *
 *     /// @fieldseal(table_uuid: "018f3c2e-...")            <- on the model
 *     /// @fieldseal(encrypted, column_uuid: "018f3c2e-...")
 *     /// @fieldseal(index: "email", index_id: "exact", idf: "hmac-sha512",
 *     ///            normalize: "nfc-casefold-v1", truncate_bits: 15,
 *     ///            projected_population: 100000)
 *
 * Prisma's parser hands the generator the *joined* documentation string: the
 * `/// ` prefix is stripped from every line and the lines are joined with
 * `\n`. So a declaration that spans several `///` lines -- which the example
 * in `docs/13` §1 already does -- arrives as one string containing newlines.
 * Measured against Prisma 7.10.0, 2026-08-27; the continuation case is pinned
 * by `tests/annotations.test.ts`.
 *
 * Everything here is pure text -> data. It knows nothing about Fieldseal
 * semantics: whether `truncate_bits: 15` is inside the §7.4 band is the core's
 * question, asked at client construction, and deliberately not re-asked here
 * (`checks.ts` explains why the adapter must not re-implement a core gate).
 */

import { FieldsealConfigurationError } from "./errors.ts";

/** A parsed `@fieldseal(...)` call: bare flags plus `key: value` pairs. */
export interface Annotation {
  readonly flags: ReadonlySet<string>;
  readonly values: ReadonlyMap<string, string | number>;
}

/** Where an annotation was found, for error messages that can be acted on. */
export interface Site {
  readonly model: string;
  /** Absent for a model-level annotation. */
  readonly field?: string;
}

export function siteLabel(site: Site): string {
  return site.field === undefined ? site.model : `${site.model}.${site.field}`;
}

const CALL = /@fieldseal\s*\(/g;

/**
 * Extract every `@fieldseal(...)` call from one documentation string.
 *
 * Returns `[]` when there is none -- a doc comment that says something else is
 * an ordinary comment, not an error. A doc comment that *starts* a call and
 * never closes it is an error, because the alternative is treating a
 * truncated declaration as absent, which is the silent-skip this design
 * refuses (`docs/13` §1).
 */
export function parseAnnotations(documentation: string | null | undefined, site: Site): Annotation[] {
  if (documentation === null || documentation === undefined || documentation === "") return [];

  const out: Annotation[] = [];
  CALL.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = CALL.exec(documentation)) !== null) {
    const open = m.index + m[0].length;
    const close = findClose(documentation, open);
    if (close === -1) {
      throw new FieldsealConfigurationError(
        `${siteLabel(site)}: an @fieldseal(...) annotation is not closed -- no ` +
          `matching ")" after column ${String(m.index)}. The declaration was ` +
          `read as:\n  ${documentation.replace(/\n/g, "\n  ")}\n` +
          `An unterminated declaration is refused rather than ignored: ignoring ` +
          `it would leave the column unencrypted with nothing raised.`,
      );
    }
    out.push(parseArgs(documentation.slice(open, close), site));
    CALL.lastIndex = close + 1;
  }
  return out;
}

/** Scan to the `)` that closes the call, respecting quoted strings. */
function findClose(s: string, from: number): number {
  let depth = 1;
  let quote: string | null = null;
  for (let i = from; i < s.length; i++) {
    const ch = s[i]!;
    if (quote !== null) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "(") depth++;
    else if (ch === ")" && --depth === 0) return i;
  }
  return -1;
}

function parseArgs(body: string, site: Site): Annotation {
  const flags = new Set<string>();
  const values = new Map<string, string | number>();

  for (const raw of splitTopLevel(body)) {
    const arg = raw.trim();
    if (arg === "") continue;

    const colon = indexOfTopLevelColon(arg);
    if (colon === -1) {
      if (!/^[a-z_][a-z0-9_]*$/i.test(arg)) {
        throw new FieldsealConfigurationError(
          `${siteLabel(site)}: "${arg}" is not a valid @fieldseal argument. ` +
            `Expected either a bare flag (encrypted) or a key: value pair.`,
        );
      }
      if (flags.has(arg)) {
        throw new FieldsealConfigurationError(
          `${siteLabel(site)}: the flag "${arg}" appears more than once.`,
        );
      }
      flags.add(arg);
      continue;
    }

    const key = arg.slice(0, colon).trim();
    const rawValue = arg.slice(colon + 1).trim();
    if (!/^[a-z_][a-z0-9_]*$/i.test(key)) {
      throw new FieldsealConfigurationError(
        `${siteLabel(site)}: "${key}" is not a valid @fieldseal key.`,
      );
    }
    if (values.has(key)) {
      throw new FieldsealConfigurationError(
        `${siteLabel(site)}: the key "${key}" appears more than once. A repeated ` +
          `key has no defined winner, so it is refused rather than resolved.`,
      );
    }
    values.set(key, parseValue(rawValue, key, site));
  }

  return { flags, values };
}

function parseValue(raw: string, key: string, site: Site): string | number {
  if (raw === "") {
    throw new FieldsealConfigurationError(`${siteLabel(site)}: "${key}" has no value.`);
  }
  const q = raw[0];
  if (q === '"' || q === "'") {
    if (raw.length < 2 || raw[raw.length - 1] !== q) {
      throw new FieldsealConfigurationError(
        `${siteLabel(site)}: the value for "${key}" has an unterminated string.`,
      );
    }
    return raw.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  if (/^-?\d+$/.test(raw)) return Number(raw);
  if (raw === "true" || raw === "false") return raw;
  // A bare word: allowed, so `idf: hmac-sha512` reads the same as the quoted
  // form. Anything with whitespace in it was meant to be quoted.
  if (/^[a-z0-9][a-z0-9._-]*$/i.test(raw)) return raw;
  throw new FieldsealConfigurationError(
    `${siteLabel(site)}: the value for "${key}" (${raw}) is not a quoted string, ` +
      `an integer, or a bare identifier. Quote it if it contains spaces.`,
  );
}

/** Split on commas that are not inside quotes or nested parentheses. */
function splitTopLevel(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let start = 0;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]!;
    if (quote !== null) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "(" || ch === "[") depth++;
    else if (ch === ")" || ch === "]") depth--;
    else if (ch === "," && depth === 0) {
      parts.push(body.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(body.slice(start));
  return parts;
}

function indexOfTopLevelColon(arg: string): number {
  let quote: string | null = null;
  for (let i = 0; i < arg.length; i++) {
    const ch = arg[i]!;
    if (quote !== null) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === ":") return i;
  }
  return -1;
}
