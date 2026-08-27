/**
 * Unindexable values (`docs/09` §7.2, `docs/13` §9).
 *
 * `encrypt` does not normalize and `blindIndex` does, so a value containing a
 * code point the pinned Unicode version does not define **stores but cannot be
 * fingerprinted**. Under `on_unindexable: "refuse"` (the default) the core
 * throws `INVALID_ARGUMENT` and the extension lets it out of the operation, so
 * the caller sees a rejected write. Under `"bucket"` the core substitutes the
 * column's reserved marker and the write succeeds, and the query path needs no
 * special case -- the same marker is derived for the operand.
 *
 * The important half is the query path, and it is the §10.2 rule this adapter
 * already lives under: this adapter's whole reason for existing is that
 * `prisma-field-encryption` encrypts filter operands and silently returns
 * nothing. Swallowing an unindexable-value error and returning `[]` would be
 * the same failure with a different cause.
 *
 * **The message.** The extension throws; it does not render. But the thrown
 * error MUST carry what a UI needs to build the message in `docs/12` §10.2 --
 * the offending code point and its offset -- because an error that says only
 * "invalid input" forces the application to show that to a person or guess.
 * The three rules: name the character and its position, put the fault on the
 * system, and offer a route that ends with the real value stored.
 *
 * **A gap this works around, and should not have to.** `docs/09` §7.1 says
 * cores MUST export the assigned-code-point check (`firstUnassigned` /
 * `first_unassigned`) precisely "for adapters that hold the text earlier and
 * can give a better-sited error" -- which is this adapter. Neither core does:
 * the TypeScript core re-exports it from `normalize.ts` but not from
 * `src/index.ts`, and the Python core has it in `blindindex.py` and
 * `unicode/__init__.py` but not in `fieldseal/__init__.py`. So the only route
 * to the code point and offset today is the core's own error *message*, which
 * this module parses. That is a dependency on prose, and it is why the gap is
 * filed rather than quietly lived with.
 */

import { InvalidArgumentError } from "@fieldseal/core";

import { FieldsealNotSupported } from "./errors.ts";

/** What a UI needs to render `docs/12` §10.2's message. */
export interface UnindexableDetail {
  /** e.g. `"U+0378"`. */
  readonly codePoint: string | null;
  /** Offset into the value, when the core reported one. */
  readonly offset: number | null;
  /** What to call the value to a person. */
  readonly noun: string;
}

export class FieldsealUnindexable extends FieldsealNotSupported {
  readonly detail: UnindexableDetail;
  constructor(message: string, detail: UnindexableDetail) {
    super(message);
    this.name = "FieldsealUnindexable";
    this.detail = detail;
  }
}

const CODE_POINT = /\bU\+[0-9A-F]{4,6}\b/;
const OFFSET = /\bat index (\d+)\b/;

/**
 * Turn the core's refusal into one an application can render.
 *
 * Anything that is not an unindexable-value refusal is returned untouched: a
 * `KEY_UNAVAILABLE` must not be re-dressed as a data-quality problem.
 */
export function unindexableError(e: unknown, label: string, noun: string): unknown {
  if (!(e instanceof InvalidArgumentError)) return e;

  const cp = CODE_POINT.exec(e.message)?.[0] ?? null;
  const off = OFFSET.exec(e.message)?.[1];
  const offset = off === undefined ? null : Number(off);
  if (cp === null && offset === null) return e;

  const where =
    offset === null ? "" : ` at position ${String(offset + 1)}`;
  return new FieldsealUnindexable(
    `${label}: this ${noun} contains a character (${cp ?? "unknown"})${where} that ` +
      `this system cannot index yet, so it cannot be saved on a searchable ` +
      `column. This is a limitation of the system, not a problem with the ` +
      `value: the index is pinned to a published Unicode version, and a ` +
      `character added after that pin has no agreed handling, so two servers ` +
      `would fingerprint it differently and the row would silently stop being ` +
      `findable. The value itself is storable -- an operator can enable ` +
      `\`on_unindexable: "bucket"\` for this column, which keeps the real value ` +
      `and keeps the row findable, at the documented cost in docs/12 §10.4. ` +
      `Original: ${e.message}`,
    { codePoint: cp, offset, noun },
  );
}
