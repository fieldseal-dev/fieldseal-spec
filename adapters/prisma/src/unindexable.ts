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
 * **The gap this used to work around, closed 2026-08-31 (G22, #88).** `docs/09`
 * §7.1 says cores MUST export the assigned-code-point check (`firstUnassigned`
 * / `first_unassigned`) precisely "for adapters that hold the text earlier and
 * can give a better-sited error" -- which is this adapter. Neither core did, so
 * this module parsed the code point and offset out of the core's error
 * *message*: a dependency on prose. Both cores now export it, returning the
 * code point **and its offset in code points**, and this module calls it.
 *
 * Closing it turned up a defect the issue did not know about. The offset regex
 * (`/at index (\d+)/`) matched only the `identity`/bytes path's message.
 * On `nfc-casefold-v1` -- the normalizer every indexed column here declares,
 * and the only one `on_unindexable` governs in practice -- neither core's
 * message carries an offset at all, so `detail.offset` was always `null` and
 * the rendered message named the character without saying where it was.
 * `docs/12` §10.2 requires both. Measured before the fix, not inferred:
 * `{"codePoint":"U+0378","offset":null}`.
 */

import { firstUnassigned, InvalidArgumentError, UNICODE_VERSION } from "@fieldseal/core";

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

/**
 * Turn the core's refusal into one an application can render.
 *
 * Anything that is not an unindexable-value refusal is returned untouched: a
 * `KEY_UNAVAILABLE` must not be re-dressed as a data-quality problem.
 *
 * **The operand is a parameter because the character and its position come
 * from the core's exported check, not from its error message** (G22, #88).
 * What this function used to do was regex the message for `U+XXXX` and
 * `at index N` -- and the second one never matched on the path that matters.
 * Measured 2026-08-31: under `nfc-casefold-v1`, the only normalizer
 * `on_unindexable` governs in practice, *neither* core's message carries an
 * offset at all (the offset appears only on the `identity`/bytes path, which
 * this column never takes). So the shipped refusal named the character and
 * silently dropped the position, and `docs/12` §10.2 requires both --
 * "somewhere in this field" is not something a person can act on. Exporting
 * the check was the fix; parsing prose could not have been.
 */
export function unindexableError(
  e: unknown,
  label: string,
  noun: string,
  operand: string | Uint8Array,
): unknown {
  if (!(e instanceof InvalidArgumentError)) return e;

  const text = asText(operand);
  const stray = text === null ? undefined : firstUnassigned(text);
  // No offending code point means the refusal was for some other reason --
  // undecodable bytes, an operand the normalizer rejects as a whole. Better
  // discrimination than the old regex, which inferred "unindexable value" from
  // the presence of a `U+` in the text of a message.
  if (stray === undefined) return e;

  const cp = `U+${stray.codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
  const offset = stray.offset;
  const where = ` at position ${String(offset + 1)}`;
  return new FieldsealUnindexable(
    `${label}: this ${noun} contains a character (${cp})${where} that ` +
      `this system cannot index yet, so it cannot be saved on a searchable ` +
      `column. This is a limitation of the system, not a problem with the ` +
      `value: the index is pinned to a published Unicode version, and a ` +
      `character added after that pin has no agreed handling, so two servers ` +
      `would fingerprint it differently and the row would silently stop being ` +
      `findable. The value itself is storable -- an operator can enable ` +
      `\`on_unindexable: "bucket"\` for this column, which keeps the real value ` +
      `and keeps the row findable, at the documented cost in docs/12 §10.4. ` +
      `The index is pinned to Unicode ${UNICODE_VERSION}. Original: ${e.message}`,
    { codePoint: cp, offset, noun },
  );
}

/**
 * The operand as text, or `null` when it is not text at all.
 *
 * A non-string column (`as: "bytes"`, and every numeric rendering) hands the
 * index derivation raw bytes. Decoded strictly: bytes that are not UTF-8 have
 * no characters to count, so "the Nth character" would be an invented number
 * and the caller gets the core's own error instead.
 */
function asText(operand: string | Uint8Array): string | null {
  if (typeof operand === "string") return operand;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(operand);
  } catch {
    return null;
  }
}
