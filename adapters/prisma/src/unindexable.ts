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
 *
 * **Why this probes the declared normalizer instead of calling
 * `firstUnassigned` (review round, #101).** The exported accessor answers one
 * question -- "which code point is unassigned in the pinned version" -- and
 * that is `nfc-casefold-v1`'s refusal rule, not every column's. `identity`
 * refuses only unpaired surrogates and indexes unassigned code points
 * perfectly well, and a declaration may name any `NORMALIZER_IDS` member on an
 * indexed column. A normalizer-blind accessor therefore misdiagnosed an
 * `identity` column: reproduced on `"\u0378a\uD800"`, the wrap named U+0378
 * at position 1 -- a character that column indexes fine, at the wrong place --
 * while the real fault was the surrogate two positions along, and the remedy
 * it offered ("a later Unicode version may add it") was false twice over.
 * Django's `locate_unindexable` had already written this asymmetry down as its
 * reason for probing; this module said the same thing in a docstring and then
 * did the other thing.
 *
 * So: offer each code point to the column's *own* normalizer until one is
 * refused. The core stays the oracle -- no second copy of the assignment
 * table, which is the rule that matters, because a copy that drifts is a
 * silent lookup miss (`docs/09` §7.1). The accessor keeps its purpose, which
 * is a caller holding the text *before* a write that wants to know whether an
 * `nfc-casefold-v1` column will take it.
 */

import { InvalidArgumentError, type NormalizerId, normalize, UNICODE_VERSION } from "@fieldseal/core";

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
  normalizer: NormalizerId,
): unknown {
  if (!(e instanceof InvalidArgumentError)) return e;

  const text = asText(operand);
  const stray = text === null ? null : locate(normalizer, text);
  // Nothing this normalizer refuses means the refusal had some other cause --
  // undecodable bytes, or an operand rejected as a whole rather than for one
  // character. The core's own error goes back untouched rather than being
  // re-dressed as a data-quality problem the caller cannot act on.
  if (stray === null) return e;

  const cp = `U+${stray.codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
  const offset = stray.offset;
  const where = ` at position ${String(offset + 1)}`;
  // A lone surrogate is not "a character we have not added support for yet":
  // no Unicode version will ever assign one, it has no UTF-8 encoding at all,
  // and the `bucket` escape does not make it storable-and-findable the way it
  // does for a genuinely new character. Saying otherwise offers a remedy that
  // does not exist.
  if (stray.codePoint >= 0xd800 && stray.codePoint <= 0xdfff) {
    return new FieldsealUnindexable(
      `${label}: this ${noun} contains an unpaired surrogate (${cp})${where}, ` +
        `which is not a character -- it is half of one, and it has no UTF-8 ` +
        `encoding at all. It most often means the value was cut in the middle ` +
        `of a character somewhere upstream. Re-enter the ${noun}, or fix the ` +
        `truncation that split it. Original: ${e.message}`,
      { codePoint: cp, offset, noun },
    );
  }
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
    return UTF8_STRICT.decode(operand);
  } catch {
    return null;
  }
}

/** Constructed once. `unindexableError` runs only on an error path, but a
 * decoder with fixed options is pure and there is no reason to rebuild it
 * (review round, #101). */
const UTF8_STRICT = new TextDecoder("utf-8", { fatal: true });

/**
 * The first code point **this normalizer** refuses, and where it is.
 *
 * The core is the oracle: each code point is offered to `normalize` until one
 * is refused, so this adapter carries no copy of any rule. Refusal is a
 * per-code-point property for every normalizer in the registry -- unassigned
 * under `nfc-casefold-v1`, an unpaired surrogate under `identity` and
 * `digits-only-v1` -- so probing one character at a time gives the same answer
 * as probing the whole string.
 *
 * `null` is a real outcome and not an error path: a normalizer may refuse a
 * *string* for a reason no single character carries, and the caller then hands
 * back the core's own message rather than inventing a position.
 *
 * The offset counts **code points**, matching the cores' exported accessor and
 * `docs/12` §10.2's "the Nth character".
 */
function locate(
  normalizer: NormalizerId,
  text: string,
): { codePoint: number; offset: number } | null {
  let offset = 0;
  for (const ch of text) {
    try {
      normalize(normalizer, ch);
    } catch (e) {
      if (e instanceof InvalidArgumentError) {
        return { codePoint: ch.codePointAt(0)!, offset };
      }
      throw e;
    }
    offset++;
  }
  return null;
}
