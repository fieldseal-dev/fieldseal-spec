/**
 * The RE-VERIFY pass (pipeline step 8) -- spec §7.5, the half that makes the
 * index rewrite correct.
 *
 * A blind index MUST be treated as a **filter, never as an answer.** Spec §7.4
 * sizes the truncation so that `2 <= P*2^-b < sqrt(P)`: every index value is
 * expected to correspond to at least two distinct plaintexts *by construction*,
 * because that ambiguity is the privacy mechanism. So the rows the database
 * returned for a rewritten predicate are a superset of the answer, and the ones
 * that do not actually hold the value are dropped here, after decryption.
 *
 * **The comparison is the index's own equality, not byte equality** (G19,
 * [#78], resolved 2026-08-26): `normalize(stored)` against `normalize(queried)`
 * under the normalizer the index declares, compared on the normalizer's output
 * bytes. On an `nfc-casefold-v1` column a query for `ada@example.com` therefore
 * returns a row stored as `Ada@Example.com` -- the index already merged them,
 * and un-merging them here would leave the caseless lookup the normalizer
 * exists to enable unreachable from the client. Where the normalizer *refuses*
 * a value (`on_unindexable: "bucket"`), §7.5 requires that side to fall back to
 * raw plaintext bytes: refused values share one reserved index value, so there
 * this comparison is what separates them rather than merely trimming
 * collisions.
 *
 * **Why the projection check lives here and not in the argument walk.** §7.5
 * needs the candidate's decrypted value, and three different things take it
 * away: `select` without the column, query-level `omit`, and client-level
 * `omit` passed to `new PrismaClient({ omit: … })`. Measured against Prisma
 * 7.10.0 on 2026-08-27 (`docs/13` §2.0), the third is **invisible
 * in `args`** -- the operation arrives as a bare `{ where }` and the row simply
 * comes back without the key. An argument-side check cannot see it. A check on
 * the returned row sees all three and fails closed on the one that cannot be
 * predicted.
 */

import { FieldsealNotSupported } from "../errors.ts";
import { bytesOf, hex, normalizeOrNull, type Obligation, operandOf } from "./rewrite.ts";

/**
 * Drop every candidate row that does not hold one of the queried values.
 *
 * Returns the result to hand back to the caller: a new array at the top level,
 * with nested relation arrays filtered in place.
 */
export function verifyResult(result: unknown, obligations: readonly Obligation[]): unknown {
  const top = obligations.filter((o) => o.resultPath.length === 0);
  const nested = obligations.filter((o) => o.resultPath.length > 0);

  let rows = result;
  if (top.length > 0) {
    if (!Array.isArray(rows)) {
      // Unreachable by construction: only `findMany` is given a verifiable
      // top-level `where` (every other operation's is answered by the database
      // and refused). Asserted rather than assumed, because the failure of a
      // silently skipped verification is unverified rows presented as answers.
      throw new FieldsealNotSupported(
        `fieldseal: a spec §7.5 obligation was recorded for the rows of this ` +
          `operation, but it did not return a row set. The adapter refuses ` +
          `rather than returning the value unchecked; this is an adapter bug -- ` +
          `please report it with the operation and arguments.`,
      );
    }
    rows = rows.filter((row) => matchesAll(row, top));
  }
  for (const o of nested) pruneNested(rows, o, 0);
  return rows;
}

/** Walk `resultPath` and filter the relation array it names. */
function pruneNested(node: unknown, o: Obligation, depth: number): void {
  if (Array.isArray(node)) {
    for (const row of node) pruneNested(row, o, depth);
    return;
  }
  if (!isRecord(node)) return;
  const key = o.resultPath[depth]!;
  const child = node[key];
  if (child === null || child === undefined) return;
  if (depth < o.resultPath.length - 1) {
    pruneNested(child, o, depth + 1);
    return;
  }
  if (!Array.isArray(child)) {
    // A nested obligation is only recorded for a to-many relation, whose
    // rows come back as an array. Anything else means the result shape is not
    // what the field map describes.
    throw new FieldsealNotSupported(
      `fieldseal: ${o.model}.${o.field} was filtered through its blind index ` +
        `under \`${o.resultPath.join(".")}\`, but that key did not come back as ` +
        `a list of rows, so spec §7.5 re-verification has nothing to check. The ` +
        `adapter refuses rather than returning the rows unchecked.`,
    );
  }
  node[key] = child.filter((row) => matchesOne(row, o));
}

function matchesAll(row: unknown, obligations: readonly Obligation[]): boolean {
  for (const o of obligations) {
    if (!matchesOne(row, o)) return false;
  }
  return true;
}

function matchesOne(row: unknown, o: Obligation): boolean {
  if (!isRecord(row)) return false;
  if (!(o.field in row)) {
    throw new FieldsealNotSupported(
      `${o.model}.${o.field}: this query filtered on the column's blind index, ` +
        `and spec §7.5 requires the candidate rows to be decrypted and compared ` +
        `before they are treated as results -- but the column is not in the ` +
        `returned rows, so there is nothing to compare. Something projected it ` +
        `away: a \`select\` that does not name it, a query-level \`omit\`, or a ` +
        `client-level \`omit: { ${lower(o.model)}: { ${o.field}: true } }\` on ` +
        `\`new PrismaClient(...)\` -- the last of which the extension cannot see ` +
        `in the arguments at all, which is why this is refused here rather than ` +
        `earlier. Include the column in the projection (\`select: { …, ` +
        `${o.field}: true }\`), or filter on something else and compare after ` +
        `decryption.`,
    );
  }
  const value = row[o.field];
  // NULL never equals an indexed target. A NULL row cannot reach a verified
  // result set through the rewrite at all -- the sibling is NULL exactly when
  // the source is (§10.2's NULL-preservation invariant), and `IS NULL` records
  // no obligation in the first place.
  if (value === null || value === undefined) return false;

  const operand = operandOf(value, o.enc, `${o.model}.${o.field}`);
  const normalized = normalizeOrNull(o.normalizer, operand);
  return normalized === null
    ? o.raw.has(hex(bytesOf(operand)))
    : o.normalized.has(hex(normalized));
}

/** Only used to render a `PrismaClient` option key, which is lower-camel. */
function lower(model: string): string {
  return model.charAt(0).toLowerCase() + model.slice(1);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array);
}
