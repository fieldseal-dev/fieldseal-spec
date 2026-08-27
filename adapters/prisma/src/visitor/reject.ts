/**
 * The mandatory throw list (spec §10.2; `docs/13` §4) -- pipeline step 3.
 *
 * `docs/04` §3 records the failure this exists to prevent, measured against
 * `prisma-field-encryption`: an un-rewritten filter shape gets *the operand
 * encrypted instead*, and the query returns zero rows, silently, with no
 * error. `orderBy` on an encrypted field is deleted with a `console.error`.
 * Spec §10.2 requires an adapter to throw on all of it.
 *
 * The rule, from `docs/13` §4: **nothing on this list may silently degrade,
 * and nothing may be downgraded to a warning.**
 *
 * Two refusal families live here, and they are not the same family:
 *
 *  1. **Not serveable over ciphertext.** Substring, order, membership without
 *     an index, case-insensitivity. These are properties of the value that a
 *     randomized envelope does not preserve.
 *
 *  2. **SQL computing on envelope bytes** (G20, [#80]). `orderBy`, `distinct`,
 *     `groupBy.by`, `having`, and aggregate expressions over an encrypted
 *     column. These *do* return an answer, which is what makes them dangerous:
 *     `MIN()` over a ciphertext column returns whichever envelope sorts first,
 *     and it decrypts cleanly and is presented as the minimum. Measured on the
 *     Django adapter before the refusals were written: `Min("age")` over
 *     {30, 40} returned **40**. Every other failure in the family is loud or
 *     visibly absurd; that one is silent and plausible.
 *
 * The second family is not lifted by any escape hatch. Bucket semantics are a
 * meaningful thing for a caller to accept; ciphertext order has no semantics to
 * accept.
 *
 * **Fail closed.** A leaf this cannot classify against the schema is a hard
 * error, not a passthrough (`docs/13` §2.1). The alternative is the correctness
 * cliff: a shape nobody thought about reaching the database unexamined.
 */

import { FieldsealNotSupported } from "../errors.ts";
import type { ResolvedMap, ResolvedModel } from "../fieldmap.ts";

/** Scalar filter operators, and why each is refused over an envelope. */
const REFUSED_OPERATORS: Readonly<Record<string, string>> = {
  contains: "no substring matching over ciphertext (spec §7.1)",
  startsWith:
    "no prefix matching over ciphertext (spec §7.1). A §7.9 prefix index is " +
    "queried through its own declared predicate; spec §10.2 forbids rewriting " +
    "startsWith onto one, because the rewrite is sound only when the operand " +
    "length happens to equal the declared prefix length",
  endsWith: "no suffix matching over ciphertext (spec §7.1)",
  search: "no full-text search over ciphertext (spec §7.10)",
  lt: "no ordering over ciphertext (spec §4.7)",
  lte: "no ordering over ciphertext (spec §4.7)",
  gt: "no ordering over ciphertext (spec §4.7)",
  gte: "no ordering over ciphertext (spec §4.7)",
  mode: "case folding belongs to the normalizer, not the query (spec §7.5)",
};

/** Aggregate keys Prisma accepts at the top level of an operation. */
const AGGREGATES = ["_min", "_max", "_sum", "_avg", "_count"] as const;

export interface RejectOptions {
  /** Whether equality has a rewrite available yet (L2, PR2). */
  readonly equalityRewritable: boolean;
}

interface Ctx {
  readonly map: ResolvedMap;
  readonly operation: string;
  readonly opts: RejectOptions;
}

export function rejectForbiddenShapes(
  model: ResolvedModel,
  operation: string,
  args: unknown,
  map: ResolvedMap,
  opts: RejectOptions,
): void {
  if (!isRecord(args)) return;
  const ctx: Ctx = { map, operation, opts };

  if (operation === "findUnique" || operation === "findUniqueOrThrow") {
    refuseUniqueBy(model, args["where"]);
  }

  if (args["where"] !== undefined) walkWhere(model, args["where"], ctx, `${model.model}.where`);
  if (args["orderBy"] !== undefined) walkOrderBy(model, args["orderBy"], ctx);
  if (args["cursor"] !== undefined) refuseCursor(model, args["cursor"]);
  if (args["distinct"] !== undefined) refuseDistinct(model, args["distinct"]);
  if (args["by"] !== undefined) refuseGroupBy(model, args["by"]);
  if (args["having"] !== undefined) refuseHaving(model, args["having"]);
  for (const agg of AGGREGATES) {
    if (args[agg] !== undefined) refuseAggregate(model, agg, args[agg]);
  }
  if (isRecord(args["select"])) walkProjection(model, args["select"], ctx);
  if (isRecord(args["include"])) walkProjection(model, args["include"], ctx);
}

// ---------------------------------------------------------------- where ----

function walkWhere(model: ResolvedModel, node: unknown, ctx: Ctx, path: string): void {
  if (!isRecord(node)) return;

  for (const [key, value] of Object.entries(node)) {
    if (key === "AND" || key === "OR" || key === "NOT") {
      // OR and NOT over an encrypted column are refused in PR2 alongside the
      // rewrite that makes AND serveable; until equality is rewritable at all,
      // any encrypted column under any of them is already refused below.
      for (const branch of asArray(value)) walkWhere(model, branch, ctx, `${path}.${key}`);
      continue;
    }

    const enc = model.encryptedByField.get(key);
    if (enc !== undefined) {
      refuseScalarFilter(model, key, value, ctx, path);
      continue;
    }

    const idx = model.indexByField.get(key);
    if (idx !== undefined) {
      throw new FieldsealNotSupported(
        `${model.model}.${key} is a blind-index sibling column and cannot be ` +
          `filtered on directly. Spec §7.4 mandates collisions in a truncated ` +
          `index, so the rows it selects are a superset of the answer, and spec ` +
          `§7.5 requires those candidates to be decrypted and re-verified before ` +
          `they reach you -- which the adapter cannot do for a filter it did not ` +
          `construct. Filter on ${model.model}.${idx.source} instead.`,
      );
    }

    const rel = model.relationByField.get(key);
    if (rel !== undefined) {
      const target = ctx.map.byModel.get(rel.model);
      if (target !== undefined && isRecord(value)) {
        for (const [op, sub] of Object.entries(value)) {
          // some / every / none / is / isNot all nest a where on the target.
          walkWhere(target, sub, ctx, `${path}.${key}.${op}`);
        }
      }
    }
  }
}

function refuseScalarFilter(
  model: ResolvedModel,
  field: string,
  value: unknown,
  ctx: Ctx,
  path: string,
): void {
  const label = `${model.model}.${field}`;

  // Shorthand equality: `where: { email: "..." }`.
  if (!isRecord(value)) {
    refuseEquality(model, field, ctx, `${path}.${field}`);
    return;
  }

  // Refused operators are checked across the whole object first, before the
  // rewritable ones. `{ equals: "x", mode: "insensitive" }` is one filter, and
  // reporting it as a plain equality would name the wrong reason -- `mode` is
  // what makes it unserveable, and G19's one-equality rule is why.
  for (const op of Object.keys(value)) {
    const reason = REFUSED_OPERATORS[op];
    if (reason !== undefined) {
      throw new FieldsealNotSupported(
        `${label}: \`${op}\` is not available on an encrypted column -- ${reason}. ` +
          `The column holds a randomized envelope, so this filter would compile ` +
          `to valid SQL and return a confidently wrong answer; spec §10.2 ` +
          `requires the adapter to raise instead. Spec §7.10 lists the honest ` +
          `fallback for each shape.`,
      );
    }
  }

  for (const op of Object.keys(value)) {
    if (op === "equals") {
      refuseEquality(model, field, ctx, `${path}.${field}.equals`);
      continue;
    }
    if (op === "in" || op === "notIn") {
      refuseMembership(model, field, op, ctx);
      continue;
    }
    if (op === "not") {
      throw new FieldsealNotSupported(
        `${label}: \`not\` is not available on an encrypted column. The SQL ` +
          `excludes the whole index bucket, and spec §7.4 mandates that the ` +
          `bucket holds rows whose value differs -- so the query drops rows it ` +
          `should have kept, and they never reach the adapter for §7.5 ` +
          `re-verification to put back. A filter's false positives are ` +
          `recoverable; an exclusion's false negatives are not. Fetch the ` +
          `matches and exclude their ids instead.`,
      );
    }
    if (op === "isSet") continue; // Mongo-only; this adapter has no Mongo support.

    // Fail closed: an operator the visitor does not know is not passed through.
    throw new FieldsealNotSupported(
      `${label}: \`${op}\` is not a filter shape this adapter recognises, and it ` +
        `will not be passed through unexamined on an encrypted column. Every ` +
        `un-rewritten shape reaching the database encrypts the operand and ` +
        `returns zero rows silently (docs/04 §3) -- the failure this adapter ` +
        `exists to prevent. If this shape is legitimate, it needs a visitor case ` +
        `and a test.`,
    );
  }

}

function refuseEquality(model: ResolvedModel, field: string, ctx: Ctx, path: string): void {
  const idx = model.indexBySource.get(field);
  if (idx === undefined) {
    throw new FieldsealNotSupported(
      `${model.model}.${field}: equality on an encrypted column needs a declared ` +
        `blind index. The suite is randomized -- every write of the same value ` +
        `produces a different envelope (spec §4.4) -- so comparing against the ` +
        `ciphertext matches nothing and would return an empty result, which is a ` +
        `wrong answer rather than an error. Declare a sibling index column, or ` +
        `fetch the rows and filter after decryption.`,
    );
  }
  if (!ctx.opts.equalityRewritable) {
    throw new FieldsealNotSupported(
      `${model.model}.${field}: this build serves L1 (transparent encrypt and ` +
        `decrypt) only; the index rewrite that makes equality correct is L2 and ` +
        `is not in this release. A declared index is present, so this refusal is ` +
        `temporary -- but serving the filter without spec §7.5 re-verification ` +
        `would return collision rows as matches, so it refuses rather than ` +
        `approximates (at ${path}).`,
    );
  }
}

function refuseMembership(model: ResolvedModel, field: string, op: string, ctx: Ctx): void {
  const idx = model.indexBySource.get(field);
  if (op === "notIn") {
    throw new FieldsealNotSupported(
      `${model.model}.${field}: \`notIn\` is not available on an encrypted ` +
        `column. Spec §7.10 supports membership (N index values OR'd) but has no ` +
        `row for negated membership, and spec §10.2's rewrite permission names ` +
        `\`in\` only. The reason is the same asymmetry that refuses \`not\`: the ` +
        `SQL excludes whole index buckets, and spec §7.4 mandates that a bucket ` +
        `holds rows whose value differs, so the query drops rows it should have ` +
        `kept and §7.5 never sees them. Fetch the matches and exclude their ids.`,
    );
  }
  if (idx === undefined) {
    throw new FieldsealNotSupported(
      `${model.model}.${field}: \`in\` on an encrypted column needs a declared ` +
        `blind index -- without one there is nothing to rewrite onto, and the ` +
        `operands would be encrypted and match nothing (docs/04 §3). Declare a ` +
        `sibling index column, or fetch and filter after decryption.`,
    );
  }
  if (!ctx.opts.equalityRewritable) {
    throw new FieldsealNotSupported(
      `${model.model}.${field}: \`in\` rewriting onto the declared blind index is ` +
        `L2 and is not in this release, which serves L1 only.`,
    );
  }
}

// -------------------------------------------------- G20: computing on bytes ----

function walkOrderBy(model: ResolvedModel, node: unknown, ctx: Ctx): void {
  for (const entry of asArray(node)) {
    if (!isRecord(entry)) continue;
    for (const [key, value] of Object.entries(entry)) {
      if (model.encryptedByField.has(key)) refuseOrder(model, key);
      const rel = model.relationByField.get(key);
      if (rel !== undefined) {
        const target = ctx.map.byModel.get(rel.model);
        if (target !== undefined) walkOrderBy(target, value, ctx);
      }
    }
  }
}

function refuseOrder(model: ResolvedModel, field: string): never {
  const idx = model.indexBySource.get(field);
  throw new FieldsealNotSupported(
    `${model.model}.${field}: \`orderBy\` over an encrypted column sorts envelope ` +
      `bytes -- a stable-looking order with no relation to the values (spec ` +
      `§7.10, §10.2 "All ORMs"). ` +
      (idx === undefined
        ? `Materialize the rows, decrypt, and sort in application code.`
        : `Materialize, decrypt and sort in application code; ordering by the ` +
          `${model.model}.${idx.field} sibling is permitted but orders by index ` +
          `value, which is a documented-meaningless tiebreaker, not value order.`),
  );
}

function refuseCursor(model: ResolvedModel, cursor: unknown): void {
  if (!isRecord(cursor)) return;
  for (const key of Object.keys(cursor)) {
    if (model.encryptedByField.has(key) || model.indexByField.has(key)) {
      throw new FieldsealNotSupported(
        `${model.model}.${key}: \`cursor\` pagination over an encrypted column or ` +
          `its index sibling is incorrect. A cursor needs a stable total order, ` +
          `and ciphertext has none; on the sibling, §7.4 collisions mean the ` +
          `cursor value does not identify a row. Spec §7.5: the correct pattern ` +
          `is over-fetch, decrypt, filter, then paginate. Paginate on the ` +
          `primary key instead.`,
      );
    }
  }
}

function refuseDistinct(model: ResolvedModel, distinct: unknown): void {
  for (const f of asArray(distinct)) {
    if (typeof f !== "string") continue;
    if (model.encryptedByField.has(f)) {
      throw new FieldsealNotSupported(
        `${model.model}.${f}: \`distinct\` over an encrypted column deduplicates ` +
          `nothing. A randomized suite writes a different envelope for every row ` +
          `(spec §4.4), so every value is distinct by construction and the ` +
          `result is one group per row (spec §7.10, §10.2 "All ORMs"). ` +
          `Materialize, decrypt, and deduplicate in application code.`,
      );
    }
  }
}

function refuseGroupBy(model: ResolvedModel, by: unknown): void {
  for (const f of asArray(by)) {
    if (typeof f !== "string") continue;
    if (model.encryptedByField.has(f)) {
      throw new FieldsealNotSupported(
        `${model.model}.${f}: \`groupBy\` over an encrypted column returns one ` +
          `group per row under keys that decrypt identically -- wrong counts, ` +
          `presented without error (spec §7.10, §10.2 "All ORMs"). Grouping by ` +
          `the blind-index sibling is the documented alternative, with the ` +
          `caveat that it groups by index value including §7.4 collisions.`,
      );
    }
  }
}

function refuseHaving(model: ResolvedModel, having: unknown): void {
  if (!isRecord(having)) return;
  for (const [key, value] of Object.entries(having)) {
    if (key === "AND" || key === "OR" || key === "NOT") {
      for (const b of asArray(value)) refuseHaving(model, b);
      continue;
    }
    if (model.encryptedByField.has(key)) {
      throw new FieldsealNotSupported(
        `${model.model}.${key}: \`having\` over an encrypted column filters a ` +
          `grouping computed on envelope bytes, which is meaningless (spec ` +
          `§7.10). Materialize, decrypt, and aggregate in application code.`,
      );
    }
    if (AGGREGATES.includes(key as (typeof AGGREGATES)[number])) {
      refuseAggregate(model, key, value);
    }
  }
}

function refuseAggregate(model: ResolvedModel, agg: string, node: unknown): void {
  if (!isRecord(node)) return;
  for (const [field, on] of Object.entries(node)) {
    if (on === false || on === undefined) continue;
    if (!model.encryptedByField.has(field)) continue;
    throw new FieldsealNotSupported(
      `${model.model}.${field}: \`${agg}\` over an encrypted column computes on ` +
        `envelope bytes (spec §7.10, §10.2 "All ORMs"). This is the failure in ` +
        `the family that is both silent and plausible: the byte-wise minimum ` +
        `envelope decrypts cleanly and is presented as the minimum. Measured on ` +
        `a shipping adapter, MIN over {30, 40} returned 40. Materialize, ` +
        `decrypt, and aggregate in application code.`,
    );
  }
}

/** `select` / `include` can nest a whole operation's args under a relation. */
function walkProjection(model: ResolvedModel, node: Record<string, unknown>, ctx: Ctx): void {
  for (const [key, value] of Object.entries(node)) {
    if (key === "_count") {
      // `_count: { select: { rel: { where: ... } } }` -- a nested filter.
      if (isRecord(value) && isRecord(value["select"])) walkProjection(model, value["select"], ctx);
      continue;
    }
    const rel = model.relationByField.get(key);
    if (rel === undefined || !isRecord(value)) continue;
    const target = ctx.map.byModel.get(rel.model);
    if (target === undefined) continue;
    rejectForbiddenShapes(target, ctx.operation, value, ctx.map, ctx.opts);
  }
}

// --------------------------------------------------------------- unique ----

function refuseUniqueBy(model: ResolvedModel, where: unknown): void {
  if (!isRecord(where)) return;
  for (const key of Object.keys(where)) {
    const enc = model.encryptedByField.has(key);
    const idx = model.indexByField.has(key);
    if (!enc && !idx) continue;
    throw new FieldsealNotSupported(
      `${model.model}.${key}: \`findUnique\` requires a unique column, and neither ` +
        `an encrypted column nor a blind-index sibling can be one -- spec §7.10 ` +
        `states this normatively. A randomized envelope differs on every write, ` +
        `and §7.4 *mandates* collisions in a truncated index, so a UNIQUE ` +
        `constraint there would reject legitimate distinct values as the table ` +
        `fills. Use \`findFirst\` with an equality filter, which the adapter ` +
        `re-verifies under §7.5.`,
    );
  }
}

// ---------------------------------------------------------------- utils ----

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array);
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [v];
}

