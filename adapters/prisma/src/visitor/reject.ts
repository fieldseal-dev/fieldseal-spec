/**
 * The analysis pass (pipeline step 3) -- the mandatory throw list (spec §10.2;
 * `docs/13` §4), and the plan for the L2 rewrite that step 5 applies.
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
 * Three refusal families live here, and they are not the same family:
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
 *  3. **Answered before spec §7.5 can run** (L2). An equality *is* serveable --
 *     rewritten onto the sibling blind index -- but only where the rows it
 *     selects come back to the extension to be decrypted and compared. Where
 *     the database answers instead (a `count`, a `LIMIT`, a join, a `DELETE`),
 *     the answer is computed over the §7.4 collision bucket and no later step
 *     can correct it.
 *
 * Family 2 is lifted by nothing. Families 1 and 3 differ: family 3 is exactly
 * what `candidateScope()` hands over, because bucket semantics are a meaningful
 * thing for a caller to accept.
 *
 * ---
 *
 * **The classification this file exists to make.** Measured against Prisma
 * 7.10.0 on 2026-08-27 (`docs/13` §2.0), exactly **two** `where`
 * sites in Prisma's whole surface select rows that come back to the extension:
 *
 *   1. the top-level `where` of `findMany`, and
 *   2. a relation `where` under `include` / `select`, where the matched rows
 *      arrive nested inside their parents.
 *
 * Everywhere else -- `count`, `aggregate`, `groupBy`, `findFirst` (its `LIMIT
 * 1` is applied below the extension and cannot be widened: `take` on
 * `findFirst` must be 1 or -1), `updateMany`, `deleteMany`, `update`, `delete`,
 * `upsert`, the unique inputs, the filters nested writes carry, relation
 * filters (`some`/`every`/`none`/`is`/`isNot`), and `_count` -- the database
 * computes the answer and only the answer comes back. Spec §10.2 states the
 * consequence directly: an adapter that cannot guarantee the rewrite, *"or a
 * filter path its interception surface does not reach"*, MUST reject.
 *
 * The walk below carries that classification as a `Site`, and every decision --
 * rewrite, refuse, or record an obligation for `verify.ts` -- reads it. One
 * walk, so the refusal and the rewrite can never disagree about what a site is.
 *
 * **Fail closed.** A leaf this cannot classify against the schema is a hard
 * error, not a passthrough (`docs/13` §2.1). The alternative is the correctness
 * cliff: a shape nobody thought about reaching the database unexamined.
 */

import { FieldsealNotSupported } from "../errors.ts";
import {
  type EncryptedFieldDecl,
  relationTarget,
  type ResolvedMap,
  type ResolvedModel,
} from "../fieldmap.ts";
import type { RewriteIntent } from "./rewrite.ts";

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

/**
 * Aggregate keys Prisma accepts at the top level of an operation.
 *
 * `_count` is deliberately not here: `_count: { field: true }` counts non-NULL
 * rows and reads no envelope bytes, and it is *exact* over an encrypted column
 * because the write pass guarantees NULL stays NULL and a value stays not-NULL.
 * It is the one member of the family with nothing to refuse.
 */
const AGGREGATES = ["_min", "_max", "_sum", "_avg"] as const;

/** Keys under which an operation's write payload can appear (mirrors write.ts). */
const DATA_KEYS = ["data", "create", "update"] as const;

/**
 * Operations whose result this adapter does not treat as verifiable rows.
 *
 * Mostly because the result is a computed answer rather than entity rows. The
 * `*AndReturn` pair do return rows, and are here deliberately: Prisma restricts
 * relation `include` on them, so a nested obligation is unreachable there, and
 * being wrong in this direction only costs a refusal -- being wrong the other
 * way would record an obligation against rows that never arrive.
 */
const NO_ROWS = new Set([
  "count",
  "aggregate",
  "groupBy",
  "updateMany",
  "deleteMany",
  "createMany",
  "updateManyAndReturn",
  "createManyAndReturn",
]);

/** Why this level's `where` cannot carry a §7.5 obligation. */
interface Answered {
  readonly why: string;
  readonly fallback: string;
}

/**
 * What the rows selected at one level of the argument tree do next.
 *
 * `path === null` means they never reach the extension at all. `answered ===
 * null` means this level's own `where` selects rows that do, so an equality
 * here can be rewritten and re-verified.
 */
interface Site {
  readonly path: readonly string[] | null;
  /** The argument node at this level, for the `take`/`skip`/`distinct` checks. */
  readonly args: Record<string, unknown> | null;
  readonly answered: Answered | null;
  /** Non-null once inside an `OR` / `NOT`: a returned row is unattributable. */
  readonly combinator: string | null;
}

export interface AnalyzeOptions {
  /**
   * False inside `candidateScope()`: spec §7.5 becomes the caller's, so no
   * obligation is recorded and family-3 refusals are lifted. Families 1 and 2
   * are not.
   */
  readonly verify: boolean;
}

interface Ctx {
  readonly map: ResolvedMap;
  readonly operation: string;
  readonly opts: AnalyzeOptions;
  readonly intents: RewriteIntent[];
}

/**
 * Refuse every shape this adapter cannot serve, and plan the rewrites for the
 * ones it can. Returns the intents for `applyRewrites` (step 5); throws before
 * returning anything if the operation is not serveable.
 */
export function analyzeOperation(
  model: ResolvedModel,
  operation: string,
  args: unknown,
  map: ResolvedMap,
  opts: AnalyzeOptions,
): RewriteIntent[] {
  const ctx: Ctx = { map, operation, opts, intents: [] };
  if (!isRecord(args)) return ctx.intents;

  if (operation === "findUnique" || operation === "findUniqueOrThrow") {
    refuseUniqueBy(model, args["where"]);
  }

  const site: Site = {
    // `findMany` is the only operation whose own `where` selects rows that come
    // back as a row set. Everything else is answered below the extension.
    answered: operation === "findMany" ? null : topLevelAnswered(operation),
    path: NO_ROWS.has(operation) ? null : [],
    args,
    combinator: null,
  };
  analyzeNode(model, args, ctx, site);

  // Nested relation writes carry filters over *existing* rows -- the `where`
  // of a nested update/updateMany/upsert/deleteMany/connectOrCreate, and the
  // unique inputs of connect/disconnect/delete/set. The write pass encrypts
  // their payloads but must never touch their filters, so the filters are
  // walked here, exactly as the top-level `where` is -- and always as rows the
  // database acts on rather than returns.
  const writeSite: Site = { path: null, args: null, answered: NESTED_WRITE, combinator: null };
  for (const key of DATA_KEYS) {
    const node = args[key];
    if (node === undefined) continue;
    for (const row of asArray(node)) walkWriteWheres(model, row, ctx, `${model.model}.${key}`, writeSite);
  }
  return ctx.intents;
}

/**
 * One level of the argument tree: an operation's own args, or the node under a
 * relation key in `include` / `select`. The same keys appear at both.
 */
function analyzeNode(
  model: ResolvedModel,
  node: Record<string, unknown>,
  ctx: Ctx,
  site: Site,
): void {
  if (node["where"] !== undefined) walkWhere(model, node["where"], ctx, `${model.model}.where`, site);
  if (node["orderBy"] !== undefined) walkOrderBy(model, node["orderBy"], ctx);
  if (node["cursor"] !== undefined) refuseCursor(model, node["cursor"]);
  if (node["distinct"] !== undefined) refuseDistinct(model, node["distinct"]);
  if (node["by"] !== undefined) refuseGroupBy(model, node["by"]);
  if (node["having"] !== undefined) refuseHaving(model, node["having"]);
  for (const agg of AGGREGATES) {
    if (node[agg] !== undefined) refuseAggregate(model, agg, node[agg]);
  }
  if (isRecord(node["select"])) walkProjection(model, node["select"], ctx, site);
  if (isRecord(node["include"])) walkProjection(model, node["include"], ctx, site);
}

// ---------------------------------------------------------------- where ----

function walkWhere(
  model: ResolvedModel,
  node: unknown,
  ctx: Ctx,
  path: string,
  site: Site,
): void {
  if (!isRecord(node)) return;

  for (const [key, value] of Object.entries(node)) {
    if (key === "AND") {
      // A conjunction is safe: every returned row satisfies every term, so a
      // failed check on one term is a sound reason to drop the row.
      for (const branch of asArray(value)) walkWhere(model, branch, ctx, `${path}.AND`, site);
      continue;
    }
    if (key === "OR" || key === "NOT") {
      const poisoned: Site = { ...site, combinator: site.combinator ?? key };
      for (const branch of asArray(value)) walkWhere(model, branch, ctx, `${path}.${key}`, poisoned);
      continue;
    }

    const enc = model.encryptedByField.get(key);
    if (enc !== undefined) {
      scalarFilter(model, node, key, enc, value, ctx, path, site);
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
      if (isRecord(value)) {
        const target = relationTarget(ctx.map, model, rel);
        // Whatever the shape, a relation filter is resolved in the database as
        // a join or a subquery and only the *parent* rows come back.
        const sub: Site = {
          path: null,
          args: null,
          answered: relationFilterAnswered(model, key),
          combinator: site.combinator,
        };
        // A to-many filter wraps the target's where in some/every/none, and a
        // to-one filter in is/isNot -- but a to-one filter may also BE the
        // target's where directly (`patient: { email: … }`), with no wrapper.
        // Treating that form's operands as wheres walks right past them.
        const keys = Object.keys(value);
        if (keys.every((k) => RELATION_WRAPPERS.has(k))) {
          for (const [op, nested] of Object.entries(value)) {
            walkWhere(target, nested, ctx, `${path}.${key}.${op}`, sub);
          }
        } else {
          walkWhere(target, value, ctx, `${path}.${key}`, sub);
        }
      }
    }
  }
}

const RELATION_WRAPPERS = new Set(["some", "every", "none", "is", "isNot"]);

/**
 * One predicate on an encrypted column: rewritten, served as-is, or refused.
 *
 * The literal NULL forms are served untouched. `IS NULL` is exact over an
 * envelope column under spec §10.2's NULL-preservation invariant -- the write
 * pass stores an absence as NULL and a value as a non-NULL envelope, and the
 * sibling is NULL exactly when the source is -- so there is no collision class
 * and nothing for §7.5 to re-verify. Everything else needs the index.
 */
function scalarFilter(
  model: ResolvedModel,
  node: Record<string, unknown>,
  field: string,
  enc: EncryptedFieldDecl,
  value: unknown,
  ctx: Ctx,
  path: string,
  site: Site,
): void {
  const label = `${model.model}.${field}`;
  if (value === null) return; // IS NULL: exact, see above.

  if (!isRecord(value)) {
    record(model, node, field, enc, [{ op: "equals", values: [value] }], null, ctx, site, path);
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

  const ops: Array<{ op: "equals" | "in"; values: unknown[] }> = [];
  const residual: Record<string, unknown> = {};
  let hasResidual = false;

  for (const [op, operand] of Object.entries(value)) {
    if (op === "equals") {
      if (operand === null) {
        residual["equals"] = null; // IS NULL: exact, stays on the envelope column.
        hasResidual = true;
        continue;
      }
      ops.push({ op: "equals", values: [operand] });
      continue;
    }
    if (op === "not") {
      if (operand === null) {
        residual["not"] = null; // IS NOT NULL: equally exact.
        hasResidual = true;
        continue;
      }
      throw new FieldsealNotSupported(
        `${label}: \`not\` is not available on an encrypted column. The SQL ` +
          `excludes the whole index bucket, and spec §7.4 mandates that the ` +
          `bucket holds rows whose value differs -- so the query drops rows it ` +
          `should have kept, and they never reach the adapter for §7.5 ` +
          `re-verification to put back. A filter's false positives are ` +
          `recoverable; an exclusion's false negatives are not. Fetch the ` +
          `matches and exclude their ids instead. (This is the shape G21 ([#87]) ` +
          `was filed to settle; \`candidateScope()\` does not lift it, because ` +
          `spec §7.10 has no row for negated membership to serve it under.)`,
      );
    }
    if (op === "in") {
      // SQL `IN` never matches NULL, and neither does the rewritten predicate,
      // so a NULL target is dropped rather than tracked: no NULL row can arrive
      // to be matched against it.
      ops.push({ op: "in", values: asArray(operand).filter((v) => v !== null) });
      continue;
    }
    if (op === "notIn") {
      throw new FieldsealNotSupported(
        `${label}: \`notIn\` is not available on an encrypted column. Spec §7.10 ` +
          `supports membership (N index values OR'd) but has no row for negated ` +
          `membership, and spec §10.2's rewrite permission names \`in\` only. The ` +
          `reason is the same asymmetry that refuses \`not\`: the SQL excludes ` +
          `whole index buckets, and spec §7.4 mandates that a bucket holds rows ` +
          `whose value differs, so the query drops rows it should have kept and ` +
          `§7.5 never sees them. Fetch the matches and exclude their ids. (G21, ` +
          `[#87]; \`candidateScope()\` does not lift it.)`,
      );
    }
    if (op === "isSet") {
      residual["isSet"] = operand; // Mongo-only; this adapter has no Mongo support.
      hasResidual = true;
      continue;
    }

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

  if (ops.length === 0) return; // Only the exact NULL forms; nothing to rewrite.
  record(model, node, field, enc, ops, hasResidual ? residual : null, ctx, site, path);
}

/**
 * Record one rewrite, having established that the site can carry it.
 *
 * The order of the checks is deliberate: the site refusal comes before the
 * missing-index refusal, because declaring a blind index is a schema migration
 * and a caller sent to do one for a `count()` that will be refused anyway has
 * migrated for nothing.
 */
function record(
  model: ResolvedModel,
  node: Record<string, unknown>,
  field: string,
  enc: EncryptedFieldDecl,
  ops: Array<{ op: "equals" | "in"; values: unknown[] }>,
  residual: Record<string, unknown> | null,
  ctx: Ctx,
  site: Site,
  path: string,
): void {
  const label = `${model.model}.${field}`;
  const verify = ctx.opts.verify;

  if (verify && site.answered !== null) {
    throw new FieldsealNotSupported(
      `${label}: ${site.answered.why} Spec §7.4 mandates that the index bucket ` +
        `holds rows whose value differs, so the answer would be computed over ` +
        `rows that do not match, and spec §7.5 requires candidates to be ` +
        `decrypted and compared before they count as results. Spec §10.2 ` +
        `requires rejecting a filter path the interception surface does not ` +
        `reach rather than serving it approximately. ${site.answered.fallback} ` +
        `If bucket semantics are what you want, say so explicitly with ` +
        `candidateScope(() => …) and take on §7.5 yourself. (At ${path}.)`,
    );
  }
  if (verify && site.combinator !== null) {
    throw new FieldsealNotSupported(
      `${label}: an encrypted column under \`${site.combinator}\` is not ` +
        `available. A returned row may be there because the *other* branch ` +
        `matched, so spec §7.5 re-verification cannot decide it without ` +
        `evaluating the whole predicate in application code -- and dropping the ` +
        `row on a failed check would remove a legitimate result. Put the ` +
        `encrypted term in the operation's own \`where\` (or under \`AND\`), ` +
        `where every returned row must satisfy it, or run the branches as ` +
        `separate queries and merge. \`candidateScope()\` lifts this, at bucket ` +
        `semantics. (At ${path}.)`,
    );
  }

  const idx = model.indexBySource.get(field);
  if (idx === undefined) {
    throw new FieldsealNotSupported(
      `${label}: equality on an encrypted column needs a declared blind index. ` +
        `The suite is randomized -- every write of the same value produces a ` +
        `different envelope (spec §4.4) -- so comparing against the ciphertext ` +
        `matches nothing and would return an empty result, which is a wrong ` +
        `answer rather than an error. Declare a sibling index column, or fetch ` +
        `the rows and filter after decryption.`,
    );
  }

  const resultPath = verify && site.answered === null ? site.path : null;
  if (resultPath !== null) checkRowHazards(site, label);

  ctx.intents.push({ node, model, enc, idx, ops, residual, resultPath });
}

/**
 * The shapes the database applies to the candidate set *before* §7.5 shrinks
 * it. Each is checked against the arguments at the obligation's own level: a
 * `take` on the parent of a nested obligation is fine, because dropping child
 * rows cannot change which parents matched.
 */
function checkRowHazards(site: Site, label: string): void {
  const args = site.args;
  if (args === null) return;
  const at = site.path !== null && site.path.length > 0 ? ` (under \`${site.path.join(".")}\`)` : "";

  for (const key of ["take", "skip"]) {
    if (args[key] === undefined) continue;
    throw new FieldsealNotSupported(
      `${label}: \`${key}\`${at} is not available together with a filter on an ` +
        `encrypted column. It compiles to LIMIT/OFFSET, which the database ` +
        `applies to the §7.4 index bucket before spec §7.5 re-verification drops ` +
        `the rows that do not match -- so the page comes back short and the next ` +
        `page starts in the wrong place. Spec §7.5 states outright that ` +
        `pagination built directly on an indexed encrypted column is incorrect, ` +
        `and gives the pattern: over-fetch, decrypt, filter, then paginate. ` +
        `Fetch the verified rows and slice them, or use candidateScope() and ` +
        `paginate the bucket yourself.`,
    );
  }
  if (args["cursor"] !== undefined) {
    throw new FieldsealNotSupported(
      `${label}: \`cursor\`${at} is not available together with a filter on an ` +
        `encrypted column. The cursor positions the database inside the §7.4 ` +
        `candidate set, which spec §7.5 re-verification then shrinks, so pages ` +
        `come back short and the caller cannot tell how far it actually got. ` +
        `Paginate over verified rows in application code, or use ` +
        `candidateScope() for bucket semantics.`,
    );
  }
  if (args["distinct"] !== undefined) {
    throw new FieldsealNotSupported(
      `${label}: \`distinct\`${at} is not available together with a filter on an ` +
        `encrypted column. Measured against Prisma 7.10.0: the dedup runs in the ` +
        `database, over the §7.4 candidate rows -- so the row it keeps may be one ` +
        `spec §7.5 then drops, while the row it discarded would have matched, and ` +
        `dropping the kept one cannot bring the discarded one back. Fetch the ` +
        `verified rows and deduplicate in application code.`,
    );
  }
}

// ------------------------------------------------- who answers this where ----

function topLevelAnswered(operation: string): Answered {
  switch (operation) {
    case "findFirst":
    case "findFirstOrThrow":
      return {
        why:
          `\`${operation}\` applies its LIMIT 1 below the extension -- it is not ` +
          `in the arguments, and it cannot be widened (measured against Prisma ` +
          `7.10.0: \`take\` on findFirst must be 1 or -1), and an extension ` +
          `cannot turn one operation into another.`,
        fallback:
          `So the database returns one candidate: a §7.4 collision comes back as ` +
          `the wrong row, and a true match sorted behind it comes back as null. ` +
          `Use findMany with the same where (plus orderBy) and take the first ` +
          `verified row.`,
      };
    case "count":
      return {
        why: `\`count\` is answered by the database as a COUNT over the index bucket.`,
        fallback:
          `The extension cannot turn a count into a row fetch, so it cannot ` +
          `verify what it counted. Use \`(await prisma.<model>.findMany({ where ` +
          `})).length\`, which counts verified rows.`,
      };
    case "aggregate":
    case "groupBy":
      return {
        why: `\`${operation}\` is answered by the database over the index bucket.`,
        fallback: `Fetch the verified rows with findMany and aggregate in application code.`,
      };
    case "updateMany":
    case "deleteMany":
    case "update":
    case "delete":
    case "upsert":
      return {
        why:
          `\`${operation}\` acts on the rows the database selects, and none of ` +
          `them come back for spec §7.5 to check.`,
        fallback:
          `The statement would ${operation.startsWith("delete") ? "delete" : "write to"} ` +
          `rows that do not hold the value. Fetch the verified rows with findMany ` +
          `first and act on their primary keys.`,
      };
    default:
      return {
        why: `\`${operation}\` does not return the rows this filter selects.`,
        fallback: `Fetch them with findMany, where spec §7.5 re-verification can run.`,
      };
  }
}

function relationFilterAnswered(model: ResolvedModel, field: string): Answered {
  return {
    why:
      `this filter reaches the encrypted column through the relation ` +
      `\`${model.model}.${field}\`, so it is resolved in the database as a join ` +
      `or subquery and only the parent rows come back.`,
    fallback:
      `Spec §7.5 re-verification needs the encrypted column's decrypted value, ` +
      `which lives on the related model. Query that model directly and join on ` +
      `the result -- \`const owners = await prisma.<owner>.findMany({ where: { ` +
      `<col>: v }, select: { id: true, <col>: true } })\` (the column must stay ` +
      `in the projection, or there is nothing to verify against), then filter ` +
      `by \`{ in: owners.map(o => o.id) }\`.`,
  };
}

const NESTED_WRITE: Answered = {
  why:
    `this filter selects the existing rows a nested write acts on, and the ` +
    `database applies it -- the rows are not returned for checking.`,
  fallback:
    `Fetch the rows with findMany first, where spec §7.5 re-verification runs, ` +
    `and address the nested write by primary key.`,
};

const TO_ONE_INCLUDE: Answered = {
  why:
    `a to-one relation in \`include\`/\`select\` is not filtered -- the related ` +
    `row comes back regardless -- so this \`where\` selects nothing the adapter ` +
    `can verify.`,
  fallback: `Filter the owning model directly and join on the result.`,
};

const RELATION_COUNT: Answered = {
  why: `\`_count\` is computed by the database over the §7.4 index bucket.`,
  fallback:
    `Include the relation with the same filter and count the verified rows in ` +
    `application code.`,
};

// ---------------------------------------------------- nested write filters ----

/** Walk one write payload for the filters nested relation writes carry. */
function walkWriteWheres(
  model: ResolvedModel,
  row: unknown,
  ctx: Ctx,
  path: string,
  site: Site,
): void {
  if (!isRecord(row)) return;
  for (const [key, value] of Object.entries(row)) {
    const rel = model.relationByField.get(key);
    if (rel === undefined || !isRecord(value)) continue;
    const target = relationTarget(ctx.map, model, rel);
    for (const [nestedOp, payload] of Object.entries(value)) {
      const p = `${path}.${key}.${nestedOp}`;
      // Unique inputs: shorthand equalities over the target's columns.
      if (
        nestedOp === "connect" ||
        nestedOp === "disconnect" ||
        nestedOp === "delete" ||
        nestedOp === "set"
      ) {
        for (const item of asArray(payload)) walkWhere(target, item, ctx, p, site);
        continue;
      }
      // The payload *is* the filter.
      if (nestedOp === "deleteMany") {
        for (const item of asArray(payload)) walkWhere(target, item, ctx, p, site);
        continue;
      }
      for (const item of asArray(payload)) {
        if (!isRecord(item)) continue;
        if (item["where"] !== undefined) walkWhere(target, item["where"], ctx, `${p}.where`, site);
        // Descend into the write payloads for deeper relation levels. The
        // shapes mirror write.ts: update/updateMany/upsert carry `data` /
        // `create` / `update`; connectOrCreate carries `create`; create /
        // createMany are either the payload itself or `{ data: [...] }`.
        for (const dataKey of DATA_KEYS) {
          const nested = item[dataKey];
          if (nested === undefined) continue;
          for (const r of asArray(nested)) walkWriteWheres(target, r, ctx, p, site);
        }
        if (item["where"] === undefined && item["data"] === undefined) {
          // Bare payload form (to-one update, nested create).
          walkWriteWheres(target, item, ctx, p, site);
        }
      }
    }
  }
}

// -------------------------------------------------- G20: computing on bytes ----

function walkOrderBy(model: ResolvedModel, node: unknown, ctx: Ctx): void {
  for (const entry of asArray(node)) {
    if (!isRecord(entry)) continue;
    for (const [key, value] of Object.entries(entry)) {
      if (model.encryptedByField.has(key)) refuseOrder(model, key);
      const rel = model.relationByField.get(key);
      if (rel !== undefined) walkOrderBy(relationTarget(ctx.map, model, rel), value, ctx);
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

/**
 * `select` / `include` can nest a whole operation's args under a relation.
 *
 * This is the second of the two verifiable `where` sites: a to-many relation's
 * matched rows arrive nested inside their parents, so an equality there can be
 * rewritten and re-verified in the returned tree. The path grows by the
 * relation key, and a to-one hop stays in the path -- `verify.ts` walks through
 * it -- even though a to-one's own `where` is not a filter.
 */
function walkProjection(
  model: ResolvedModel,
  node: Record<string, unknown>,
  ctx: Ctx,
  site: Site,
): void {
  for (const [key, value] of Object.entries(node)) {
    if (key === "_count") {
      // `_count: { select: { rel: { where: … } } }` -- a filter the database
      // turns into a number.
      if (isRecord(value) && isRecord(value["select"])) {
        const counted: Site = { path: null, args: null, answered: RELATION_COUNT, combinator: null };
        walkProjection(model, value["select"], ctx, counted);
      }
      continue;
    }
    const rel = model.relationByField.get(key);
    if (rel === undefined || !isRecord(value)) continue;
    const target = relationTarget(ctx.map, model, rel);
    const path = site.path === null ? null : [...site.path, key];
    const child: Site = {
      path,
      args: value,
      answered: path === null ? (site.answered ?? UNREACHABLE_ROWS) : rel.isList ? null : TO_ONE_INCLUDE,
      combinator: null,
    };
    analyzeNode(target, value, ctx, child);
  }
}

const UNREACHABLE_ROWS: Answered = {
  why: `the rows this filter selects are not returned by this operation.`,
  fallback: `Fetch them with findMany, where spec §7.5 re-verification can run.`,
};

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
        `fills. Use \`findMany\` with an equality filter, which is rewritten onto ` +
        `the declared index and re-verified under §7.5, and take the first row; ` +
        `or fetch by primary key. This refusal is structural, so ` +
        `candidateScope() does not lift it.`,
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
