/**
 * The WHERE pass (pipeline step 5) -- equality and membership onto the sibling
 * blind index.
 *
 * The predicate `where: { email: "ada@example.com" }` cannot reach the database
 * as written: the suite is randomized, so every write of that value produced a
 * different envelope (spec §4.4) and a comparison against ciphertext matches
 * nothing. `docs/04` §3 records what `prisma-field-encryption` does with it --
 * encrypts the operand and returns zero rows, silently -- which is the failure
 * this adapter exists to refuse.
 *
 * So the predicate is rewritten onto the declared sibling:
 *
 *     { email: "ada@example.com" }        ->  { emailBidx: <15 bits> }
 *     { email: { in: ["a", "b"] } }       ->  { emailBidx: { in: [<15>, <15>] } }
 *
 * Membership is exactly spec §7.10's supported shape ("N indexes OR'd"), and
 * §10.2's Prisma bullet permits the `in:` rewrite as of G13 provided the
 * candidates are re-verified.
 *
 * **The rewrite is only half of it.** Spec §7.4 *mandates* collisions -- the
 * truncation band is `2 <= P*2^-b < sqrt(P)`, so an index value is expected to
 * correspond to at least two distinct plaintexts by construction, and that
 * ambiguity is the privacy mechanism. What the database returns is therefore a
 * **superset** of the answer. Every rewrite here records an `Obligation`, and
 * `verify.ts` discharges it against the decrypted rows. A rewrite without its
 * obligation is a confidently wrong answer, which is why the two land in one
 * release and why equality was refused outright until they did.
 *
 * **What re-verification compares** is spec §7.5's rule (G19, [#78]):
 * `normalize(stored)` against `normalize(queried)` under the index's *own*
 * declared normalizer, on the normalizer's output bytes -- using the core's
 * public `normalize`, never a reimplementation. A column declaring
 * `nfc-casefold-v1` matches `Ada@Example.com` for a query of
 * `ada@example.com`, because the index already merged them and a verification
 * step that un-merged them would leave the caseless lookup the normalizer
 * exists to enable unreachable. Where the normalizer *refuses* a value
 * (`on_unindexable: "bucket"`), §7.5 requires the comparison to fall back to
 * raw plaintext bytes on that side -- two refused values share one index value,
 * so there the comparison is load-bearing rather than merely collision-trimming.
 */

import type { Fieldseal, NormalizerId } from "@fieldseal/core";
import { InvalidArgumentError, normalize } from "@fieldseal/core";

import { toBytes } from "../codec.ts";
import { buildContext, type ContextOptions, indexContext } from "../context.ts";
import type { EncryptedFieldDecl, IndexFieldDecl, ResolvedModel } from "../fieldmap.ts";
import { unindexableError } from "../unindexable.ts";

/** One rewritable predicate, as the analysis walk found it. */
export interface RewriteIntent {
  /** The `where` object holding the predicate; rewritten in place. */
  readonly node: Record<string, unknown>;
  readonly model: ResolvedModel;
  readonly enc: EncryptedFieldDecl;
  readonly idx: IndexFieldDecl;
  /** One entry per rewritable operator found on this field at this node. */
  readonly ops: ReadonlyArray<{ readonly op: "equals" | "in"; readonly values: readonly unknown[] }>;
  /**
   * The null-valued forms to leave on the envelope column (`{ not: null }`),
   * or `null` to remove the caller's key entirely. `IS NULL` is exact over an
   * envelope under §10.2's NULL-preservation invariant and is not rewritten.
   */
  readonly residual: Record<string, unknown> | null;
  /**
   * Where in the result the rows this predicate selects will land -- `[]` for
   * the operation's own rows, `["visits"]` for an `include`d relation. `null`
   * inside a `candidateScope`, where §7.5 is the caller's and nothing is
   * recorded.
   */
  readonly resultPath: readonly string[] | null;
}

/**
 * One rewritten *operator's* §7.5 debt, discharged by `verify.ts`.
 *
 * Per operator, not per field: a row must satisfy every obligation, so the
 * conjunction a caller wrote (`{ equals: A, in: [...] }`) stays a conjunction
 * through verification.
 */
export interface Obligation {
  readonly resultPath: readonly string[];
  readonly model: string;
  readonly field: string;
  readonly enc: EncryptedFieldDecl;
  readonly normalizer: NormalizerId;
  /** Hex of `normalize(target)` for every target the normalizer accepted. */
  readonly normalized: ReadonlySet<string>;
  /** Hex of the raw bytes of every target the normalizer *refused* (§7.5). */
  readonly raw: ReadonlySet<string>;
}

export interface RewriteCtx {
  readonly client: Fieldseal;
  readonly operation: string;
  readonly rootArgs: unknown;
  readonly context: ContextOptions;
}

/**
 * Derive the index values, rewrite the predicates in place, and return the
 * obligations they incur.
 *
 * Deliberately separate from the analysis walk that produced the intents: a
 * shape that will be refused should not first have its operands fingerprinted,
 * and the walk refuses eagerly, so reaching here means the whole operation is
 * serveable.
 */
export function applyRewrites(
  intents: readonly RewriteIntent[],
  ctx: RewriteCtx,
): Obligation[] {
  const obligations: Obligation[] = [];
  for (const intent of intents) {
    const label = `${intent.model.model}.${intent.enc.field}`;
    const fieldCtx = buildContext(
      intent.model,
      intent.enc,
      ctx.rootArgs,
      ctx.operation,
      ctx.context,
    );
    const idxCtx = indexContext(fieldCtx, intent.idx.indexId);

    const predicates: unknown[] = [];
    // One target set -- and so one obligation -- PER OPERATOR, never a union
    // across them. `{ equals: A, in: [B] }` is a conjunction, and `place()`
    // rewrites it as one; an obligation holding {A, B} would verify the
    // disjunction instead, so when §7.4 collides bidx(A) with bidx(B) -- the
    // event the truncation band mandates at scale -- a row holding only B
    // survives both the SQL and §7.5 and is returned as a verified match for a
    // filter whose true answer excludes it. `verify.ts` requires every
    // obligation to hold, which restores the conjunction.
    const perOp: Array<{ normalized: Set<string>; raw: Set<string> }> = [];

    for (const { op, values } of intent.ops) {
      const derived: Uint8Array[] = [];
      const normalized = new Set<string>();
      const raw = new Set<string>();
      for (const value of values) {
        const operand = operandOf(value, intent.enc, label);
        try {
          derived.push(ctx.client.blindIndex(operand, idxCtx));
        } catch (e) {
          // docs/13 §9: an unindexable operand under `refuse` propagates. It
          // MUST NOT become a query that returns zero rows -- that is the
          // silent miss this adapter exists to prevent, with a different cause.
          throw unindexableError(e, label, intent.enc.noun);
        }
        const n = normalizeOrNull(intent.idx.normalize, operand);
        if (n === null) raw.add(hex(bytesOf(operand)));
        else normalized.add(hex(n));
      }
      // `in: []` matches nothing in SQL and must keep doing so; the obligation
      // with empty target sets drops every row, which agrees.
      predicates.push(op === "in" ? { in: derived } : derived[0]);
      perOp.push({ normalized, raw });
    }

    if (intent.residual === null) delete intent.node[intent.enc.field];
    else intent.node[intent.enc.field] = intent.residual;
    place(intent.node, intent.idx.field, predicates);

    if (intent.resultPath !== null) {
      for (const { normalized, raw } of perOp) {
        obligations.push({
          resultPath: intent.resultPath,
          model: intent.model.model,
          field: intent.enc.field,
          enc: intent.enc,
          normalizer: intent.idx.normalize,
          normalized,
          raw,
        });
      }
    }
  }
  return obligations;
}

/**
 * Place the derived predicates on the sibling column.
 *
 * More than one only arises when a caller wrote two rewritable operators on one
 * field (`{ equals: "a", in: [...] }`), which Prisma reads as a conjunction.
 * Two values cannot sit under one key, so the extras go into the node's `AND`,
 * where they mean the same thing.
 */
function place(node: Record<string, unknown>, sibling: string, predicates: unknown[]): void {
  const [first, ...rest] = predicates;
  node[sibling] = first;
  for (const extra of rest) {
    const existing = node["AND"];
    const arr = existing === undefined ? [] : Array.isArray(existing) ? existing : [existing];
    arr.push({ [sibling]: extra });
    node["AND"] = arr;
  }
}

/**
 * The operand handed to `blindIndex` and to `normalize`.
 *
 * A string is passed **as a string** (spec §7.1 / G16 part A): `TextEncoder`
 * substitutes U+FFFD for an unpaired surrogate, so a caller who encodes first
 * has collapsed two distinct values into one before the core is entered. This
 * mirrors `write.ts` exactly, and it has to: the query side and the write side
 * must hand the core the same thing for the same value, or the lookup misses.
 */
export function operandOf(
  value: unknown,
  enc: EncryptedFieldDecl,
  label: string,
): string | Uint8Array {
  return typeof value === "string" ? value : toBytes(value, enc, label);
}

/** `null` when the normalizer refuses -- §7.5's raw-bytes fallback side. */
export function normalizeOrNull(
  normalizer: NormalizerId,
  operand: string | Uint8Array,
): Uint8Array | null {
  try {
    return normalize(normalizer, operand);
  } catch (e) {
    if (e instanceof InvalidArgumentError) return null;
    throw e;
  }
}

export function bytesOf(operand: string | Uint8Array): Uint8Array {
  return typeof operand === "string" ? Buffer.from(operand, "utf8") : operand;
}

export function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
