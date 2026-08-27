/**
 * The extension: one top-level `query.$allOperations` component.
 *
 * That component is the only one that can touch writes *and* filters
 * (`docs/04` §3). The `result` component is read-side only and adds virtual
 * fields, which cannot be used in `where` or `orderBy`; `$use` middleware is
 * deprecated. So everything happens here.
 *
 * Pipeline, per operation (`docs/13` §2):
 *
 *   1. model === undefined (raw ops) -> passthrough + warning, or throw
 *   2. no encrypted column on this model            -> passthrough
 *   3. ANALYSE  walk args: refuse forbidden shapes (§4), plan the rewrites
 *   4. WRITE    encrypt declared columns, derive index siblings
 *   5. WHERE    rewrite equality/`in` onto the sibling index, record the
 *               spec §7.5 obligations the rewrite incurs
 *   6. await query(args)      -- async: KMS acquisition can await here (L4)
 *   7. READ     decrypt declared columns in the result tree
 *   8. RE-VERIFY discharge the obligations: drop §7.4 collision rows
 *
 * Steps 5 and 8 land together, deliberately: a rewrite without re-verification
 * returns collision rows as matches, which is the wrong-answer failure this
 * adapter exists to refuse. Step 3 keeps refusing equality wherever step 8
 * cannot reach -- which, measured against Prisma 7.10.0, is everywhere except
 * the top-level `where` of `findMany` and a relation `where` under
 * `include`/`select`. Measured against Prisma 7.10.0, 2026-08-27; the
 * classification is `docs/13` §2.0.
 *
 * `candidateScope(fn)` is the documented opt-out: inside it nothing is
 * recorded, step 8 does not run, and the database answers over the §7.4 bucket.
 *
 * **Ordering.** Register fieldseal *last*. Measured against Prisma 7.10.0: the
 * extension registered first is outermost, so the one registered last sits
 * closest to the engine -- which is where this must be, so that every other
 * extension sees plaintext rather than envelopes. ("Last" reading like "runs
 * last" is exactly backwards, which is why it is written down.)
 */

import type { Fieldseal, ReadMode, Warning } from "@fieldseal/core";

import { inCandidateScope } from "./candidates.ts";
import { buildClient, type ClientOptions, type ScopedOverride } from "./client.ts";
import type { TenantResolver } from "./context.ts";
import { FieldsealConfigurationError, FieldsealNotSupported } from "./errors.ts";
import { FIELD_MAP_VERSION, type FieldMap, resolveMap } from "./fieldmap.ts";
import { analyzeOperation } from "./visitor/reject.ts";
import { applyReads } from "./visitor/read.ts";
import { applyRewrites } from "./visitor/rewrite.ts";
import { verifyResult } from "./visitor/verify.ts";
import { applyWrites, type WriteCtx } from "./visitor/write.ts";

export interface FieldsealExtensionOptions {
  /** The generated field map (see `generator/`). */
  readonly fieldMap: FieldMap;
  readonly keyProvider: ClientOptions["keyProvider"];
  readonly allowedSuites: readonly number[];
  readonly writeSuite: number;
  readonly readMode?: ReadMode | undefined;
  /** Spec §7.6: an explicit, logged, reviewed declaration, in code. */
  readonly cardinalityOverride?: readonly ScopedOverride[] | undefined;
  /** docs/09 §7.2: the same ceremony, for `on_unindexable: "bucket"`. */
  readonly unindexableOverride?: readonly ScopedOverride[] | undefined;
  readonly tenant?: TenantResolver | undefined;
  /**
   * Raw operations carry an opaque SQL template the extension cannot inspect
   * (`docs/04` §3). Default is passthrough plus a warning; strict deployments
   * opt into the throw.
   */
  readonly strictRaw?: boolean | undefined;
  readonly onRawOperation?: ((operation: string) => void) | undefined;
  readonly onPlaintextRead?: ((model: string, field: string) => void) | undefined;
  readonly onWarning?: ((w: Warning) => void) | undefined;
  /** Leave index sibling columns in returned objects. Off by default. */
  readonly exposeIndexColumns?: boolean | undefined;
  readonly armProvisionalSuites?: boolean | undefined;
}

/**
 * What `$extends` is handed. Structural, so no Prisma type import is needed.
 *
 * `$allOperations` sits at the **top level of `query`**, not under
 * `$allModels`. That is the difference between seeing raw operations and not:
 * `query.$allModels.$allOperations` wraps model operations only, and
 * `$queryRaw` / `$executeRaw` are client-level, so they never reach it.
 * `docs/13` §2's pipeline step 1 -- "model === undefined (raw ops)" -- is only
 * reachable from here. Measured against Prisma 7.10.0, 2026-08-27.
 */
export interface QueryExtension {
  readonly name: string;
  readonly query: {
    $allOperations(params: {
      model?: string | undefined;
      operation: string;
      args: unknown;
      query: (args: unknown) => Promise<unknown>;
    }): Promise<unknown>;
  };
}

export function fieldsealExtension(opts: FieldsealExtensionOptions): QueryExtension {
  const map = validateMap(opts.fieldMap);
  const client: Fieldseal = buildClient(map, opts);
  const contextOpts = { resolver: opts.tenant };
  const exposeIndexColumns = opts.exposeIndexColumns === true;

  return {
    name: "fieldseal",
    query: {
      async $allOperations({ model, operation, args, query }) {
          // 1. Raw operations: `model` is undefined and the SQL is opaque.
          if (model === undefined) {
            if (opts.strictRaw === true) {
              throw new FieldsealNotSupported(
                `fieldseal: \`${operation}\` is a raw operation and strictRaw is ` +
                  `set. Raw SQL parameters are never encrypted by any ORM ` +
                  `surveyed (spec §10.2, "All ORMs"), and the extension cannot ` +
                  `inspect the template to tell whether it touches an encrypted ` +
                  `column. Use the model API, or unset strictRaw and accept that ` +
                  `raw parameters and results are unprotected.`,
              );
            }
            opts.onRawOperation?.(operation);
            return query(args);
          }

          // 2. Every schema model is in the map, declared or not -- the
          //    undeclared ones as relation-only entries, because a write can
          //    reach an encrypted column *through* them and the walks below
          //    must be able to follow. A model the map does not carry is
          //    therefore a stale or edited map, and passing it through would
          //    reopen exactly that bypass.
          const resolved = map.byModel.get(model);
          if (resolved === undefined) {
            throw new FieldsealConfigurationError(
              `fieldseal: the model "${model}" is not in the field map, which ` +
                `was generated by ${map.source.generator}. The map is emitted ` +
                `from the same schema as the client, so a model the client can ` +
                `name but the map cannot means the map is stale or was edited. ` +
                `Re-run \`prisma generate\`. It is refused rather than passed ` +
                `through because an unmapped model is a route around the ` +
                `pipeline for every encrypted model it relates to.`,
            );
          }

          // 3. Refuse before doing any work: a shape that will not be served
          //    should not first have its operands encrypted or fingerprinted.
          //    The same walk plans the rewrites, so a refusal and a rewrite can
          //    never disagree about what a `where` site is.
          const intents = analyzeOperation(resolved, operation, args, map, {
            verify: !inCandidateScope(),
          });

          // 4. Encrypt and derive.
          const writeCtx: WriteCtx = {
            client,
            map,
            operation,
            rootArgs: args,
            context: contextOpts,
          };
          applyWrites(resolved, args, writeCtx);

          // 5. Rewrite equality/`in` onto the sibling index, and take on the
          //    §7.5 debt each rewrite creates.
          const obligations = applyRewrites(intents, {
            client,
            operation,
            rootArgs: args,
            context: contextOpts,
          });

          // 6. The await the sync core cannot do (L4 lands with warm(), PR3).
          const result = await query(args);

          // 7. Decrypt.
          const decrypted = applyReads(resolved, result, {
            client,
            map,
            operation,
            rootArgs: args,
            context: contextOpts,
            exposeIndexColumns,
            onPlaintextRead: opts.onPlaintextRead,
          });

          // 8. Discharge the obligations: a blind index is a filter, never an
          //    answer (spec §7.5). Nothing is recorded inside candidateScope().
          return obligations.length === 0
            ? decrypted
            : verifyResult(decrypted, obligations);
      },
    },
  };
}

function validateMap(fieldMap: FieldMap): ReturnType<typeof resolveMap> {
  if (fieldMap === undefined || fieldMap === null) {
    throw new FieldsealConfigurationError(
      `fieldseal: \`fieldMap\` is required. It is emitted by the fieldseal ` +
        `Prisma generator at \`prisma generate\`; add a generator block to your ` +
        `schema and import the file it writes. Prisma 7 does not expose \`///\` ` +
        `annotations at runtime, so there is nothing to fall back to.`,
    );
  }
  if (fieldMap.version !== FIELD_MAP_VERSION) {
    throw new FieldsealConfigurationError(
      `fieldseal: the field map is version ${String(fieldMap.version)} and this ` +
        `release reads version ${String(FIELD_MAP_VERSION)}. Re-run \`prisma ` +
        `generate\`. A map is refused rather than read optimistically because a ` +
        `half-understood map means a column quietly treated as plaintext.`,
    );
  }
  return resolveMap(fieldMap);
}
