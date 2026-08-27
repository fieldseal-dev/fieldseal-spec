/**
 * The read pass (pipeline step 7) -- decrypt declared columns in the result.
 *
 * On the *awaited result*, not through `result.compute`: a computed field
 * cannot be used in `where` or `orderBy` and cannot replace a stored value
 * (`docs/04` §3), so the `result` component cannot carry the read path.
 *
 * Because `select` / `include` cannot be mutated by an extension, there is no
 * hidden-column problem for values -- the ciphertext lives in the field's own
 * column, so a projection that asked for the field got it. But **index sibling
 * columns do appear in results**, and application code that starts depending on
 * index bytes is depending on something spec §7.8 forbids changing and §7.4
 * guarantees collides. They are stripped unless `exposeIndexColumns` is set.
 */

import type { Fieldseal } from "@fieldseal/core";

import { fromBytes, fromColumn } from "../codec.ts";
import { buildContext, type ContextOptions } from "../context.ts";
import type { ResolvedMap, ResolvedModel } from "../fieldmap.ts";

export interface ReadCtx {
  readonly client: Fieldseal;
  readonly map: ResolvedMap;
  readonly operation: string;
  readonly rootArgs: unknown;
  readonly context: ContextOptions;
  readonly exposeIndexColumns: boolean;
  /** Reported per plaintext read in non-strict modes (spec §10.3). */
  readonly onPlaintextRead?: ((model: string, field: string) => void) | undefined;
}

/** Decrypt in place, recursing through `include`d relations. */
export function applyReads(model: ResolvedModel, result: unknown, ctx: ReadCtx): unknown {
  if (Array.isArray(result)) {
    for (const row of result) applyReads(model, row, ctx);
    return result;
  }
  if (!isRecord(result)) return result;

  for (const enc of model.encrypted) {
    if (!(enc.field in result)) continue;
    const stored = result[enc.field];
    if (stored === null || stored === undefined) continue;

    const envelope = fromColumn(stored, enc);
    if (envelope === null) continue;

    // In `permissive`, the core returns a plaintext value unchanged rather than
    // raising; the hook reports model and field, never the value (spec §10.3).
    if (ctx.onPlaintextRead !== undefined && !ctx.client.isCiphertext(envelope)) {
      ctx.onPlaintextRead(model.model, enc.field);
    }

    const fieldCtx = buildContext(model, enc, ctx.rootArgs, ctx.operation, ctx.context);
    result[enc.field] = fromBytes(
      ctx.client.decrypt(envelope, fieldCtx),
      enc,
      `${model.model}.${enc.field}`,
    );
  }

  if (!ctx.exposeIndexColumns) {
    for (const idx of model.indexes) delete result[idx.field];
  }

  for (const rel of model.relations) {
    const nested = result[rel.field];
    if (nested === null || nested === undefined) continue;
    const target = ctx.map.byModel.get(rel.model);
    if (target !== undefined) applyReads(target, nested, ctx);
  }

  return result;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array);
}
