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
import { FieldsealConfigurationError } from "../errors.ts";
import { relationTarget, type ResolvedMap, type ResolvedModel } from "../fieldmap.ts";

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

    let envelope = fromColumn(stored, enc);
    if (envelope === null) {
      // The stored value's JS type contradicts the declaration (raw bytes on a
      // base64 column, or the reverse). Passing it through would hand the
      // caller the stored representation as if it were the value -- in every
      // read mode, including strict. Misconfiguration is refused, not served.
      throw new FieldsealConfigurationError(
        `${model.model}.${enc.field}: the stored value is ` +
          `${stored instanceof Uint8Array ? "raw bytes" : `a ${typeof stored}`} but ` +
          `the declaration says storage: "${enc.storage}". Either the schema's ` +
          `storage: annotation changed after rows were written, or the column ` +
          `holds data this adapter did not write. Fix the declaration, or ` +
          `migrate the column; the mismatch is refused rather than returned.`,
      );
    }

    // A base64 column holding a legacy *plaintext* row -- the migration case
    // base64 storage exists for -- must reach the core as the stored string's
    // own bytes. Decoding it as base64 first would mangle the value before the
    // core's read-mode policy (spec §10.3) ever sees it: strict must raise
    // NOT_CIPHERTEXT and permissive must return the actual value, and both
    // judgements are the core's to make, not this visitor's.
    if (enc.storage === "base64" && !ctx.client.isCiphertext(envelope)) {
      // fromColumn already proved `stored` is a string on a base64 column.
      envelope = Buffer.from(stored as string, "utf8");
    }

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

  // A relation target the map does not carry is refused, not skipped: only a
  // stale or edited map can miss, and skipping would hand the caller raw
  // envelope bytes for that model's columns as if they were values.
  for (const rel of model.relations) {
    const nested = result[rel.field];
    if (nested === null || nested === undefined) continue;
    applyReads(relationTarget(ctx.map, model, rel), nested, ctx);
  }

  return result;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array);
}
