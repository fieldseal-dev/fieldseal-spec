/**
 * Tenant binding and context assembly (spec §10, L3).
 *
 * The Prisma extension runs before the query engine acquires a connection and
 * sees only `(model, operation, args)` -- never the record. So the tenant
 * arrives out of band, exactly as it does in Django, and spec §10.1 marks
 * Prisma's L3 "⚠️ partial" for this reason. Two documented side channels:
 *
 *  - `tenantScope(id, fn)` -- an `AsyncLocalStorage`, set by request
 *    middleware. Survives `await` across the whole request, which a
 *    thread-local could not.
 *  - the `tenant` option -- a callback given `(args, model, operation)`, for
 *    deployments that carry the tenant in the arguments themselves.
 *
 * **Fail-closed.** A tenant-bound column with no resolvable tenant refuses the
 * write. Falling back to a tenantless context would store a row that no
 * correctly configured reader can decrypt -- and because spec §6.3 binds the
 * context into the derived key, the reader's error would be
 * `COMMITMENT_INVALID`: a decrypt-side failure reported for a write-side
 * configuration mistake, arbitrarily far from the cause.
 *
 * `rowId` is always `null`: L3-row is not in v0 (`docs/13` §8). The extension
 * runs before the query, so a database-generated id does not exist yet.
 */

import { AsyncLocalStorage } from "node:async_hooks";

import type { FieldContext } from "@fieldseal/core";

import { FieldsealConfigurationError } from "./errors.ts";
import type { EncryptedFieldDecl, ResolvedModel } from "./fieldmap.ts";

const storage = new AsyncLocalStorage<Uint8Array>();

/** Run `fn` with `tenant` bound for every fieldseal operation inside it. */
export function tenantScope<T>(tenant: Uint8Array | string, fn: () => T): T {
  return storage.run(toBytes(tenant), fn);
}

/** The tenant bound in this async context, or `null`. */
export function getTenant(): Uint8Array | null {
  return storage.getStore() ?? null;
}

function toBytes(v: Uint8Array | string): Uint8Array {
  return typeof v === "string" ? Buffer.from(v, "utf8") : v;
}

/** Resolves the tenant for one operation. */
export type TenantResolver = (
  args: unknown,
  model: string,
  operation: string,
) => Uint8Array | string | null | undefined;

export interface ContextOptions {
  readonly resolver?: TenantResolver | undefined;
  /**
   * Told about every `FieldContext` this module builds (L4, `warm.ts`).
   *
   * This module is the single place a context is constructed -- `buildContext`
   * makes the value context and `indexContext` derives the index one from it --
   * so recording here records all of them. That is what makes `warm()`-on-miss
   * able to name the keys an operation needs without a second walk of the
   * arguments: the passes themselves report what they asked for.
   */
  readonly record?: ((ctx: FieldContext) => void) | undefined;
}

/**
 * Assemble the `FieldContext` for one column.
 *
 * The purpose is `"encrypt"`. `FieldContext` is a plain interface in this core,
 * not a class, so there is no `forIndex` method to call: `indexContext()` below
 * derives the index context from this one by replacing the purpose, which keeps
 * the two from ever disagreeing about table, column or tenant.
 */
export function buildContext(
  model: ResolvedModel,
  field: EncryptedFieldDecl,
  args: unknown,
  operation: string,
  opts: ContextOptions,
): FieldContext {
  // Only models with declarations reach here, and the generator refuses a
  // declared model without a table_uuid; a null here is an edited or stale map.
  if (model.tableUuid === null) {
    throw new FieldsealConfigurationError(
      `fieldseal: ${model.model}.${field.field} is declared encrypted but the ` +
        `field map carries no table_uuid for ${model.model}. The generator ` +
        `emits both together, so the map is stale or was edited -- re-run ` +
        `\`prisma generate\`.`,
    );
  }
  const tenant = field.tenantBound
    ? requireTenant(model, field, args, operation, opts)
    : null;
  const ctx: FieldContext = {
    tableUuid: uuidBytes(model.tableUuid),
    columnUuid: uuidBytes(field.columnUuid),
    tenantId: tenant,
    rowId: null,
    purpose: "encrypt",
  };
  opts.record?.(ctx);
  return ctx;
}

function requireTenant(
  model: ResolvedModel,
  field: EncryptedFieldDecl,
  args: unknown,
  operation: string,
  opts: ContextOptions,
): Uint8Array {
  const fromCallback = opts.resolver?.(args, model.model, operation);
  const tenant =
    fromCallback === null || fromCallback === undefined ? getTenant() : toBytes(fromCallback);
  if (tenant === null) {
    throw new FieldsealConfigurationError(
      `${model.model}.${field.field} is declared tenant_bound and no tenant is ` +
        `resolvable for this ${operation}. Set one with \`tenantScope(id, fn)\` ` +
        `-- request middleware covers requests, but scripts, queue workers and ` +
        `REPL sessions run outside it and must set it themselves -- or supply a ` +
        `\`tenant\` callback to fieldsealExtension(). Encrypting without it ` +
        `would store a row that no correctly configured reader can decrypt, and ` +
        `spec §6.3 binds the context into the derived key, so the reader would ` +
        `see COMMITMENT_INVALID rather than anything naming this cause.`,
    );
  }
  return tenant;
}

/**
 * The index-key context for a column, derived from its value context.
 *
 * Spec §5.2 makes the index key a *sibling* of the tenant DEK rather than a
 * child of it, and spec §6.1's purpose grammar is what selects between them.
 * Deriving this from the value context rather than rebuilding it is deliberate:
 * a table, column or tenant that differed between the two would derive an
 * index value under one identity and a ciphertext under another, and nothing
 * would raise -- the lookup would simply stop finding the row.
 */
export function indexContext(
  ctx: FieldContext,
  indexId: string,
  opts: ContextOptions = {},
): FieldContext {
  const derived: FieldContext = { ...ctx, purpose: `index:${indexId}` };
  // Recorded separately from the value context it came from: spec §5.2 makes
  // the index key a *sibling* of the tenant DEK rather than a child, so a
  // provider that warmed only the value context would leave every indexed
  // lookup stalled -- the failure Django's warm tests name as "a slow query
  // rather than a cold cache".
  opts.record?.(derived);
  return derived;
}

/** 8-4-4-4-12 hex -> the 16 bytes spec §6.1 derives from. */
export function uuidBytes(uuid: string): Uint8Array {
  return Buffer.from(uuid.replace(/-/g, ""), "hex");
}
