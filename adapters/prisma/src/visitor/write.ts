/**
 * The write pass (pipeline step 4) -- encrypt declared columns, derive index
 * siblings.
 *
 * Schema-driven, not path-driven. `docs/04` §3 calls the existing library's
 * JSON-path approach "the correctness cliff": it rewrites a fixed list of
 * paths, and a write shape not on that list goes to the database untouched. So
 * this walks the args tree *guided by the relation graph* -- nested
 * `create` / `createMany` / `update` / `upsert` / `connectOrCreate.create`
 * under a relation key are reached because the schema says the relation is
 * there, not because a path pattern happened to match.
 *
 * Every value written to a declared column is encrypted with a fresh nonce and
 * a fresh `msg_seed` (spec §4.4), on every write including an UPDATE. Nothing
 * here caches, derives from row identity, or reuses.
 */

import type { Fieldseal } from "@fieldseal/core";

import { toBytes, toColumn } from "../codec.ts";
import { buildContext, type ContextOptions, indexContext } from "../context.ts";
import { FieldsealNotSupported } from "../errors.ts";
import type { Journal } from "../journal.ts";
import {
  type EncryptedFieldDecl,
  type IndexFieldDecl,
  relationTarget,
  type ResolvedMap,
  type ResolvedModel,
} from "../fieldmap.ts";
import { unindexableError } from "../unindexable.ts";

export interface WriteCtx {
  readonly client: Fieldseal;
  readonly map: ResolvedMap;
  readonly operation: string;
  readonly rootArgs: unknown;
  readonly context: ContextOptions;
  /** Every mutation below is recorded before it is applied -- `journal.ts`. */
  readonly journal: Journal;
}

/** Keys under which an operation's write payload can appear. */
const DATA_KEYS = ["data", "create", "update"] as const;

export function applyWrites(model: ResolvedModel, args: unknown, ctx: WriteCtx): void {
  if (!isRecord(args)) return;
  for (const key of DATA_KEYS) {
    const node = args[key];
    if (node === undefined) continue;
    for (const row of asArray(node)) encryptRow(model, row, ctx);
  }
}

/**
 * Encrypt one write payload in place.
 *
 * In place, deliberately: Prisma hands the extension a mutable `args`, and
 * rebuilding the tree would mean reconstructing every shape faithfully --
 * including the ones this visitor does not understand. Mutating only the leaves
 * it recognises leaves everything else exactly as the caller wrote it.
 */
function encryptRow(model: ResolvedModel, row: unknown, ctx: WriteCtx): void {
  if (!isRecord(row)) return;

  // An index sibling the caller set by hand is refused: those bytes are
  // derived, and a hand-written value is either wrong or a way to plant a
  // chosen index value on someone else's row.
  for (const key of Object.keys(row)) {
    const idx = model.indexByField.get(key);
    if (idx !== undefined) {
      throw new FieldsealNotSupported(
        `${model.model}.${key} is a blind-index sibling and is derived, not ` +
          `written. Set ${model.model}.${idx.source} and the adapter derives it; ` +
          `writing it directly would store an index value that does not ` +
          `correspond to the ciphertext beside it, and every later lookup for ` +
          `that row would miss.`,
      );
    }
  }

  for (const enc of model.encrypted) {
    if (!(enc.field in row)) continue;
    const label = `${model.model}.${enc.field}`;
    const written = unwrapSet(row[enc.field], label);

    // Prisma's contract for `undefined` is "do not touch this field" -- so the
    // sibling is not touched either. Writing NULL to it here would desync the
    // index from a ciphertext that stays behind, and every later lookup for
    // the row would miss.
    if (written === undefined) continue;

    if (written === null) {
      // NULL is an absence, not a value: it stays NULL, and the sibling with
      // it, so `where: { field: null }` keeps working as plain SQL.
      const idx = model.indexBySource.get(enc.field);
      if (idx !== undefined) ctx.journal.set(row, idx.field, null);
      continue;
    }

    const fieldCtx = buildContext(model, enc, ctx.rootArgs, ctx.operation, ctx.context);
    const plaintext = toBytes(written, enc, label);
    ctx.journal.set(row, enc.field, toColumn(ctx.client.encrypt(plaintext, fieldCtx), enc));

    const idx = model.indexBySource.get(enc.field);
    if (idx !== undefined) {
      ctx.journal.set(
        row,
        idx.field,
        deriveIndex(ctx.client, idx, enc, written, fieldCtx, label, ctx.context),
      );
    }
  }

  // Nested relation writes, reached through the schema rather than by path.
  // A relation target the map does not carry is refused, not skipped: only a
  // stale or edited map can miss (the generator emits every model), and
  // skipping would write plaintext through the edge with nothing raised.
  for (const [key, value] of Object.entries(row)) {
    const rel = model.relationByField.get(key);
    if (rel === undefined || !isRecord(value)) continue;
    const target = relationTarget(ctx.map, model, rel);
    for (const [nestedOp, payload] of Object.entries(value)) {
      // Link and delete shapes write no ciphertext. Their payloads are unique
      // inputs or filters over existing rows -- `set` replaces links by unique
      // input, `deleteMany`'s payload IS a where -- and the reject pass has
      // already walked every one of them for encrypted columns.
      if (
        nestedOp === "connect" ||
        nestedOp === "disconnect" ||
        nestedOp === "delete" ||
        nestedOp === "deleteMany" ||
        nestedOp === "set"
      ) {
        continue;
      }
      if (nestedOp === "connectOrCreate") {
        for (const item of asArray(payload)) {
          if (isRecord(item)) encryptRow(target, item["create"], ctx);
        }
        continue;
      }
      if (nestedOp === "upsert") {
        for (const item of asArray(payload)) {
          if (!isRecord(item)) continue;
          encryptRow(target, item["create"], ctx);
          encryptRow(target, item["update"], ctx);
        }
        continue;
      }
      if (nestedOp === "update" || nestedOp === "updateMany") {
        for (const item of asArray(payload)) {
          if (!isRecord(item)) continue;
          // Both `{ where, data }` and the bare-payload form.
          encryptRow(target, item["data"] ?? item, ctx);
        }
        continue;
      }
      if (nestedOp === "create" || nestedOp === "createMany") {
        for (const item of asArray(payload)) {
          if (isRecord(item) && Array.isArray(item["data"])) {
            for (const r of item["data"]) encryptRow(target, r, ctx);
          } else {
            encryptRow(target, item, ctx);
          }
        }
        continue;
      }
      throw new FieldsealNotSupported(
        `${model.model}.${key}.${nestedOp}: this adapter does not recognise that ` +
          `nested write and will not pass it through unexamined onto a model ` +
          `with encrypted columns (${rel.model}). An unhandled write shape is ` +
          `how plaintext reaches a column: it needs a visitor case and a test.`,
      );
    }
  }
}

function deriveIndex(
  client: Fieldseal,
  idx: IndexFieldDecl,
  encDecl: EncryptedFieldDecl,
  written: unknown,
  fieldCtx: ReturnType<typeof buildContext>,
  label: string,
  opts: ContextOptions,
): Uint8Array {
  // §7.1/G16 part A: pass the *string*, never its encoding. TextEncoder
  // substitutes U+FFFD for an unpaired surrogate, so a caller who encodes
  // first has already collapsed two distinct values into one before the core
  // is entered -- the exact false match the refusal exists to prevent.
  const operand = typeof written === "string" ? written : toBytes(written, encDecl, label);
  try {
    return client.blindIndex(operand, indexContext(fieldCtx, idx.indexId, opts));
  } catch (e) {
    throw unindexableError(e, label, encDecl.noun, operand);
  }
}

/**
 * `update` accepts `{ set: value }` as well as a bare value.
 *
 * Only a *plain* object can be the `{ set }` / atomic-operation wrapper.
 * Anything with a prototype of its own -- a `Date` for `as: "datetime"`, a
 * caller's value class -- is a value, and if it is the wrong value the codec
 * refuses it with the type it actually saw, which is the honest error.
 */
function unwrapSet(value: unknown, label: string): unknown {
  if (!isPlainRecord(value)) return value;
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === "set") return value["set"];
  if (keys.length === 0) return value; // let the codec name the mismatch
  // `increment`, `multiply`, `push`, ... all ask the database to compute a new
  // value from the stored one, which is an envelope.
  throw new FieldsealNotSupported(
    `${label}: \`${keys.join(", ")}\` asks the database to compute the new value ` +
      `from the stored one, which is a randomized envelope -- the result would ` +
      `be written to the column without ever passing through encryption (spec ` +
      `§10.2). Read the row, compute in application code, and write the value ` +
      `back with \`set\`.`,
  );
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array);
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [v];
}
