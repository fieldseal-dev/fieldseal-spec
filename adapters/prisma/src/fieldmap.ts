/**
 * The field map: the artifact the generator emits and the extension consumes.
 *
 * `docs/13` §1 called for a "frozen per-model field map" built by parsing `///`
 * annotations "read from the DMMF at runtime". The runtime half of that is not
 * available in Prisma 7: `Prisma.dmmf` no longer exists, and the client's
 * private `_runtimeDataModel` carries the model and relation graph but **no**
 * `documentation` -- the annotations are simply not in it. They survive only in
 * the schema source text (measured against 7.10.0, 2026-08-27).
 *
 * So the map is built where the annotations *are* available and the route is
 * supported: at `prisma generate`, from `options.dmmf`, which Prisma's own
 * parser populates with documentation on every model and field. The generator
 * emits this structure; the extension imports it.
 *
 * Two consequences, both improvements on the original design:
 *
 *  - A malformed declaration fails `prisma generate`, not the first request.
 *    That is the Prisma analogue of Django's startup system checks, and it is
 *    what `docs/13` §1 meant by "never a runtime skip".
 *  - The declarations and the relation graph arrive together, from one source.
 *    §2.1's visitor needs both, and at runtime they live in different places.
 *
 * The map is data, not behaviour: it carries no key material, no client, and
 * nothing derived. It is safe to commit and to read.
 */

import type { Argon2Params, IdfId, NormalizerId, OnUnindexable } from "@fieldseal/core";

/** How the envelope is rendered into the column (spec §3.3). */
export type Storage = "binary" | "base64";

/**
 * The *logical* type of the value, declared with `as:`.
 *
 * This has no counterpart in `docs/13` §1 and it has to exist. In Prisma the
 * schema type is the **storage** type -- the column is `Bytes` because it holds
 * an envelope -- so it cannot also say what the value is. Django never needed
 * this: `Encrypted(models.EmailField())` composes an inner field that carries
 * the logical type, and Prisma has no equivalent.
 *
 * `docs/14` §3 already names this as the adapter decision no core test can see:
 * "an IntegerField is not self-evidently `b\"42\"`". The rendering chosen here
 * is what a consumer in another language must decode, which is why the
 * cross-language producer exercises every one of these.
 */
export type ValueType = "string" | "bytes" | "int" | "float" | "boolean" | "datetime";

export const VALUE_TYPES: readonly ValueType[] = [
  "string",
  "bytes",
  "int",
  "float",
  "boolean",
  "datetime",
];

/** An encrypted value column. */
export interface EncryptedFieldDecl {
  readonly field: string;
  /** Surrogate, immutable, written literally in the schema (spec §6.1). */
  readonly columnUuid: string;
  readonly storage: Storage;
  /** What the value *is*, as opposed to how the envelope is stored. */
  readonly valueType: ValueType;
  /** Whether the tenant must be resolvable before this column may be written. */
  readonly tenantBound: boolean;
  /** The Prisma scalar type, so the codec knows what it is rendering. */
  readonly prismaType: string;
  /** What to call the value in a user-facing refusal (`docs/12` §10.2). */
  readonly noun: string;
}

/** A blind-index sibling column. */
export interface IndexFieldDecl {
  /** The sibling column itself, e.g. `emailBidx`. */
  readonly field: string;
  /** The encrypted field it indexes, e.g. `email`. */
  readonly source: string;
  readonly indexId: string;
  readonly idf: IdfId;
  readonly normalize: NormalizerId;
  readonly truncateBits: number;
  readonly projectedPopulation: number;
  readonly argon2?: Argon2Params;
  readonly onUnindexable: OnUnindexable;
  readonly skewed: boolean;
  readonly prismaType: string;
}

/** A relation edge, so the args-tree visitor can walk nested writes by schema. */
export interface RelationDecl {
  readonly field: string;
  readonly model: string;
  readonly isList: boolean;
}

export interface ModelMap {
  readonly model: string;
  /**
   * `null` on a model with no declarations of its own. Every model is in the
   * map, declared or not, because the relation graph must be walkable from
   * anywhere: a write can reach an encrypted column through a model that
   * declares nothing (`appointment.create({ data: { patient: { create: … } } })`),
   * and a map that omits the undeclared model makes that write a silent
   * plaintext bypass.
   */
  readonly tableUuid: string | null;
  readonly encrypted: readonly EncryptedFieldDecl[];
  readonly indexes: readonly IndexFieldDecl[];
  readonly relations: readonly RelationDecl[];
}

/**
 * The emitted artifact.
 *
 * `version` is checked at extension construction: a map emitted by a different
 * generator version than the runtime expects is refused rather than read
 * optimistically, because the failure of a half-understood map is a column
 * quietly treated as plaintext.
 */
export interface FieldMap {
  readonly version: 2;
  readonly generator: string;
  readonly models: readonly ModelMap[];
}

// Version 2: every model in the schema is in the map (undeclared ones as
// relation-only entries with `tableUuid: null`), and the extension refuses an
// operation on a model the map does not carry. A version-1 map omitted
// undeclared models, which made any of them a silent bypass around the
// pipeline for the declared models they relate to.
export const FIELD_MAP_VERSION = 2 as const;

/** Indexed view of the map, built once at extension construction. */
export interface ResolvedMap {
  readonly byModel: ReadonlyMap<string, ResolvedModel>;
  readonly source: FieldMap;
}

export interface ResolvedModel extends ModelMap {
  readonly encryptedByField: ReadonlyMap<string, EncryptedFieldDecl>;
  /** Keyed by the *source* field, which is how a `where` clause names it. */
  readonly indexBySource: ReadonlyMap<string, IndexFieldDecl>;
  /** Keyed by the sibling column, so a filter naming it directly is catchable. */
  readonly indexByField: ReadonlyMap<string, IndexFieldDecl>;
  readonly relationByField: ReadonlyMap<string, RelationDecl>;
}

export function resolveMap(map: FieldMap): ResolvedMap {
  const byModel = new Map<string, ResolvedModel>();
  for (const m of map.models) {
    byModel.set(m.model, {
      ...m,
      encryptedByField: new Map(m.encrypted.map((e) => [e.field, e])),
      indexBySource: new Map(m.indexes.map((i) => [i.source, i])),
      indexByField: new Map(m.indexes.map((i) => [i.field, i])),
      relationByField: new Map(m.relations.map((r) => [r.field, r])),
    });
  }
  return { byModel, source: map };
}
