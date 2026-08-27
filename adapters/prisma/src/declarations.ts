/**
 * Annotations -> field map, with structural validation.
 *
 * "Structural" is the whole boundary here. This module checks the things that
 * are true of a *declaration* -- a UUID is 16 bytes, an index names a column
 * that exists and is encrypted, a `Bytes` column is not declared `base64` --
 * and refuses to check the things that are true of an *index*: the §7.4
 * truncation band, the §7.6 cardinality gate, the Argon2 minima, the §7.2
 * bucket ceremony.
 *
 * Those belong to the core and run at client construction
 * (`validateIndexDeclaration`). The Django adapter learned this the expensive
 * way: `docs/07` §7 records that the Python core had drifted to enforcing
 * *none* of its declaration-time gates while `docs/10` §4 specified all of
 * them, and it went unnoticed because the adapter looked like it was checking.
 * A second copy of a gate is a copy that can disagree with the one that
 * matters, and the disagreement is silent.
 */

import { NORMALIZER_IDS, type IdfId, type NormalizerId, type OnUnindexable } from "@fieldseal/core";

import { type Annotation, type Site, siteLabel } from "./annotations.ts";
import { FieldsealConfigurationError } from "./errors.ts";
import type {
  EncryptedFieldDecl,
  IndexFieldDecl,
  ModelMap,
  RelationDecl,
  Storage,
  ValueType,
} from "./fieldmap.ts";
import { VALUE_TYPES } from "./fieldmap.ts";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IDF_IDS = ["hmac-sha512", "argon2id"] as const;
const ON_UNINDEXABLE = ["refuse", "bucket"] as const;

/** One field's raw input, as the generator reads it out of the DMMF. */
export interface FieldInput {
  readonly name: string;
  readonly type: string;
  readonly kind: string;
  readonly isList: boolean;
  readonly isRequired: boolean;
  readonly isUnique?: boolean | undefined;
  readonly isId?: boolean | undefined;
  readonly relationName?: string | undefined;
  readonly documentation?: string | null | undefined;
}

export interface ModelInput {
  readonly name: string;
  readonly documentation?: string | null | undefined;
  readonly fields: readonly FieldInput[];
  /** `@@unique([...])` groups, as the DMMF reports them. */
  readonly uniqueFields?: readonly (readonly string[])[] | undefined;
  /** `@@id([...])`, when the model declares a compound primary key. */
  readonly primaryKey?: { readonly fields: readonly string[] } | null | undefined;
}

/**
 * Resolve one model. Collects *every* problem before throwing, so a schema
 * with four mistakes reports four -- the property that makes Django's check
 * framework worth having, and the reason this returns a list rather than
 * failing at the first bad field.
 *
 * A model with no declarations resolves to a relation-only entry
 * (`tableUuid: null`, nothing encrypted) rather than being dropped: the
 * relation graph must be walkable from *every* model, because a write can
 * reach an encrypted column through a model that declares nothing, and a map
 * that omits it turns that write into a silent plaintext bypass.
 */
export function resolveModel(model: ModelInput, parse: ParseFn): ModelMap {
  const problems: string[] = [];
  const site = (field?: string): Site =>
    field === undefined ? { model: model.name } : { model: model.name, field };

  const collect = <T>(fn: () => T): T | undefined => {
    try {
      return fn();
    } catch (e) {
      problems.push(e instanceof Error ? e.message : String(e));
      return undefined;
    }
  };

  const modelAnns = collect(() => parse(model.documentation, site())) ?? [];
  const encrypted: EncryptedFieldDecl[] = [];
  const rawIndexes: Array<{ decl: IndexFieldDecl; site: Site }> = [];
  const relations: RelationDecl[] = [];
  // Whether any @fieldseal declaration was *seen*, as opposed to successfully
  // resolved. These are different questions, and conflating them means a model
  // whose declarations all fail to parse looks like a model with none -- so it
  // exits before the model-level checks run and under-reports its own errors.
  let sawDeclaration = false;

  for (const f of model.fields) {
    if (f.kind === "object" && f.relationName !== undefined) {
      relations.push({ field: f.name, model: f.type, isList: f.isList });
    }
    const anns = collect(() => parse(f.documentation, site(f.name)));
    if (anns === undefined) continue;
    for (const ann of anns) {
      if (ann.flags.has("encrypted")) {
        sawDeclaration = true;
        const d = collect(() => encryptedField(ann, f, site(f.name)));
        if (d !== undefined) encrypted.push(d);
      } else if (ann.values.has("index")) {
        sawDeclaration = true;
        const d = collect(() => indexField(ann, f, site(f.name)));
        if (d !== undefined) rawIndexes.push({ decl: d, site: site(f.name) });
      } else {
        problems.push(
          `${siteLabel(site(f.name))}: an @fieldseal annotation that is neither ` +
            `"encrypted" nor "index: <field>" has nothing to declare. Use ` +
            `@fieldseal(encrypted, column_uuid: "...") on the value column, or ` +
            `@fieldseal(index: "<value column>", ...) on the sibling.`,
        );
      }
    }
  }

  // A model that declares nothing still contributes its relation edges: the
  // visitors must be able to walk *through* it to the declared models it
  // touches. Everything else about it is left alone.
  if (!sawDeclaration) {
    if (problems.length > 0) throw new FieldsealConfigurationError(problems.join("\n"));
    return { model: model.name, tableUuid: null, encrypted: [], indexes: [], relations };
  }

  const tableUuid = collect(() => requiredUuid(modelAnns, "table_uuid", site()));

  // Cross-field checks, which is why they are not in `indexField`.
  const encryptedNames = new Set(encrypted.map((e) => e.field));
  const seenSources = new Map<string, string>();
  const indexes: IndexFieldDecl[] = [];
  for (const { decl, site: s } of rawIndexes) {
    if (!encryptedNames.has(decl.source)) {
      problems.push(
        `${siteLabel(s)}: indexes "${decl.source}", which is not an encrypted ` +
          `column on ${model.name}. An index sibling must name a column ` +
          `declared @fieldseal(encrypted, ...) on the same model.`,
      );
      continue;
    }
    // Spec §7.5, the G19 one-equality rule: a column has exactly one equality,
    // under its own normalizer, and an adapter MUST NOT offer a second. Two
    // index siblings over one column is precisely that second equality.
    const prior = seenSources.get(decl.source);
    if (prior !== undefined) {
      problems.push(
        `${siteLabel(s)}: "${decl.source}" already has an index sibling ` +
          `("${prior}"). Spec §7.5 gives a column exactly one equality, under ` +
          `its declared normalizer, and forbids offering a second, ` +
          `differently-folded one beside it. Drop one of the two siblings.`,
      );
      continue;
    }
    seenSources.set(decl.source, decl.field);
    indexes.push(decl);
  }

  // Compound uniqueness is the same hazard as @unique, spread across columns:
  // an encrypted member randomizes the tuple (the constraint never fires), a
  // sibling member makes §7.4 collisions violate it (legitimate rows refused).
  const constrained = new Set([...encryptedNames, ...indexes.map((i) => i.field)]);
  const groups: Array<readonly string[]> = [...(model.uniqueFields ?? [])];
  if (model.primaryKey != null) groups.push(model.primaryKey.fields);
  for (const group of groups) {
    const hit = group.find((name) => constrained.has(name));
    if (hit !== undefined) {
      problems.push(
        `${siteLabel(site(hit))}: "${hit}" is part of a @@unique or @@id ` +
          `constraint, and neither an encrypted column nor a blind-index ` +
          `sibling may be (spec §7.10). A randomized envelope makes the tuple ` +
          `never repeat, so the constraint never fires; a truncated index's ` +
          `mandated §7.4 collisions make it fire on legitimate distinct values.`,
      );
    }
  }

  if (problems.length > 0) throw new FieldsealConfigurationError(problems.join("\n"));
  return { model: model.name, tableUuid: tableUuid!, encrypted, indexes, relations };
}

type ParseFn = (doc: string | null | undefined, site: Site) => Annotation[];

function encryptedField(ann: Annotation, f: FieldInput, site: Site): EncryptedFieldDecl {
  const columnUuid = requiredUuidFrom(ann, "column_uuid", site);
  const storage = (optString(ann, "storage", site) ?? "binary") as Storage;
  if (storage !== "binary" && storage !== "base64") {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: storage must be "binary" or "base64", not "${storage}".`,
    );
  }
  if (f.type !== "Bytes" && f.type !== "String") {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: an encrypted column must be Bytes (recommended) or ` +
        `String with storage: "base64", not ${f.type}. Spec §3.3: the column ` +
        `holds an envelope, and the logical type of the value is the ` +
        `adapter's concern, not the column's.`,
    );
  }
  if (f.type === "String" && storage !== "base64") {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: a String column must declare storage: "base64" -- ` +
        `raw envelope bytes are not text. Bytes is the recommended column type ` +
        `(spec §3.3); base64 exists for migration compatibility and costs ~33% ` +
        `more storage.`,
    );
  }
  if (f.type === "Bytes" && storage === "base64") {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: storage: "base64" on a Bytes column would base64 the ` +
        `envelope and then store the ASCII as bytes, paying the 33% overhead ` +
        `for nothing. Drop the storage option, or make the column String.`,
    );
  }
  if (f.isUnique === true || f.isId === true) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: an encrypted column cannot be @unique or @id (spec ` +
        `§7.10). The suite is randomized -- every write of one value stores a ` +
        `different envelope (spec §4.4) -- so the constraint never fires and ` +
        `never helps, while Prisma generates a typed findUnique surface for a ` +
        `query the adapter must refuse. Drop the attribute; equality lives on ` +
        `the blind-index sibling, as a filter (spec §7.5).`,
    );
  }
  // `as:` is the *logical* type. The Prisma column type is the storage type --
  // Bytes because it holds an envelope -- so it cannot also say what the value
  // is. Defaulting to "string" makes the common case silent and every other
  // case explicit; defaulting to "bytes" would make a text column round-trip as
  // a Buffer with nothing raised.
  const valueType = (optString(ann, "as", site) ?? "string") as ValueType;
  if (!VALUE_TYPES.includes(valueType)) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: as must be one of ${VALUE_TYPES.join(", ")}, not ` +
        `"${valueType}". It declares what the value IS; the column type declares ` +
        `how the envelope is stored, and the two are not the same question.`,
    );
  }

  return {
    field: f.name,
    columnUuid,
    storage,
    valueType,
    tenantBound: ann.flags.has("tenant_bound"),
    prismaType: f.type,
    noun: optString(ann, "noun", site) ?? f.name,
  };
}

function indexField(ann: Annotation, f: FieldInput, site: Site): IndexFieldDecl {
  // Spec §7.11: an index column is raw bytes of exactly ceil(b/8), or lowercase
  // hex. Base64 is not among the alternatives, because index bytes are
  // compared rather than round-tripped.
  if (f.type !== "Bytes") {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: a blind-index sibling must be Bytes, not ${f.type} ` +
        `(spec §7.11 -- the column's bytes are compared, not round-tripped, and ` +
        `base64 is not among the permitted representations).`,
    );
  }
  // The sibling must be optional in the schema, for two reasons that both bite.
  // Prisma's generated `create` input makes a required column mandatory, so a
  // required sibling forces every caller to supply the one value the adapter
  // refuses to accept from them. And a NULL value has no index, so the column
  // has to be able to hold NULL anyway.
  if (f.isRequired) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: a blind-index sibling must be optional -- declare it ` +
        `\`${f.name} Bytes?\`. Prisma's generated create input requires every ` +
        `non-optional column, so a required sibling makes callers pass the one ` +
        `value this adapter refuses to accept from them (it is derived). A NULL ` +
        `value also has no index, so the column must accept NULL regardless.`,
    );
  }
  if (f.isUnique === true || f.isId === true) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: a blind-index sibling cannot be @unique or @id. ` +
        `truncate_bits must sit inside the spec §7.4 band, which *mandates* ` +
        `collisions, so a UNIQUE constraint here starts rejecting legitimate ` +
        `distinct values as the table fills -- a delayed data-loss bug, and ` +
        `spec §7.10 forbids it outright. Use a plain @@index.`,
    );
  }

  const idf = requiredString(ann, "idf", site);
  if (!(IDF_IDS as readonly string[]).includes(idf)) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: idf must be one of ${IDF_IDS.join(", ")}, not "${idf}".`,
    );
  }
  const normalize = requiredString(ann, "normalize", site);
  if (!(NORMALIZER_IDS as readonly string[]).includes(normalize)) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: normalize must be one of ${NORMALIZER_IDS.join(", ")}, ` +
        `not "${normalize}". A custom normalizer is a portability break: the ` +
        `identifier IS the definition, so an implementation that does not know ` +
        `it cannot derive the same index value.`,
    );
  }
  const onUnindexable = (optString(ann, "on_unindexable", site) ?? "refuse") as OnUnindexable;
  if (!(ON_UNINDEXABLE as readonly string[]).includes(onUnindexable)) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: on_unindexable must be "refuse" or "bucket", not ` +
        `"${onUnindexable}" (docs/09 §7.2).`,
    );
  }

  const argon2Time = optInt(ann, "argon2_time_cost", site);
  const argon2Mem = optInt(ann, "argon2_memory_kib", site);
  if ((argon2Time === undefined) !== (argon2Mem === undefined)) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: argon2_time_cost and argon2_memory_kib must be given ` +
        `together or not at all -- a half-specified cost is not a cost.`,
    );
  }

  const decl: IndexFieldDecl = {
    field: f.name,
    source: requiredString(ann, "index", site),
    indexId: optString(ann, "index_id", site) ?? "exact",
    idf: idf as IdfId,
    normalize: normalize as NormalizerId,
    truncateBits: requiredInt(ann, "truncate_bits", site),
    projectedPopulation: requiredInt(ann, "projected_population", site),
    onUnindexable,
    skewed: optString(ann, "skewed", site) === "true",
    prismaType: f.type,
    ...(argon2Time !== undefined && argon2Mem !== undefined
      ? { argon2: { timeCost: argon2Time, memoryKib: argon2Mem } }
      : {}),
  };
  return decl;
}

function requiredUuid(anns: readonly Annotation[], key: string, site: Site): string {
  for (const a of anns) {
    if (a.values.has(key)) return requiredUuidFrom(a, key, site);
  }
  throw new FieldsealConfigurationError(
    `${siteLabel(site)}: no @fieldseal(${key}: "...") declared. The surrogate is ` +
      `REQUIRED and immutable: spec §6.1 binds key derivation to it, so it must ` +
      `never be derived from the model or field name -- a rename would make ` +
      `every existing row undecryptable. Generate one with a UUID v4 tool and ` +
      `write it literally in the schema.`,
  );
}

function requiredUuidFrom(ann: Annotation, key: string, site: Site): string {
  const v = requiredString(ann, key, site);
  if (!UUID_RE.test(v)) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: ${key} must be a UUID in 8-4-4-4-12 hex form, not "${v}".`,
    );
  }
  return v.toLowerCase();
}

function requiredString(ann: Annotation, key: string, site: Site): string {
  const v = ann.values.get(key);
  if (v === undefined) {
    throw new FieldsealConfigurationError(`${siteLabel(site)}: "${key}" is required.`);
  }
  return String(v);
}

function optString(ann: Annotation, key: string, _site: Site): string | undefined {
  const v = ann.values.get(key);
  return v === undefined ? undefined : String(v);
}

function requiredInt(ann: Annotation, key: string, site: Site): number {
  const v = ann.values.get(key);
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new FieldsealConfigurationError(
      `${siteLabel(site)}: "${key}" is required and must be an integer.`,
    );
  }
  return v;
}

function optInt(ann: Annotation, key: string, site: Site): number | undefined {
  const v = ann.values.get(key);
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new FieldsealConfigurationError(`${siteLabel(site)}: "${key}" must be an integer.`);
  }
  return v;
}
