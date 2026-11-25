/**
 * The declaration lockfile: the baseline `prisma generate` compares against.
 *
 * A `///` annotation changed in `schema.prisma` produces no migration, and
 * `prisma generate` would silently rewrite the field map under the new
 * declaration. For an encrypted column's identity that leaves every stored
 * value undecryptable (spec §6.1); for a blind index's declaration it makes
 * equality lookups silently return nothing (spec §7.8, §10.2). The previously
 * generated field map cannot be the baseline: in most projects it lives in the
 * gitignored Prisma `output` folder. So the attributes that must not change are
 * recorded in a small committed file, and a generate that would change one
 * is refused (issue #317). The Django adapter does the same at `migrate`
 * (#288, #303).
 *
 * Pure logic only -- build, parse, compare, render -- so it is testable
 * without spawning a generator. `bin.ts` does the file IO.
 *
 * Entries are keyed by PHYSICAL names (`@@schema`.`@@map` / `@map`, else the
 * Prisma name), so a Prisma-only rename keeps its entry. An index records its
 * source column's `column_uuid` and `tenant_bound`, the parts of the source's
 * context its key is derived under (`indexContext` in `context.ts`), and those
 * are compared rather than the source's name: a renamed source is no change,
 * and an identity change of the source is refused on the index too (PR #318
 * review).
 *
 * Every lookup by a physical name goes through `own()`: a table or column
 * named after an `Object.prototype` member (`constructor`, `toString`) must
 * not find the inherited one.
 */

import type { ModelInput } from "../declarations.ts";
import { FieldsealConfigurationError } from "../errors.ts";
import type { EncryptedFieldDecl, FieldMap, IndexFieldDecl } from "../fieldmap.ts";

export const LOCK_VERSION = 1;
export const DEFAULT_LOCKFILE = "fieldseal.lock.json";

/**
 * Spec §7.3's Argon2id minima, which the core applies where a declaration
 * states no cost (`argon2ParamsOrMinima` in `@fieldseal/core`). The lock
 * records the cost an index is derived under, so unstated and the minima
 * stated are the same entry. The core does not export them.
 */
export const ARGON2_MIN = { timeCost: 3, memoryKib: 32768 } as const;

export interface EncryptedLockEntry {
  readonly kind: "encrypted";
  readonly columnUuid: string;
  readonly valueType: string;
  readonly storage: string;
  readonly tenantBound: boolean;
}

export interface IndexLockEntry {
  readonly kind: "index";
  /** The source column's PHYSICAL name. For reading only: not compared. */
  readonly source: string;
  /** The source's `column_uuid`, in the index key's derivation context. */
  readonly sourceColumnUuid: string;
  /** The source's `tenant_bound`: the tenant is in that context too. */
  readonly sourceTenantBound: boolean;
  readonly indexId: string;
  readonly suiteId: number;
  readonly idf: string;
  readonly normalize: string;
  readonly truncateBits: number;
  /** The cost derived under: present exactly when `idf` is `argon2id`. */
  readonly argon2?: { readonly timeCost: number; readonly memoryKib: number };
}

export type ColumnLockEntry = EncryptedLockEntry | IndexLockEntry;

export interface TableLock {
  readonly tableUuid: string | null;
  readonly columns: Readonly<Record<string, ColumnLockEntry>>;
}

export interface Lock {
  readonly version: 1;
  /** The schema this lock belongs to, relative to the lock's directory. */
  readonly schema: string;
  readonly tables: Readonly<Record<string, TableLock>>;
}

/**
 * Every model of the schema by physical table, with every scalar field by
 * physical column: names for messages, and which columns still exist, so a
 * declaration removed from a column that is still there can be told from a
 * column removed. Not written to the file.
 */
export interface Origins {
  readonly [table: string]: {
    readonly model: string;
    readonly columns: { readonly [column: string]: string };
  };
}

/** An own property only, never an inherited `Object.prototype` member. */
function own<T>(o: Readonly<Record<string, T>> | undefined, k: string): T | undefined {
  return o !== undefined && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined;
}

function physicalTable(m: ModelInput): string {
  const table = m.dbName ?? m.name;
  return m.schema !== undefined && m.schema !== null && m.schema !== "" ? `${m.schema}.${table}` : table;
}

/** Build the lock the current schema implies. */
export function buildLock(
  datamodel: { readonly models: readonly ModelInput[] },
  map: FieldMap,
  schema: string,
): { lock: Lock; origins: Origins } {
  const tables: Record<string, TableLock> = Object.create(null) as Record<string, TableLock>;
  const origins = Object.create(null) as Record<string, { model: string; columns: Record<string, string> }>;
  for (const m of datamodel.models) {
    const table = physicalTable(m);
    const seen = own(origins, table);
    if (seen !== undefined) {
      throw new FieldsealConfigurationError(
        `fieldseal: models ${seen.model} and ${m.name} both map to the table ${table}. ` +
          `The declaration lock keys each table by its physical name, so it cannot ` +
          `tell them apart.`,
      );
    }
    const col = (fieldName: string): string =>
      m.fields.find((f) => f.name === fieldName)?.dbName ?? fieldName;
    const fieldOf = Object.create(null) as Record<string, string>;
    for (const f of m.fields) {
      if (f.kind !== "object") fieldOf[col(f.name)] = f.name;
    }
    origins[table] = { model: m.name, columns: fieldOf };

    const resolved = map.models.find((r) => r.model === m.name);
    if (resolved === undefined) continue;
    if (resolved.tableUuid === null && resolved.encrypted.length === 0 && resolved.indexes.length === 0) {
      continue;
    }
    const columns: Record<string, ColumnLockEntry> = {};
    for (const e of resolved.encrypted) columns[col(e.field)] = encryptedEntry(e);
    for (const i of resolved.indexes) {
      const source = resolved.encrypted.find((e) => e.field === i.source);
      if (source === undefined) {
        // `resolveModel` refuses an index over anything but an encrypted
        // field, so a map that gets here was not built by it.
        throw new FieldsealConfigurationError(
          `fieldseal: ${m.name}.${i.field} indexes ${i.source}, which is not an encrypted field.`,
        );
      }
      columns[col(i.field)] = indexEntry(i, col(i.source), source);
    }
    tables[table] = { tableUuid: resolved.tableUuid, columns: sortKeys(columns) };
  }
  return { lock: { version: LOCK_VERSION, schema, tables: sortKeys(tables) }, origins };
}

function encryptedEntry(e: EncryptedFieldDecl): EncryptedLockEntry {
  return {
    kind: "encrypted",
    columnUuid: e.columnUuid,
    valueType: e.valueType,
    storage: e.storage,
    tenantBound: e.tenantBound,
  };
}

function indexEntry(i: IndexFieldDecl, source: string, src: EncryptedFieldDecl): IndexLockEntry {
  const argon2 = i.argon2 ?? ARGON2_MIN;
  return {
    kind: "index",
    source,
    sourceColumnUuid: src.columnUuid,
    sourceTenantBound: src.tenantBound,
    indexId: i.indexId,
    suiteId: i.suiteId,
    idf: i.idf,
    normalize: i.normalize,
    truncateBits: i.truncateBits,
    ...(i.idf === "argon2id"
      ? { argon2: { timeCost: argon2.timeCost, memoryKib: argon2.memoryKib } }
      : {}),
  };
}

function sortKeys<T>(o: Record<string, T>): Record<string, T> {
  const out = Object.create(null) as Record<string, T>;
  for (const k of Object.keys(o).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) out[k] = o[k]!;
  return out;
}

/**
 * The file's text: stable key order (entries are built in a fixed order and
 * tables and columns are sorted), two-space indent, trailing newline, so an
 * unchanged schema regenerates byte-identical.
 */
export function renderLock(lock: Lock): string {
  return `${JSON.stringify(lock, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Parsing: fail closed. A lockfile that cannot be read is never "missing".
// ---------------------------------------------------------------------------

const ENCRYPTED_KEYS = ["kind", "columnUuid", "valueType", "storage", "tenantBound"];
const INDEX_KEYS = [
  "kind", "source", "sourceColumnUuid", "sourceTenantBound", "indexId", "suiteId", "idf",
  "normalize", "truncateBits", "argon2",
];

export function parseLock(text: string, where: string): Lock {
  const bad = (why: string): never => {
    throw new FieldsealConfigurationError(
      `fieldseal: the lockfile ${where} is malformed: ${why}. It is the baseline ` +
        `that guards declarations against a silent change, so it is never treated ` +
        `as missing. Restore it from version control; if it is genuinely lost, ` +
        `delete it and run \`prisma generate\` to start a new baseline (which ` +
        `forgoes the guard for what was in it, so review the diff).`,
    );
  };
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return bad(`not valid JSON (${e instanceof Error ? e.message : String(e)})`);
  }
  if (!isObject(raw)) return bad("the top level is not an object");
  if (raw["version"] !== LOCK_VERSION) {
    return bad(
      `version is ${JSON.stringify(raw["version"])}, and this generator reads version ${String(LOCK_VERSION)} only`,
    );
  }
  const extra = Object.keys(raw).filter((k) => k !== "version" && k !== "schema" && k !== "tables");
  if (extra.length > 0) return bad(`unknown top-level key "${extra[0]!}"`);
  const schema = raw["schema"];
  if (typeof schema !== "string") return bad(`"schema" is not a string`);
  const rawTables = raw["tables"];
  if (!isObject(rawTables)) return bad(`"tables" is not an object`);
  const tables = Object.create(null) as Record<string, TableLock>;
  for (const [t, tv] of Object.entries(rawTables)) {
    const at = `tables[${JSON.stringify(t)}]`;
    if (!isObject(tv)) return bad(`${at} is not an object`);
    for (const k of Object.keys(tv)) {
      if (k !== "tableUuid" && k !== "columns") return bad(`${at} has unknown key "${k}"`);
    }
    const tableUuid = tv["tableUuid"];
    if (tableUuid !== null && typeof tableUuid !== "string") {
      return bad(`${at}.tableUuid is not a string or null`);
    }
    const rawCols = tv["columns"];
    if (!isObject(rawCols)) return bad(`${at}.columns is not an object`);
    const columns = Object.create(null) as Record<string, ColumnLockEntry>;
    for (const [c, cv] of Object.entries(rawCols)) {
      const ca = `${at}.columns[${JSON.stringify(c)}]`;
      if (!isObject(cv)) return bad(`${ca} is not an object`);
      columns[c] = parseEntry(cv, ca, bad);
    }
    tables[t] = { tableUuid, columns };
  }
  return { version: LOCK_VERSION, schema, tables };
}

function parseEntry(
  v: Record<string, unknown>,
  at: string,
  bad: (why: string) => never,
): ColumnLockEntry {
  const allowed = v["kind"] === "encrypted" ? ENCRYPTED_KEYS : v["kind"] === "index" ? INDEX_KEYS : null;
  if (allowed === null) return bad(`${at}.kind is not "encrypted" or "index"`);
  for (const k of Object.keys(v)) {
    if (!allowed.includes(k)) return bad(`${at} has unknown key "${k}"`);
  }
  const str = (k: string): string => {
    const x = v[k];
    return typeof x === "string" ? x : bad(`${at}.${k} is not a string`);
  };
  const int = (k: string): number => {
    const x = v[k];
    return typeof x === "number" && Number.isInteger(x) ? x : bad(`${at}.${k} is not an integer`);
  };
  const bool = (k: string): boolean => {
    const x = v[k];
    return typeof x === "boolean" ? x : bad(`${at}.${k} is not a boolean`);
  };
  if (v["kind"] === "encrypted") {
    return {
      kind: "encrypted",
      columnUuid: str("columnUuid"),
      valueType: str("valueType"),
      storage: str("storage"),
      tenantBound: bool("tenantBound"),
    };
  }
  const base = {
    kind: "index" as const,
    source: str("source"),
    sourceColumnUuid: str("sourceColumnUuid"),
    sourceTenantBound: bool("sourceTenantBound"),
    indexId: str("indexId"),
    suiteId: int("suiteId"),
    idf: str("idf"),
    normalize: str("normalize"),
    truncateBits: int("truncateBits"),
  };
  const a = v["argon2"];
  if (base.idf !== "argon2id") {
    return a === undefined ? base : bad(`${at}.argon2 is present, and idf is not argon2id`);
  }
  if (!isObject(a)) return bad(`${at}.argon2 is missing or not an object, and idf is argon2id`);
  for (const k of Object.keys(a)) {
    if (k !== "timeCost" && k !== "memoryKib") return bad(`${at}.argon2 has unknown key "${k}"`);
  }
  const tc = a["timeCost"];
  const mk = a["memoryKib"];
  if (typeof tc !== "number" || !Number.isInteger(tc) || typeof mk !== "number" || !Number.isInteger(mk)) {
    return bad(`${at}.argon2 needs integer timeCost and memoryKib`);
  }
  return { ...base, argon2: { timeCost: tc, memoryKib: mk } };
}

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

// ---------------------------------------------------------------------------
// Comparing
// ---------------------------------------------------------------------------

export interface Refusal {
  readonly table: string;
  /** Absent for a table-level change (`table_uuid`). */
  readonly column?: string;
  readonly model: string;
  readonly field?: string;
  /** The attribute as written in the `///` annotation. */
  readonly attribute: string;
  readonly before: string;
  readonly after: string;
  readonly why: string;
  readonly index: boolean;
}

const WHY = {
  column_uuid:
    "spec §6.1 binds each value's key derivation and context to column_uuid, so every " +
    "stored value, written under the old one, no longer decrypts",
  as:
    "spec §3.6 fixes each type's rendering, and the stored envelopes hold the old " +
    "type's, so a read fails or misreads them",
  storage:
    "spec §3.3 gives the envelope a binary or a base64 text form, and nothing converts " +
    "the stored values into the new one, so reads fail or return the envelope's text",
  tenant_bound:
    "the tenant is part of the key and context a value is encrypted under (spec §6; " +
    "docs/12 §4), so values written under one setting do not decrypt under the other",
  table_uuid:
    "spec §6.1 binds key derivation and context to table_uuid as well, so every stored " +
    "value in the table, and every blind index over it, written under the old one, no " +
    "longer decrypts or matches",
  kind:
    "the column's stored values were written as the old kind, so they are not valid " +
    "as the new one",
  undeclared:
    "the column still exists and still holds envelopes, and without its declaration " +
    "reads return the envelope bytes as the value and writes store plaintext beside " +
    "them",
} as const;

const LOOKUPS =
  "stored index values no longer match, so equality lookups would silently return no " +
  "rows, which spec §10.2 forbids an adapter to do";

/** In the index key's derivation context (spec §7.2). */
const WHY_CONTEXT = `spec §7.2 puts it in the index key's derivation context: ${LOOKUPS}`;
/** Named by spec §7.8, apart from the context. */
const WHY_DERIVATION = `spec §7.8 says it MUST NOT change once an index is written: ${LOOKUPS}`;

/** A suite id as hex, as the Django adapter prints it; tolerant of a non-int. */
export function suiteText(v: unknown): string {
  return typeof v === "number" && Number.isInteger(v)
    ? `0x${v.toString(16).padStart(4, "0")}`
    : JSON.stringify(v);
}

export function compareLocks(old: Lock, next: Lock, origins: Origins): Refusal[] {
  const out: Refusal[] = [];
  for (const [table, ot] of Object.entries(old.tables)) {
    const nt = own(next.tables, table);
    const origin = own(origins, table);
    const model = origin?.model ?? table;
    if (nt !== undefined && ot.tableUuid !== null && nt.tableUuid !== null && ot.tableUuid !== nt.tableUuid) {
      out.push({
        table, model, attribute: "table_uuid", before: ot.tableUuid, after: nt.tableUuid,
        why: WHY.table_uuid, index: false,
      });
    }
    for (const [column, oc] of Object.entries(ot.columns)) {
      const field = own(origin?.columns, column);
      const add = (attribute: string, before: string, after: string, why: string, index: boolean) =>
        out.push({ table, column, model, field: field ?? column, attribute, before, after, why, index });
      const nc = own(nt?.columns, column);
      if (nc === undefined) {
        // Gone from the lock. A removed column, or a removed index, passes;
        // an encrypted column still in the schema without its declaration
        // does not.
        if (oc.kind === "encrypted" && field !== undefined) {
          add("encrypted", "declared", "not declared", WHY.undeclared, false);
        }
        continue;
      }
      if (oc.kind !== nc.kind) {
        add("kind", oc.kind, nc.kind, WHY.kind, oc.kind === "index" || nc.kind === "index");
      } else if (oc.kind === "encrypted" && nc.kind === "encrypted") {
        if (oc.columnUuid !== nc.columnUuid) add("column_uuid", oc.columnUuid, nc.columnUuid, WHY.column_uuid, false);
        if (oc.valueType !== nc.valueType) add("as", oc.valueType, nc.valueType, WHY.as, false);
        if (oc.storage !== nc.storage) add("storage", oc.storage, nc.storage, WHY.storage, false);
        if (oc.tenantBound !== nc.tenantBound) {
          add("tenant_bound", String(oc.tenantBound), String(nc.tenantBound), WHY.tenant_bound, false);
        }
      } else if (oc.kind === "index" && nc.kind === "index") {
        if (oc.sourceColumnUuid !== nc.sourceColumnUuid) {
          add(
            "index (the source's column_uuid)",
            `${oc.sourceColumnUuid} (${oc.source})`,
            `${nc.sourceColumnUuid} (${nc.source})`,
            WHY_CONTEXT, true,
          );
        }
        if (oc.sourceTenantBound !== nc.sourceTenantBound) {
          add(
            "index (the source's tenant_bound)",
            String(oc.sourceTenantBound), String(nc.sourceTenantBound), WHY_CONTEXT, true,
          );
        }
        const t = (a: string, b: unknown, c: unknown, why: string) => {
          if (b !== c) add(a, String(b), String(c), why, true);
        };
        t("index_id", oc.indexId, nc.indexId, WHY_CONTEXT);
        if (oc.suiteId !== nc.suiteId) {
          add("suite_id", suiteText(oc.suiteId), suiteText(nc.suiteId), WHY_CONTEXT, true);
        }
        t("idf", oc.idf, nc.idf, WHY_DERIVATION);
        t("normalize", oc.normalize, nc.normalize, WHY_DERIVATION);
        t("truncate_bits", oc.truncateBits, nc.truncateBits, WHY_DERIVATION);
        if (oc.argon2 !== undefined && nc.argon2 !== undefined) {
          t("argon2_time_cost", oc.argon2.timeCost, nc.argon2.timeCost, WHY_DERIVATION);
          t("argon2_memory_kib", oc.argon2.memoryKib, nc.argon2.memoryKib, WHY_DERIVATION);
        }
      }
    }
  }
  return out;
}

const q = (s: string): string => JSON.stringify(s);

/** Where to delete the entry to accept a refusal. */
function lockPath(r: Refusal): string {
  return r.column === undefined
    ? `tables[${q(r.table)}]`
    : `tables[${q(r.table)}].columns[${q(r.column)}]`;
}

export function renderRefusals(refusals: readonly Refusal[], lockfile: string): string {
  const items = refusals.map((r) => {
    const where =
      r.column === undefined
        ? `${r.model} (table ${r.table})`
        : `${r.model}.${r.field ?? r.column} (${r.table}.${r.column})`;
    return (
      `${where}: ${r.attribute} changed ${r.before} → ${r.after}\n` +
      `  Why: ${r.why}.\n` +
      `  To accept it, delete ${lockPath(r)} from ${lockfile}.`
    );
  });
  const hasIndex = refusals.some((r) => r.index);
  const hasIdentity = refusals.some((r) => !r.index);
  const routes: string[] = [];
  if (hasIndex) {
    routes.push(
      "The supported route for a changed blind index is a rebuild of its values, " +
        "which does not exist yet (https://github.com/fieldseal-dev/fieldseal-spec/issues/315).",
    );
  }
  if (hasIdentity) {
    routes.push(
      "For a changed encrypted-column identity, the stored values must be " +
        "re-encrypted by other means, or the data moved to a new column; a blind " +
        "index over the column must be rebuilt as well.",
    );
  }
  return (
    `fieldseal: ${String(refusals.length)} declaration change(s) refused. \`prisma generate\` ` +
    `compares the schema with ${lockfile}, which records what the stored values were ` +
    `written under, and changed attributes that make them unreadable. Neither the ` +
    `field map nor the lockfile was written.\n\n` +
    items.join("\n\n") +
    `\n\n${routes.join(" ")} Deleting an entry from ${lockfile} and running ` +
    `\`prisma generate\` again is your reviewable statement that the stored values ` +
    `were rebuilt or re-encrypted by other means; the new declaration is then recorded.`
  );
}

export type LockOutcome = "created" | "updated" | "unchanged";

/**
 * Decide what to do with the lockfile: throws on malformation, on a lock that
 * belongs to another schema, or on a refusal; otherwise returns the text to
 * write (or null for no write), what happened, and for an update a summary.
 *
 * A lock that differs only in formatting (a CRLF checkout, a reformatted
 * file) is unchanged: it is compared as parsed, not as text.
 */
export function reconcileLock(
  existing: string | null,
  next: Lock,
  origins: Origins,
  where: string,
): { text: string | null; outcome: LockOutcome; summary?: string } {
  const text = renderLock(next);
  if (existing === null) return { text, outcome: "created" };
  const old = parseLock(existing, where);
  if (old.schema !== next.schema) {
    throw new FieldsealConfigurationError(
      `fieldseal: the lockfile ${where} belongs to the schema ${old.schema}, and this ` +
        `generate is for ${next.schema}. Two schemas sharing one lockfile would each ` +
        `erase the other's baseline. Give this schema its own with ` +
        `\`lockfile = "..."\` in its generator block; if the schema was moved or ` +
        `renamed, change "schema" in the lockfile to ${q(next.schema)}.`,
    );
  }
  const refusals = compareLocks(old, next, origins);
  if (refusals.length > 0) {
    throw new FieldsealConfigurationError(renderRefusals(refusals, where));
  }
  if (renderLock(old) === text) return { text: null, outcome: "unchanged" };
  return { text, outcome: "updated", summary: summarize(old, next) };
}

/** What an update changed, in entries, for the generator's note. */
function summarize(old: Lock, next: Lock): string {
  const entries = (l: Lock): Map<string, string> => {
    const m = new Map<string, string>();
    for (const [t, tv] of Object.entries(l.tables)) {
      m.set(`${t}`, JSON.stringify(tv.tableUuid));
      for (const [c, cv] of Object.entries(tv.columns)) m.set(`${t}.${c}`, JSON.stringify(cv));
    }
    return m;
  };
  const a = entries(old);
  const b = entries(next);
  let added = 0;
  let removed = 0;
  let changed = 0;
  for (const [k, v] of b) {
    const was = a.get(k);
    if (was === undefined) added += 1;
    else if (was !== v) changed += 1;
  }
  for (const k of a.keys()) if (!b.has(k)) removed += 1;
  return `${String(added)} added, ${String(removed)} removed, ${String(changed)} rewritten`;
}
