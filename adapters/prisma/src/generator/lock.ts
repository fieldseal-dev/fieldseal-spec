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
 * Entries are keyed by PHYSICAL names (`@@map` / `@map`, else the Prisma
 * name), so a Prisma-only rename keeps its entry. An index's `source` is the
 * source column's physical name for the same reason.
 */

import type { ModelInput } from "../declarations.ts";
import { FieldsealConfigurationError } from "../errors.ts";
import type { EncryptedFieldDecl, FieldMap, IndexFieldDecl } from "../fieldmap.ts";

export const LOCK_VERSION = 1;
export const DEFAULT_LOCKFILE = "fieldseal.lock.json";

export interface EncryptedLockEntry {
  readonly kind: "encrypted";
  readonly columnUuid: string;
  readonly valueType: string;
  readonly storage: string;
  readonly tenantBound: boolean;
}

export interface IndexLockEntry {
  readonly kind: "index";
  /** The source column's PHYSICAL name. */
  readonly source: string;
  readonly indexId: string;
  readonly suiteId: number;
  readonly idf: string;
  readonly normalize: string;
  readonly truncateBits: number;
  /** As declared; present only when the declaration states a cost. */
  readonly argon2?: { readonly timeCost: number; readonly memoryKib: number };
}

export type ColumnLockEntry = EncryptedLockEntry | IndexLockEntry;

export interface TableLock {
  readonly tableUuid: string | null;
  readonly columns: Readonly<Record<string, ColumnLockEntry>>;
}

export interface Lock {
  readonly version: 1;
  readonly tables: Readonly<Record<string, TableLock>>;
}

/** Where each lock entry came from, for messages. Not written to the file. */
export interface Origins {
  readonly [table: string]: {
    readonly model: string;
    readonly columns: { readonly [column: string]: string };
  };
}

const physicalTable = (m: ModelInput): string => m.dbName ?? m.name;

/** Build the lock the current schema implies. */
export function buildLock(
  datamodel: { readonly models: readonly ModelInput[] },
  map: FieldMap,
): { lock: Lock; origins: Origins } {
  const tables: Record<string, TableLock> = {};
  const origins: Record<string, { model: string; columns: Record<string, string> }> = {};
  for (const m of datamodel.models) {
    const resolved = map.models.find((r) => r.model === m.name);
    if (resolved === undefined) continue;
    if (resolved.tableUuid === null && resolved.encrypted.length === 0 && resolved.indexes.length === 0) {
      continue;
    }
    const col = (fieldName: string): string =>
      m.fields.find((f) => f.name === fieldName)?.dbName ?? fieldName;
    const columns: Record<string, ColumnLockEntry> = {};
    const fieldOf: Record<string, string> = {};
    for (const e of resolved.encrypted) {
      columns[col(e.field)] = encryptedEntry(e);
      fieldOf[col(e.field)] = e.field;
    }
    for (const i of resolved.indexes) {
      columns[col(i.field)] = indexEntry(i, col(i.source));
      fieldOf[col(i.field)] = i.field;
    }
    const table = physicalTable(m);
    tables[table] = { tableUuid: resolved.tableUuid, columns: sortKeys(columns) };
    origins[table] = { model: m.name, columns: fieldOf };
  }
  return { lock: { version: LOCK_VERSION, tables: sortKeys(tables) }, origins };
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

function indexEntry(i: IndexFieldDecl, source: string): IndexLockEntry {
  return {
    kind: "index",
    source,
    indexId: i.indexId,
    suiteId: i.suiteId,
    idf: i.idf,
    normalize: i.normalize,
    truncateBits: i.truncateBits,
    ...(i.argon2 !== undefined
      ? { argon2: { timeCost: i.argon2.timeCost, memoryKib: i.argon2.memoryKib } }
      : {}),
  };
}

function sortKeys<T>(o: Record<string, T>): Record<string, T> {
  return Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
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
  "kind", "source", "indexId", "suiteId", "idf", "normalize", "truncateBits", "argon2",
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
  const extra = Object.keys(raw).filter((k) => k !== "version" && k !== "tables");
  if (extra.length > 0) return bad(`unknown top-level key "${extra[0]!}"`);
  const rawTables = raw["tables"];
  if (!isObject(rawTables)) return bad(`"tables" is not an object`);
  const tables: Record<string, TableLock> = {};
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
    const columns: Record<string, ColumnLockEntry> = {};
    for (const [c, cv] of Object.entries(rawCols)) {
      const ca = `${at}.columns[${JSON.stringify(c)}]`;
      if (!isObject(cv)) return bad(`${ca} is not an object`);
      columns[c] = parseEntry(cv, ca, bad);
    }
    tables[t] = { tableUuid, columns };
  }
  return { version: LOCK_VERSION, tables };
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
  if (v["kind"] === "encrypted") {
    const tb = v["tenantBound"];
    if (typeof tb !== "boolean") return bad(`${at}.tenantBound is not a boolean`);
    return {
      kind: "encrypted",
      columnUuid: str("columnUuid"),
      valueType: str("valueType"),
      storage: str("storage"),
      tenantBound: tb,
    };
  }
  const base = {
    kind: "index" as const,
    source: str("source"),
    indexId: str("indexId"),
    suiteId: int("suiteId"),
    idf: str("idf"),
    normalize: str("normalize"),
    truncateBits: int("truncateBits"),
  };
  if (v["argon2"] === undefined) return base;
  const a = v["argon2"];
  if (!isObject(a)) return bad(`${at}.argon2 is not an object`);
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

const WHY_IDENTITY = {
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
    "value in the table, written under the old one, no longer decrypts",
  kind:
    "the column's stored values were written as the old kind, so they are not valid " +
    "as the new one (spec §6.1, §7.8)",
} as const;

const WHY_INDEX =
  "spec §7.8 says this MUST NOT change once an index is written, and §7.2 puts it in " +
  "the key-derivation context: stored index values no longer match, so equality " +
  "lookups would silently return no rows, which spec §10.2 forbids an adapter to do";

/** A suite id as hex, as the Django adapter prints it; tolerant of a non-int. */
export function suiteText(v: unknown): string {
  return typeof v === "number" && Number.isInteger(v)
    ? `0x${v.toString(16).padStart(4, "0")}`
    : JSON.stringify(v);
}

const declared = (v: number | undefined): string => (v === undefined ? "not stated" : String(v));

export function compareLocks(old: Lock, next: Lock, origins: Origins): Refusal[] {
  const out: Refusal[] = [];
  for (const [table, ot] of Object.entries(old.tables)) {
    const nt = next.tables[table];
    if (nt === undefined) continue;
    const model = origins[table]?.model ?? table;
    if (ot.tableUuid !== null && nt.tableUuid !== null && ot.tableUuid !== nt.tableUuid) {
      out.push({
        table, model, attribute: "table_uuid", before: ot.tableUuid, after: nt.tableUuid,
        why: WHY_IDENTITY.table_uuid, index: false,
      });
    }
    for (const [column, oc] of Object.entries(ot.columns)) {
      const nc = nt.columns[column];
      if (nc === undefined) continue;
      const field = origins[table]?.columns[column] ?? column;
      const add = (attribute: string, before: string, after: string, why: string, index: boolean) =>
        out.push({ table, column, model, field, attribute, before, after, why, index });
      if (oc.kind !== nc.kind) {
        add("kind", oc.kind, nc.kind, WHY_IDENTITY.kind, oc.kind === "index" || nc.kind === "index");
      } else if (oc.kind === "encrypted" && nc.kind === "encrypted") {
        if (oc.columnUuid !== nc.columnUuid) add("column_uuid", oc.columnUuid, nc.columnUuid, WHY_IDENTITY.column_uuid, false);
        if (oc.valueType !== nc.valueType) add("as", oc.valueType, nc.valueType, WHY_IDENTITY.as, false);
        if (oc.storage !== nc.storage) add("storage", oc.storage, nc.storage, WHY_IDENTITY.storage, false);
        if (oc.tenantBound !== nc.tenantBound) {
          add("tenant_bound", String(oc.tenantBound), String(nc.tenantBound), WHY_IDENTITY.tenant_bound, false);
        }
      } else if (oc.kind === "index" && nc.kind === "index") {
        const t = (a: string, b: unknown, c: unknown) => {
          if (b !== c) add(a, String(b), String(c), WHY_INDEX, true);
        };
        t("index", oc.source, nc.source);
        t("index_id", oc.indexId, nc.indexId);
        t("idf", oc.idf, nc.idf);
        t("normalize", oc.normalize, nc.normalize);
        t("truncate_bits", oc.truncateBits, nc.truncateBits);
        if (oc.suiteId !== nc.suiteId) add("suite_id", suiteText(oc.suiteId), suiteText(nc.suiteId), WHY_INDEX, true);
        if (oc.idf === "argon2id" && nc.idf === "argon2id") {
          const a = (k: "timeCost" | "memoryKib", name: string) => {
            if (oc.argon2?.[k] !== nc.argon2?.[k]) {
              add(name, declared(oc.argon2?.[k]), declared(nc.argon2?.[k]), WHY_INDEX, true);
            }
          };
          a("timeCost", "argon2_time_cost");
          a("memoryKib", "argon2_memory_kib");
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
        "re-encrypted by other means, or the data moved to a new column.",
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
 * Decide what to do with the lockfile: throws on malformation or refusal, and
 * otherwise returns the text to write (or null for no write) and what happened.
 */
export function reconcileLock(
  existing: string | null,
  next: Lock,
  origins: Origins,
  where: string,
): { text: string | null; outcome: LockOutcome } {
  const text = renderLock(next);
  if (existing === null) return { text, outcome: "created" };
  const refusals = compareLocks(parseLock(existing, where), next, origins);
  if (refusals.length > 0) {
    throw new FieldsealConfigurationError(renderRefusals(refusals, where));
  }
  return existing === text ? { text: null, outcome: "unchanged" } : { text, outcome: "updated" };
}
