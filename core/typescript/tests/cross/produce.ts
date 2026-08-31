/**
 * Cross-implementation producer (docs/08 §4.7, docs/14 §3).
 *
 * Encrypts every case in vectors/cross/corpus.json through the REAL
 * production path -- runtime CSPRNG, no test-mode injection; nothing from
 * src/testing is imported here -- resolving key_ref against
 * vectors/keys/test-keys.json. The output differs on every run and is a CI
 * artifact, never committed.
 *
 * Usage: node tests/cross/produce.ts --out <file>
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Fieldseal } from "../../src/api.ts";
import type { IndexDeclaration } from "../../src/blindindex.ts";
import type { FieldContext } from "../../src/context.ts";
import { StaticKeyProvider } from "../../src/keyprovider.ts";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const VECTORS = join(REPO, "vectors");

function hex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "hex"));
}

interface KeyEntry {
  suite_id: string;
  key_id: string;
  tenant_dek: string;
  tenant_index_key: string;
}

/**
 * One index case's inputs, as `cross/corpus.json` gives them.
 *
 * The `declaration` block travels with the case because a cross producer
 * derives through a **constructed client**, not through primitives: spec §7.4's
 * truncation band and §7.6's cardinality gate run at construction, so a
 * consumer that cannot rebuild the declaration cannot build the client that
 * re-derives the value. `projected_population` and `on_unindexable` affect no
 * derived byte and gate construction absolutely.
 */
interface IndexCase {
  case: string;
  key_ref: string;
  declaration: {
    index_id: string;
    idf: string;
    idf_params: Record<string, number | string>;
    normalize: string;
    truncate_bits: number;
    projected_population: number;
    on_unindexable: string;
    unindexable_override?: { reason: string; approved_by: string; date: string };
  };
  context: Record<string, string | null>;
  value_text?: string;
  value_bytes?: string;
  value_marker?: boolean;
}

/** The corpus's declaration, as the core's registry wants it. */
function declOf(c: IndexCase): IndexDeclaration {
  const d = c.declaration;
  return {
    tableUuid: hex(c.context.table_uuid!),
    columnUuid: hex(c.context.column_uuid!),
    indexId: d.index_id,
    idf: d.idf as IndexDeclaration["idf"],
    normalize: d.normalize as IndexDeclaration["normalize"],
    truncateBits: d.truncate_bits,
    projectedPopulation: d.projected_population,
    onUnindexable: d.on_unindexable as NonNullable<IndexDeclaration["onUnindexable"]>,
    ...(d.unindexable_override !== undefined
      ? {
          unindexableOverride: {
            reason: d.unindexable_override.reason,
            approvedBy: d.unindexable_override.approved_by,
            date: d.unindexable_override.date,
          },
        }
      : {}),
  };
}

function clientFor(k: KeyEntry, indexes: IndexDeclaration[] = []): Fieldseal {
  const suiteId = parseInt(k.suite_id.slice(2), 16);
  return new Fieldseal(
    {
      keyProvider: new StaticKeyProvider({ dek: hex(k.tenant_dek), keyId: hex(k.key_id), indexKey: hex(k.tenant_index_key) }),
      allowedSuites: [suiteId],
      writeSuite: suiteId,
      indexes,
      onWarning: () => {},
    },
    // Spec §4.8: writing under a provisional suite is armed deliberately.
    { armProvisionalSuites: true },
  );
}

function ctxFrom(c: Record<string, string | null>): FieldContext {
  return {
    tableUuid: hex(c.table_uuid!),
    columnUuid: hex(c.column_uuid!),
    tenantId: c.tenant_id === null ? null : hex(c.tenant_id!),
    rowId: c.row_id === null ? null : hex(c.row_id!),
    purpose: c.purpose!,
  };
}

function commit(): string {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO, encoding: "utf-8" }).trim();
  } catch {
    return "unknown";
  }
}

const outFlag = process.argv.indexOf("--out");
if (outFlag === -1 || process.argv[outFlag + 1] === undefined) {
  console.error("usage: produce.ts --out <file>");
  process.exit(2);
}
const outPath = process.argv[outFlag + 1]!;

const corpus = JSON.parse(readFileSync(join(VECTORS, "cross", "corpus.json"), "utf-8")) as {
  suite_id: string;
  cases: { case: string; key_ref: string; context: Record<string, string | null>; plaintext: string }[];
  index_cases?: IndexCase[];
};
const keys = (JSON.parse(readFileSync(join(VECTORS, "keys", "test-keys.json"), "utf-8")) as { keys: Record<string, KeyEntry> }).keys;
const indexCases = corpus.index_cases ?? [];

// One client per key_ref, carrying every declaration that ref's index cases
// need. Deduplicated on the registry's own key (table + column + index_id) --
// the corpus asserts that two cases sharing one key share one declaration, so
// a duplicate here is the same object and a *conflict* would have failed
// generation rather than construction.
const declsFor = (ref: string): IndexDeclaration[] => {
  const seen = new Map<string, IndexDeclaration>();
  for (const c of indexCases.filter((x) => x.key_ref === ref)) {
    seen.set(`${c.context.table_uuid!}/${c.context.column_uuid!}/${c.declaration.index_id}`, declOf(c));
  }
  return [...seen.values()];
};
const clients = new Map(Object.entries(keys).map(([ref, k]) => [ref, clientFor(k, declsFor(ref))]));

const pkg = JSON.parse(readFileSync(join(REPO, "core", "typescript", "package.json"), "utf-8")) as { version: string };
const doc = {
  schema: indexCases.length > 0 ? "fieldseal-vectors/cross/v2" : "fieldseal-vectors/cross/v1",
  producer: {
    implementation: "typescript",
    version: pkg.version,
    commit: commit(),
    produced_at: new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00"),
  },
  suite_id: corpus.suite_id,
  index_cases: indexCases.map((c) => {
    const client = clients.get(c.key_ref)!;
    const ctx = ctxFrom(c.context);
    // The marker is a derivation with no plaintext: a bucketed column's
    // reserved index value, which an adapter derives for every value the
    // normalizer refuses. It goes through its own operation, not `blindIndex`.
    const index = c.value_marker === true
      ? client.unindexableMarker(ctx)
      : client.blindIndex(
          // Text as text, never its encoding (spec §7.1 / G16 part A): a
          // producer that encoded first would have collapsed two distinct
          // values into one before the core saw them, which is the false
          // match the text path exists to prevent. `value_bytes` is only for
          // an `identity` column, where the bytes *are* the value.
          c.value_text !== undefined ? c.value_text : hex(c.value_bytes!),
          ctx,
        );
    return {
      id: `cross/typescript/index/${c.case}`,
      key_ref: c.key_ref,
      declaration: c.declaration,
      context: c.context,
      ...(c.value_text !== undefined ? { value_text: c.value_text } : {}),
      ...(c.value_bytes !== undefined ? { value_bytes: c.value_bytes } : {}),
      ...(c.value_marker === true ? { value_marker: true } : {}),
      index: Buffer.from(index).toString("hex"),
    };
  }),
  cases: corpus.cases.map((c) => ({
    id: `cross/typescript/${c.case}`,
    key_ref: c.key_ref,
    context: c.context,
    plaintext: c.plaintext,
    envelope: Buffer.from(clients.get(c.key_ref)!.encrypt(hex(c.plaintext), ctxFrom(c.context))).toString("hex"),
  })),
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(doc, null, 1) + "\n");
console.error(
  `wrote ${outPath} (${doc.cases.length} cases, ${doc.index_cases.length} index cases, ` +
    `producer typescript@${doc.producer.commit.slice(0, 12)})`,
);
