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

function clientFor(k: KeyEntry): Fieldseal {
  const suiteId = parseInt(k.suite_id.slice(2), 16);
  return new Fieldseal(
    {
      keyProvider: new StaticKeyProvider({ dek: hex(k.tenant_dek), keyId: hex(k.key_id), indexKey: hex(k.tenant_index_key) }),
      allowedSuites: [suiteId],
      writeSuite: suiteId,
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
};
const keys = (JSON.parse(readFileSync(join(VECTORS, "keys", "test-keys.json"), "utf-8")) as { keys: Record<string, KeyEntry> }).keys;
const clients = new Map(Object.entries(keys).map(([ref, k]) => [ref, clientFor(k)]));

const pkg = JSON.parse(readFileSync(join(REPO, "core", "typescript", "package.json"), "utf-8")) as { version: string };
const doc = {
  schema: "fieldseal-vectors/cross/v1",
  producer: {
    implementation: "typescript",
    version: pkg.version,
    commit: commit(),
    produced_at: new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00"),
  },
  suite_id: corpus.suite_id,
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
console.error(`wrote ${outPath} (${doc.cases.length} cases, producer typescript@${doc.producer.commit.slice(0, 12)})`);
