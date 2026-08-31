/**
 * Cross-implementation consumer (docs/08 §4.7, docs/14 §3).
 *
 * Decrypts every case of one or more producer files and compares plaintext
 * byte-exact -- the direction that tests the central claim. Exit status is
 * non-zero on any failed pair; a verdict file is written for the CI gate.
 *
 * Usage: node tests/cross/consume.ts <producer-file>... --verdict <file>
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Fieldseal } from "../../src/api.ts";
import type { FieldContext } from "../../src/context.ts";
import { FieldsealError } from "../../src/errors.ts";
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
  // Decrypt needs no §4.8 arming; strict mode so a non-envelope producer
  // value fails loudly instead of passing through.
  return new Fieldseal({
    keyProvider: new StaticKeyProvider({ dek: hex(k.tenant_dek), keyId: hex(k.key_id), indexKey: hex(k.tenant_index_key) }),
    allowedSuites: [suiteId],
    writeSuite: suiteId,
    onWarning: () => {},
  });
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

const argv = process.argv.slice(2);
const vFlag = argv.indexOf("--verdict");
if (vFlag === -1 || argv[vFlag + 1] === undefined || vFlag === 0) {
  console.error("usage: consume.ts <producer-file>... --verdict <file>");
  process.exit(2);
}
const verdictPath = argv[vFlag + 1]!;
const files = argv.filter((_, i) => i !== vFlag && i !== vFlag + 1);

const keys = (JSON.parse(readFileSync(join(VECTORS, "keys", "test-keys.json"), "utf-8")) as { keys: Record<string, KeyEntry> }).keys;
const clients = new Map(Object.entries(keys).map(([ref, k]) => [ref, clientFor(k)]));

/**
 * The producer-document schemas this consumer understands.
 *
 * **Read, not assumed.** Until 2026-08-31 neither consumer looked at
 * `doc.schema` at all: it wrote one into its own verdict and ignored the
 * producer's. Harmless with one schema, and the exact failure this family
 * exists to catch the moment there are two -- a consumer that did not
 * understand `cross/v2` would decrypt the envelopes, report `fail: 0`, and
 * never touch the index half. A green run that skipped the more valuable
 * assertion is worse than a red one.
 *
 * `v2` adds `index_cases` beside `cases`; `v1` documents stay valid and are
 * recorded as carrying no index half rather than counting as if they had one.
 */
const SCHEMAS = new Set(["fieldseal-vectors/cross/v1", "fieldseal-vectors/cross/v2"]);

interface Pair {
  id: string;
  producer: string;
  status: "pass" | "fail";
  reason?: string;
}

const pairs: Pair[] = [];
const producers: string[] = [];
for (const f of files) {
  const doc = JSON.parse(readFileSync(f, "utf-8")) as {
    schema?: string;
    producer: { implementation: string };
    cases: { id: string; key_ref: string; context: Record<string, string | null>; plaintext: string; envelope: string }[];
  };
  const producer = doc.producer.implementation;
  producers.push(producer);
  if (doc.schema === undefined || !SCHEMAS.has(doc.schema)) {
    // Fail closed. An unrecognised schema may carry assertions this consumer
    // cannot make, and silently checking only the half it understands is how a
    // matrix reports green on a claim nobody tested.
    pairs.push({
      id: `${producer}/document`,
      producer,
      status: "fail",
      reason: `unrecognised producer schema ${String(doc.schema)}; this consumer reads ${[...SCHEMAS].join(", ")}`,
    });
    continue;
  }
  for (const c of doc.cases) {
    try {
      const got = Buffer.from(clients.get(c.key_ref)!.decrypt(hex(c.envelope), ctxFrom(c.context))).toString("hex");
      if (got === c.plaintext) pairs.push({ id: c.id, producer, status: "pass" });
      else pairs.push({ id: c.id, producer, status: "fail", reason: "plaintext differs" });
    } catch (e) {
      const code = e instanceof FieldsealError ? e.code : String(e);
      pairs.push({ id: c.id, producer, status: "fail", reason: `decrypt raised ${code}` });
    }
  }
}

const npass = pairs.filter((p) => p.status === "pass").length;
const verdict = {
  schema: "fieldseal-conformance-cross/v1",
  consumer: "typescript",
  producers,
  pairs,
  summary: { pass: npass, fail: pairs.length - npass, skipped: 0 },
};
mkdirSync(dirname(verdictPath), { recursive: true });
writeFileSync(verdictPath, JSON.stringify(verdict, null, 1) + "\n");
for (const p of pairs) if (p.status !== "pass") console.error(`FAIL ${p.id} (producer ${p.producer}): ${p.reason}`);
console.error(`consumer typescript: ${JSON.stringify(verdict.summary)}`);
process.exit(verdict.summary.fail > 0 ? 1 : 0);
