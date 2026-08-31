/**
 * Cross-language producer: rows written by **Prisma**, read by any core.
 *
 * The core-level cross harness already proves that a value encrypted by one
 * core decrypts in another. What it cannot prove is that the bytes an **ORM
 * adapter** puts in a database column are those bytes -- because the decisions
 * between an application value and the stored column belong to the adapter and
 * to nothing the cores test:
 *
 * - **the codec.** `age: 45` is not self-evidently `b"45"`. This adapter
 *   chooses that rendering under the column's declared `as:` type, and a
 *   consumer in another language decodes whatever it chose. A core round trip
 *   is handed bytes and gives bytes back, so it never sees the decision. Prisma
 *   is the adapter where this matters most: the schema type is the *storage*
 *   type, so `as:` exists only here, and every one of its six values is
 *   exercised below rather than text alone.
 * - **the storage form.** `binary` stores raw envelope bytes; `base64` stores
 *   ASCII in a `String` column. A consumer handed the wrong one fails at the
 *   length gate with an error that points at the envelope rather than at the
 *   column.
 * - **context assembly.** `table_uuid` and `column_uuid` come from the
 *   generated field map, and the tenant from an `AsyncLocalStorage` -- not from
 *   a caller. A consumer that reconstructs them differently derives a different
 *   record key and sees `COMMITMENT_INVALID`: a decrypt-side error for a
 *   write-side configuration mismatch.
 *
 * So this writes rows through the **real extension** -- real `create()`,
 * runtime CSPRNG, no test-mode injection -- then reads the raw column back
 * through `$queryRawUnsafe` and emits the standard `fieldseal-vectors/cross/v1`
 * document. That schema is deliberate: **every existing consumer reads this
 * file unmodified**, so this adapter joins the N x N matrix as one more
 * producer rather than needing a bespoke checker.
 *
 * Key material is resolved by `key_ref` against `vectors/keys/test-keys.json`,
 * the same public file the core producers use, so no key is embedded here.
 *
 * Usage: node tests/cross/produce.ts --out <file>
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { PrismaBetterSqlite3 } from "@prisma/adapter-better-sqlite3";
import { PrismaPg } from "@prisma/adapter-pg";
import { StaticKeyProvider } from "@fieldseal/core";

import { fieldsealExtension, tenantScope } from "../../src/index.ts";
import { fieldsealFieldMap } from "../fixture/generated/fieldseal-map.ts";
import { PrismaClient } from "../fixture/generated/prisma/client.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const ADAPTER = resolve(HERE, "../..");
const REPO = resolve(ADAPTER, "../..");
const VECTORS = join(REPO, "vectors");

/**
 * The shared key this producer writes under. One is enough: what varies here is
 * the adapter's own decisions, not the key hierarchy, which the core producers
 * already cover across tenants.
 */
const KEY_REF = "tenant-a-dek-v1";

/** The tenant `TenantDoc.body` is written under -- the corpus's own default. */
const TENANT = "tenant-0001";

interface KeyEntry {
  suite_id: string;
  key_id: string;
  tenant_dek: string;
  tenant_index_key: string;
}

function hex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "hex"));
}

function commit(): string {
  if (process.env["GITHUB_SHA"]) return process.env["GITHUB_SHA"];
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO, encoding: "utf-8" }).trim();
  } catch {
    return "unknown";
  }
}

/** `table_uuid` / `column_uuid` as the field map declares them, hex, no dashes. */
function uuids(model: string, field: string): { table: string; column: string } {
  const m = fieldsealFieldMap.models.find((x) => x.model === model);
  const c = m?.encrypted?.find((e) => e.field === field);
  if (m?.tableUuid === undefined || m.tableUuid === null || c === undefined) {
    throw new Error(`cross/produce: ${model}.${field} is not declared in the field map`);
  }
  return { table: m.tableUuid.replace(/-/g, ""), column: c.columnUuid.replace(/-/g, "") };
}

function storageOf(model: string, field: string): "binary" | "base64" {
  const m = fieldsealFieldMap.models.find((x) => x.model === model);
  return m?.encrypted?.find((e) => e.field === field)?.storage ?? "binary";
}

interface Case {
  id: string;
  key_ref: string;
  context: {
    table_uuid: string;
    column_uuid: string;
    tenant_id: string | null;
    row_id: null;
    purpose: "encrypt";
  };
  plaintext: string;
  envelope: string;
}

async function main(): Promise<number> {
  const outFlag = process.argv.indexOf("--out");
  if (outFlag === -1 || process.argv[outFlag + 1] === undefined) {
    console.error("usage: produce.ts --out <file>");
    return 2;
  }
  const outPath = process.argv[outFlag + 1]!;

  const keys = (
    JSON.parse(readFileSync(join(VECTORS, "keys", "test-keys.json"), "utf-8")) as {
      keys: Record<string, KeyEntry>;
    }
  ).keys;
  const key = keys[KEY_REF];
  if (key === undefined) throw new Error(`cross/produce: no key ${KEY_REF} in test-keys.json`);
  const suiteId = parseInt(key.suite_id.slice(2), 16);

  // The producer runs on whichever backend the suite is running on: the bytes
  // in a `bytea` and the bytes in a `BLOB` are the same claim, and a leg that
  // only ever produced from SQLite would leave the other untested.
  const postgres = process.env["FIELDSEAL_TEST_DB"] === "postgres";
  const url = postgres
    ? (process.env["DATABASE_URL"] ??
      "postgresql://postgres:postgres@localhost:5432/fieldseal_test")
    : `file:${join(ADAPTER, "tests", "fixture", "fixture.db")}`;
  const base = new PrismaClient({
    adapter: postgres ? new PrismaPg({ connectionString: url }) : new PrismaBetterSqlite3({ url }),
  } as never) as unknown as PrismaClient;

  const prisma = base.$extends(
    fieldsealExtension({
      fieldMap: fieldsealFieldMap,
      keyProvider: new StaticKeyProvider({
        dek: hex(key.tenant_dek),
        indexKey: hex(key.tenant_index_key),
        keyId: hex(key.key_id),
      }),
      allowedSuites: [suiteId],
      writeSuite: suiteId,
      readMode: "strict",
      // Spec §4.8: writing under a provisional suite is an affirmative act here
      // as everywhere.
      armProvisionalSuites: true,
      unindexableOverride: [
        {
          model: "Person",
          field: "legalName",
          reason: "Cross producer: exercises the §7.2 bucket path on an indexed column.",
          approvedBy: "adapters/prisma cross producer",
          date: "2026-08-31",
        },
      ],
      onWarning: () => {},
    }),
  ) as unknown as Record<string, { create(a: unknown): Promise<Record<string, unknown>> }>;

  // Rows from a previous run or from the test suite were written under a
  // different key. They are not read here, but leaving them would make the
  // producer's own state depend on what ran before it.
  await base.visit.deleteMany({});
  await base.referral.deleteMany({});
  await base.patient.deleteMany({});
  await base.tenantDoc.deleteMany({});
  await base.person.deleteMany({});

  const cases: Case[] = [];

  /** Read the column as the database holds it, then undo the storage form. */
  async function envelopeOf(
    model: string,
    table: string,
    field: string,
    id: string,
  ): Promise<Uint8Array> {
    const rows = await base.$queryRawUnsafe<Array<Record<string, unknown>>>(
      `SELECT "${field}" AS v FROM "${table}" WHERE "id" = ${postgres ? "$1" : "?"}`,
      id,
    );
    const stored = rows[0]?.["v"];
    if (storageOf(model, field) === "base64") {
      if (typeof stored !== "string") {
        throw new Error(`cross/produce: ${model}.${field} is base64 but the column is not text`);
      }
      return new Uint8Array(Buffer.from(stored, "base64"));
    }
    if (!(stored instanceof Uint8Array)) {
      throw new Error(`cross/produce: ${model}.${field} is binary but the column is not bytes`);
    }
    return stored;
  }

  async function record(
    caseId: string,
    model: string,
    table: string,
    field: string,
    id: string,
    plaintext: Uint8Array,
    tenant: string | null,
  ): Promise<void> {
    const { table: tableUuid, column } = uuids(model, field);
    cases.push({
      id: `cross/prisma/${caseId}`,
      key_ref: KEY_REF,
      context: {
        table_uuid: tableUuid,
        column_uuid: column,
        tenant_id: tenant === null ? null : Buffer.from(tenant, "utf8").toString("hex"),
        row_id: null, // L3-row is not in v0 (docs/13 §8)
        purpose: "encrypt",
      },
      plaintext: Buffer.from(plaintext).toString("hex"),
      envelope: Buffer.from(await envelopeOf(model, table, field, id)).toString("hex"),
    });
  }

  const utf8 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "utf8"));

  // --- Patient: text, non-ASCII text, the empty string, and every `as:` type.
  const born = new Date("1815-12-10T11:22:33.000Z");
  const blob = new Uint8Array([0x00, 0x01, 0xfe, 0xff]);
  const p1 = await prisma["patient"]!.create({
    data: {
      email: "ada@example.com",
      note: "日本語とEmoji \u{1f510}",
      age: 45,
      nickname: "Ada",
      born,
      active: true,
      score: 1.5,
      blob,
      plainName: "Ada Lovelace",
    },
  });
  const p1id = p1["id"] as string;

  await record("text-email", "Patient", "Patient", "email", p1id, utf8("ada@example.com"), null);
  // A mis-set encoding survives an ASCII-only test; this one does not let it.
  await record(
    "text-non-ascii",
    "Patient",
    "Patient",
    "note",
    p1id,
    utf8("日本語とEmoji \u{1f510}"),
    null,
  );
  // **The adapter decides these renderings.** A consumer that expected a
  // platform integer encoding, or a locale-aware date, would decrypt
  // successfully and read the wrong value -- which is the failure no core round
  // trip can catch and this file exists to pin.
  await record("as-int", "Patient", "Patient", "age", p1id, utf8("45"), null);
  await record("as-datetime", "Patient", "Patient", "born", p1id, utf8(born.toISOString()), null);
  await record("as-boolean", "Patient", "Patient", "active", p1id, utf8("true"), null);
  await record("as-float", "Patient", "Patient", "score", p1id, utf8("1.5"), null);
  await record("as-bytes", "Patient", "Patient", "blob", p1id, blob, null);
  // A `String` column holding base64 ASCII rather than a `Bytes` column holding
  // the envelope: the same envelope, a different column type, and the one
  // storage form a consumer must decode before it can parse anything.
  await record("storage-base64", "Patient", "Patient", "nickname", p1id, utf8("Ada"), null);

  // The empty string, which is a value rather than an absence.
  const p2 = await prisma["patient"]!.create({
    data: { email: "empty@example.com", note: "", age: 1, plainName: "Empty" },
  });
  await record("text-empty", "Patient", "Patient", "note", p2["id"] as string, utf8(""), null);

  // --- A tenant-bound column: the tenant reaches the context through an
  //     AsyncLocalStorage (docs/13 §5), so a consumer must be told which one.
  //     `await` inside the scope: a Prisma client method dispatches nothing
  //     until something calls `.then`.
  const doc = await tenantScope(TENANT, async () =>
    prisma["tenantDoc"]!.create({ data: { body: "tenant-scoped body" } }),
  );
  await record(
    "tenant-bound",
    "TenantDoc",
    "TenantDoc",
    "body",
    doc["id"] as string,
    utf8("tenant-scoped body"),
    TENANT,
  );

  // --- An indexed column, to assert that being indexed changes nothing about
  //     the envelope beside it.
  const person = await prisma["person"]!.create({ data: { legalName: "Ada Lovelace" } });
  await record(
    "indexed-column",
    "Person",
    "Person",
    "legalName",
    person["id"] as string,
    utf8("Ada Lovelace"),
    null,
  );

  await base.$disconnect();

  const pkg = JSON.parse(readFileSync(join(ADAPTER, "package.json"), "utf-8")) as {
    version: string;
  };
  const out = {
    schema: "fieldseal-vectors/cross/v1",
    producer: {
      implementation: "prisma",
      version: pkg.version,
      commit: commit(),
      produced_at: new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00"),
    },
    suite_id: key.suite_id,
    cases,
  };

  mkdirSync(dirname(resolve(outPath)), { recursive: true });
  writeFileSync(outPath, JSON.stringify(out, null, 1) + "\n");
  console.error(
    `wrote ${outPath} (${out.cases.length} cases, producer prisma@${out.producer.commit.slice(0, 12)})`,
  );
  return 0;
}

process.exitCode = await main();
