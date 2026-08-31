/**
 * Test fixtures: a real Prisma client over a real SQLite file, extended with a
 * real fieldseal extension over real core operations.
 *
 * Nothing here injects determinism. `FIELDSEAL_TEST_MODE` is never armed, so
 * every write draws a fresh nonce and `msg_seed` from the CSPRNG exactly as a
 * deployment would (spec §4.4) -- which is what makes
 * `test_two_writes_of_one_value_differ` meaningful rather than tautological.
 */

import { PrismaBetterSqlite3 } from "@prisma/adapter-better-sqlite3";
import { PrismaPg } from "@prisma/adapter-pg";
import { StaticKeyProvider } from "@fieldseal/core";

import { fieldsealExtension, type FieldsealExtensionOptions } from "../src/index.ts";
import { PrismaClient } from "./fixture/generated/prisma/client.ts";
import { fieldsealFieldMap } from "./fixture/generated/fieldseal-map.ts";

const H = (s: string) => Buffer.from(s, "hex");

export const DEK = H("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
export const INDEX_KEY = H("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
export const KEY_ID = H("0102030405060708090a0b0c0d0e0f10");

export const SUITE = 0xff01;

/**
 * Which database the suite runs against.
 *
 * The house rule is "never treat one database backend as representative", and
 * it exists because Django's `bulk_update` builds a different expression tree
 * on Postgres than on SQLite. It weighs differently here -- this adapter builds
 * no SQL at all -- but the surface it does depend on is exactly the one that
 * differs: an encrypted column is `Bytes`, which is a SQLite `BLOB` and a
 * Postgres `bytea`, and a `storage: "base64"` column is text on both. That is
 * the round trip worth running twice.
 */
export type Backend = "sqlite" | "postgres";
export const BACKEND: Backend =
  process.env["FIELDSEAL_TEST_DB"] === "postgres" ? "postgres" : "sqlite";

export const DB_URL =
  BACKEND === "postgres"
    ? (process.env["DATABASE_URL"] ??
      "postgresql://postgres:postgres@localhost:5432/fieldseal_test")
    : "file:./tests/fixture/fixture.db";

/** A bound parameter, 1-based. SQLite takes `?`; Postgres takes `$n`. */
export function ph(n: number): string {
  return BACKEND === "postgres" ? `$${String(n)}` : "?";
}

/** The driver adapter for `BACKEND`. Prisma 7 takes one; the schema has no url. */
export function driverAdapter(): unknown {
  return BACKEND === "postgres"
    ? new PrismaPg({ connectionString: DB_URL })
    : new PrismaBetterSqlite3({ url: DB_URL });
}

export function keyProvider(): StaticKeyProvider {
  return new StaticKeyProvider({ dek: DEK, indexKey: INDEX_KEY, keyId: KEY_ID });
}

export type Extended = ReturnType<typeof makeClient>["prisma"];

export function makeClient(
  overrides: Partial<FieldsealExtensionOptions> = {},
  /**
   * Options for the *Prisma* client, not the extension. `omit` is the one that
   * matters: it is configured here and never appears in an operation's
   * arguments, which is why the §7.5 projection check has to run on the result.
   *
   * Cast back to the default `PrismaClient` so the helpers below still accept
   * it. That does lose the type-level effect of `omit` (the generated result
   * type would drop the column), which costs nothing here because every caller
   * goes through `loose()` anyway -- and the point of the option is a *runtime*
   * shape the extension cannot see.
   */
  clientOptions: Record<string, unknown> = {},
) {
  const base = new PrismaClient({
    adapter: driverAdapter(),
    ...clientOptions,
  } as never) as unknown as PrismaClient;
  const opts: FieldsealExtensionOptions = {
    fieldMap: fieldsealFieldMap,
    keyProvider: keyProvider(),
    allowedSuites: [SUITE],
    writeSuite: SUITE,
    armProvisionalSuites: true,
    // Person.legalName declares on_unindexable: "bucket", and docs/09 §7.2
    // gates that behind the same {reason, approvedBy, date} ceremony spec §7.6
    // requires for a cardinality override. Supplying it here is the ceremony,
    // in code, which is the whole point -- a schema comment is not where a
    // human approval belongs.
    unindexableOverride: [
      {
        model: "Person",
        field: "legalName",
        reason:
          "Fixture: exercises the bucket path. A legal name must stay findable, " +
          "and refusing a customer's own name is the worse failure.",
        approvedBy: "adapters/prisma test fixture",
        date: "2026-08-27",
      },
    ],
    // StaticKeyProvider warns unless test mode is armed; we deliberately do not
    // arm it, so the warning is expected and swallowed here rather than
    // silenced globally.
    onWarning: () => {},
    ...overrides,
  };
  const prisma = base.$extends(fieldsealExtension(opts)) as ReturnType<
    PrismaClient["$extends"]
  > &
    PrismaClient;
  return { base, prisma };
}

/**
 * The client with Prisma's generated types stepped around.
 *
 * **This is a real limitation of the release, not a test convenience.** An
 * encrypted column is declared `Bytes` because that is what holds the envelope,
 * so Prisma generates `Uint8Array` for it -- while the value a caller writes is
 * a string, an int, or whatever `as:` declares. Every write of a logical value
 * to a `Bytes`-stored column is therefore a type error against the generated
 * client, and callers must cast.
 *
 * There is a way to avoid it today, and the fixture demonstrates both sides:
 * a `storage: "base64"` column is a Prisma `String`, so `nickname: "Ada"`
 * typechecks naturally -- at the ~33% storage cost spec §3.3 documents.
 * `Patient.email` is the `Bytes` case and needs this.
 *
 * The README states the trade-off; a generator-emitted typed surface that fixes
 * it properly is recorded as a follow-up rather than pretended away.
 */
export type LooseRow = Record<string, any>;
export type LooseClient = Record<string, Record<string, (a?: unknown) => Promise<LooseRow>>>;

export function loose(client: unknown): LooseClient {
  return client as LooseClient;
}

/** Every table, emptied. Order matters: Visit and Referral FK onto Patient. */
export async function clearDb(base: PrismaClient): Promise<void> {
  await base.visit.deleteMany({});
  await base.referral.deleteMany({});
  await base.patient.deleteMany({});
  await base.tenantDoc.deleteMany({});
  await base.person.deleteMany({});
}

/**
 * Read a column as the database actually holds it, bypassing the extension.
 *
 * This is the only way to assert that the stored bytes are an envelope rather
 * than the plaintext -- a read back through the extension would decrypt and
 * prove nothing.
 */
export async function rawColumn(
  base: PrismaClient,
  table: string,
  column: string,
  id: string,
): Promise<unknown> {
  const rows = await base.$queryRawUnsafe<Array<Record<string, unknown>>>(
    `SELECT "${column}" AS v FROM "${table}" WHERE "id" = ${ph(1)}`,
    id,
  );
  return rows[0]?.["v"] ?? null;
}

/**
 * Write a column as the database holds it, bypassing the extension.
 *
 * The counterpart of `rawColumn`, and the only way to plant state the adapter
 * could not have produced: a forged index value, a legacy plaintext row, a
 * flipped tag byte. Centralised so the placeholder dialect lives in one place
 * rather than in every test that plants something.
 */
export async function setColumn(
  base: PrismaClient,
  table: string,
  column: string,
  id: string,
  value: unknown,
): Promise<void> {
  await base.$executeRawUnsafe(
    `UPDATE "${table}" SET "${column}" = ${ph(1)} WHERE "id" = ${ph(2)}`,
    value,
    id,
  );
}
