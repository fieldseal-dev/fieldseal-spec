/**
 * The Prisma half of the scenario. One act per process invocation.
 *
 *     node scenario.ts <step>
 *
 * **The database is the only channel between the two stacks.** Nothing here
 * receives a value in memory from the Django half and nothing reads a file it
 * wrote: every claim is about bytes that went through Postgres. That is what
 * makes the demo an assertion rather than a picture of one, and it is why
 * each step is its own process.
 *
 * **Nothing asserts an exact ciphertext.** Every envelope carries a fresh
 * nonce and `msg_seed` (spec §3.1, §4.4), and the fixed-nonce affordance that
 * would make one reproducible is a test-mode-only facility an implementation
 * must never accept outside it. The assertions are structural: envelope
 * length, the 19-byte header two writers must share, the inequality of two
 * envelopes over one plaintext, the byte-equality of two blind indexes.
 *
 * **The `as never` casts on write payloads are a real limitation of the
 * release, not a demo shortcut.** An encrypted column is declared `Bytes`
 * because that is what holds the envelope, so Prisma generates `Uint8Array`
 * for it -- while the value a caller writes is a string. Every write of a
 * logical value to a `Bytes`-stored column is a type error against the
 * generated client. `storage: "base64"` avoids it at a ~33% storage cost
 * (spec §3.3); the adapter README records the typed-surface fix as a
 * follow-up rather than pretending it away.
 */

import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { PrismaPg } from "@prisma/adapter-pg";
import { StaticKeyProvider } from "@fieldseal/core";
import { FieldsealNotSupported, fieldsealExtension } from "@fieldseal/prisma";

import { fieldsealFieldMap } from "./generated/fieldseal-map.ts";
import { PrismaClient } from "./generated/prisma/client.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEMO = join(HERE, "..");
const REPO = join(DEMO, "..", "..");
const TRANSCRIPT = join(DEMO, "transcript");

/** Both stacks pass ids explicitly, so a row can be named across processes. */
const ADA = "018f5a10-0001-7000-8000-000000000001";
const GRACE = "018f5a10-0001-7000-8000-000000000002";
const SHARED_DJANGO = "018f5a10-0001-7000-8000-000000000005";
const SHARED_PRISMA = "018f5a10-0001-7000-8000-000000000006";

/** Spec §3.1: suite 0xFF01's fixed overhead, 1+2+16+32+12+16+32. */
const ENVELOPE_OVERHEAD = 111;
/** `fmt_ver` + `suite_id` + `key_id`: what two writers must agree on. */
const HEADER_LEN = 19;

/**
 * Key material by `key_ref`, from the same public file the cross-language
 * producers use. No key is embedded here, and that file carries its own
 * public-test-material banner -- so the banner travels with any copy-paste.
 */
const KEY_REF = "tenant-a-dek-v1";
const keyfile = JSON.parse(
  readFileSync(join(REPO, "vectors", "keys", "test-keys.json"), "utf8"),
) as { keys: Record<string, Record<string, string>> };
const key = keyfile.keys[KEY_REF];
if (key === undefined) throw new Error(`no key_ref ${KEY_REF} in test-keys.json`);
const H = (s: string) => Buffer.from(s, "hex");
const SUITE = Number.parseInt(key["suite_id"] ?? "", 16);
if (!Number.isInteger(SUITE)) {
  // `parseInt` returns NaN rather than throwing, and NaN would travel all the
  // way into `allowedSuites` and `writeSuite` before anything noticed -- the
  // failure would then name the suite policy rather than the key file.
  throw new Error(
    `key_ref ${KEY_REF} in test-keys.json has no usable suite_id ` +
      `(${JSON.stringify(key["suite_id"])}); it must be a hex literal such as "0xFF01".`,
  );
}

const DB_URL =
  process.env["DATABASE_URL"] ?? "postgresql://postgres:postgres@localhost:5432/fieldseal_demo";

interface Assertion {
  claim: string;
  ok: boolean;
  detail: string;
}

class Failed extends Error {}

/** One act: its narration, its assertions, and its transcript entry. */
class Act {
  readonly assertions: Assertion[] = [];
  readonly warnings: { kind: string; message: string }[] = [];
  readonly order: number;
  readonly step: string;
  readonly act: number;
  readonly title: string;
  readonly proves: string;

  // Fields assigned in the body rather than declared as constructor
  // parameters: a parameter property is not erasable TypeScript, and this
  // file is run by `node scenario.ts` under type stripping.
  constructor(order: number, step: string, act: number, title: string, proves: string) {
    this.order = order;
    this.step = step;
    this.act = act;
    this.title = title;
    this.proves = proves;
  }

  say(line = ""): void {
    process.stdout.write(`${line}\n`);
  }

  head(): void {
    this.say(`--- Act ${String(this.act)} * ${this.title} ` + "-".repeat(Math.max(0, 62 - this.title.length)));
    this.say(`    ${this.proves}`);
    this.say();
  }

  check(claim: string, ok: boolean, detail = ""): void {
    this.assertions.push({ claim, ok, detail });
    if (!ok) throw new Failed(`${claim} -- ${detail}`);
  }

  write(): void {
    mkdirSync(TRANSCRIPT, { recursive: true });
    const name = `${String(this.order).padStart(2, "0")}-prisma-${this.step}.json`;
    writeFileSync(
      join(TRANSCRIPT, name),
      `${JSON.stringify(
        {
          act: this.act,
          step: this.step,
          stack: "prisma",
          title: this.title,
          proves: this.proves,
          assertions: this.assertions,
          warnings: this.warnings,
        },
        null,
        1,
      )}\n`,
      "utf8",
    );
  }
}

/**
 * A base client and an extended one.
 *
 * The base client exists so a column can be read as the database holds it:
 * a read back through the extension would decrypt and prove nothing about
 * the bytes.
 *
 * The extension is registered last, which is what puts it closest to the
 * engine -- so every other extension would see plaintext rather than
 * envelopes. "Last" reading like "runs last" is exactly backwards.
 */
function clients(act: Act) {
  // The cast is the adapter test fixture's, for its reason: Prisma 7's
  // constructor options are generic over the client's own configuration, and
  // a driver adapter passed positionally does not narrow them.
  const base = new PrismaClient({
    adapter: new PrismaPg({ connectionString: DB_URL }),
  } as never) as unknown as PrismaClient;
  const prisma = base.$extends(
    fieldsealExtension({
      fieldMap: fieldsealFieldMap,
      keyProvider: new StaticKeyProvider({
        dek: H(key?.["tenant_dek"] ?? ""),
        indexKey: H(key?.["tenant_index_key"] ?? ""),
        keyId: H(key?.["key_id"] ?? ""),
      }),
      allowedSuites: [SUITE],
      writeSuite: SUITE,
      readMode: "strict",
      // Spec §4.8: the suite is provisional, so writing under it is an
      // affirmative act rather than something a copied config inherits.
      armProvisionalSuites: true,
      // Recorded rather than printed. The core warns that a
      // StaticKeyProvider is development-only, and `check_transcript.py`
      // asserts the warning is present in every Prisma act -- which turns
      // "this is not a production configuration" into a checked fact
      // instead of a sentence in a README.
      onWarning: (w) => act.warnings.push({ kind: w.kind, message: w.message }),
    }),
  );
  return { base, prisma };
}

/** The loose view: see the file header on why the casts are honest. */
type Loose = Record<string, Record<string, (a?: unknown) => Promise<any>>>;

/**
 * The only columns `raw()` will read.
 *
 * A column name cannot be a bound parameter, so it is interpolated into the
 * SQL below. Every call site passes a literal, which makes that safe *today*;
 * an allow-list makes it a property of the function instead, which is where
 * the guarantee would otherwise stop being true first.
 */
const RAW_COLUMNS = new Set(["email", "emailBidx", "note"]);

/** A column as the database holds it, with no adapter in the path. */
async function raw(base: PrismaClient, column: string, id: string): Promise<Buffer | null> {
  if (!RAW_COLUMNS.has(column)) {
    throw new Error(
      `raw() reads one of ${[...RAW_COLUMNS].join(", ")}; got ${JSON.stringify(column)}. ` +
        `The column name is interpolated into the SQL, so it is an allow-list rather ` +
        `than a parameter.`,
    );
  }
  const rows = await base.$queryRawUnsafe<{ v: Uint8Array | null }[]>(
    `SELECT "${column}" AS v FROM "Patient" WHERE "id" = $1::uuid`,
    id,
  );
  const v = rows[0]?.v;
  return v === null || v === undefined ? null : Buffer.from(v);
}

function showEnvelope(a: Act, label: string, envelope: Buffer, plaintext: string): void {
  a.say(`    ${label}`);
  a.say(
    `      envelope     ${String(envelope.length)} bytes = ${String(ENVELOPE_OVERHEAD)} fixed + ` +
      `${String(Buffer.from(plaintext, "utf8").length)} plaintext (spec §3.1)`,
  );
  a.say(`      header       ${envelope.subarray(0, HEADER_LEN).toString("hex")}`);
  a.say(
    `                   fmt_ver 0x01 | suite 0xFF01 | key_id ` +
      `${envelope.subarray(3, HEADER_LEN).toString("hex")}`,
  );
}

/**
 * Deterministic wrapping, so a refusal message is one shape every run.
 *
 * **This must stay identical to `scenario.py`'s `_wrap`,** including the
 * width and the tokenization: both halves of act 6 print wrapped refusal
 * messages into one golden narration, so a divergence here would fail
 * `run_scenario.py --check` for a reason that says nothing about either
 * adapter. `trim()` before splitting is what makes `/\s+/` match Python's
 * argument-less `str.split()`, which never yields an empty leading token.
 */
function wrap(text: string, width = 68): string[] {
  const out: string[] = [];
  let line = "";
  for (const word of text.trim().split(/\s+/)) {
    if (line !== "" && line.length + 1 + word.length > width) {
      out.push(line);
      line = word;
    } else {
      line = line === "" ? word : `${line} ${word}`;
    }
  }
  if (line !== "") out.push(line);
  return out;
}

// -- the acts ---------------------------------------------------------------

async function act2Read(a: Act, base: PrismaClient, prisma: Loose): Promise<void> {
  a.say(`    prisma.patient.findUnique({ where: { id: "${ADA}" } })`);
  a.say("      # the row Django wrote, in another process, in another language");
  a.say();
  const row = await prisma["patient"]?.["findUnique"]?.({ where: { id: ADA } });
  if (row === null || row === undefined) {
    a.check("the row Django wrote is present", false, "findUnique returned null");
    return;
  }
  a.say(`      mrn          ${JSON.stringify(row["mrn"])}   (plaintext column)`);
  a.say(`      email        ${JSON.stringify(row["email"])}   (decrypted from the envelope)`);
  a.say(`      note         ${JSON.stringify(row["note"])}`);
  a.say();

  const stored = await raw(base, "email", ADA);
  a.say(`      the same column, read with no adapter in the path:`);
  a.say(`        ${String(stored?.length ?? 0)} bytes of envelope, not "ada@example.com"`);
  a.say();

  a.check(
    "Prisma decrypts a row Django wrote -- the central claim, at the layer people deploy",
    row["email"] === "ada@example.com",
    JSON.stringify(row["email"]),
  );
  a.check("the unindexed encrypted column round-trips too", row["note"] === "peanut allergy", JSON.stringify(row["note"]));
  a.check("the plaintext column is untouched by either stack", row["mrn"] === "MRN-0001", JSON.stringify(row["mrn"]));
  a.check(
    "the stored column is an envelope, not the value: TypeScript decrypted what Python encrypted",
    stored !== null && !stored.includes(Buffer.from("ada@example.com", "utf8")),
    `${String(stored?.length ?? 0)} bytes`,
  );
}

async function act3Search(a: Act, prisma: Loose): Promise<void> {
  a.say(`    prisma.patient.findMany({ where: { email: "ada@example.com" } })`);
  a.say("      # rewritten onto \"emailBidx\", then re-verified (spec §7.5)");
  a.say();
  const rows = (await prisma["patient"]?.["findMany"]?.({
    where: { email: "ada@example.com" },
  })) as unknown as Record<string, unknown>[];
  a.say(`      ${String(rows.length)} row(s):`);
  for (const r of rows) a.say(`        ${String(r["id"])}  mrn=${JSON.stringify(r["mrn"])}`);
  a.say();
  a.say("      The predicate never reached the database as written: the suite");
  a.say("      is randomized, so comparing against ciphertext matches nothing.");
  a.say("      TypeScript derived the index value; Python wrote it.");
  a.say();

  a.check(
    "the blind index Python derived is derivable by TypeScript -- the failure that has no error message",
    rows.length === 1 && rows[0]?.["id"] === ADA,
    `${String(rows.length)} row(s)`,
  );
}

async function act4Write(a: Act, base: PrismaClient, prisma: Loose): Promise<void> {
  const email = "Grace@Example.COM";
  a.say(`    prisma.patient.create({ data: { id: "${GRACE}", mrn: "MRN-0002",`);
  a.say(`                                    email: "${email}", note: "left-handed" } })`);
  a.say("      # mixed case on purpose: the column's one equality is its");
  a.say("      # normalizer's (nfc-casefold-v1), and Django looks it up in lower case");
  a.say();
  await prisma["patient"]?.["create"]?.({
    data: { id: GRACE, mrn: "MRN-0002", email, note: "left-handed" },
  });

  const envelope = await raw(base, "email", GRACE);
  const bidx = await raw(base, "emailBidx", GRACE);
  if (envelope === null || bidx === null) {
    a.check("the row was written", false, "a column came back NULL");
    return;
  }
  showEnvelope(a, '"Patient"."email" now holds:', envelope, email);
  a.say(`      plaintext    "${email}" does not appear in the column`);
  a.say();
  a.say('    "Patient"."emailBidx" now holds:');
  a.say(`      blind index  ${String(bidx.length)} bytes = ${bidx.toString("hex")}  (15 bits, spec §7.4)`);
  a.say();

  a.check(
    "the value path encrypted: the column is an envelope of the right length",
    envelope.length === ENVELOPE_OVERHEAD + Buffer.from(email, "utf8").length,
    `${String(envelope.length)} bytes`,
  );
  a.check(
    "the plaintext is not a substring of the stored column",
    !envelope.includes(Buffer.from(email, "utf8")),
    "",
  );
  a.check("the blind index is ceil(15/8) = 2 bytes (spec §7.11)", bidx.length === 2, bidx.toString("hex"));
}

async function act5WriteShared(a: Act, base: PrismaClient, prisma: Loose): Promise<void> {
  const email = "mallory@example.com";
  a.say(`    prisma.patient.create({ data: { id: "${SHARED_PRISMA}", mrn: "MRN-0005-PR",`);
  a.say(`                                    email: "${email}" } })`);
  a.say("      # Django wrote the same address to a different row already.");
  a.say();
  await prisma["patient"]?.["create"]?.({
    data: { id: SHARED_PRISMA, mrn: "MRN-0005-PR", email },
  });
  const envelope = await raw(base, "email", SHARED_PRISMA);
  if (envelope === null) {
    a.check("Prisma wrote the shared-plaintext row", false, "the column came back NULL");
    return;
  }
  showEnvelope(a, "written:", envelope, email);
  a.say();
  a.say("      The comparison with Django's row is act 5's other half, and it");
  a.say("      is made through the database by a third process.");
  a.say();
  a.check(
    "Prisma wrote the shared-plaintext row",
    envelope.length === ENVELOPE_OVERHEAD + Buffer.from(email, "utf8").length,
    `${String(envelope.length)} bytes`,
  );
}

async function act6Refusals(a: Act, prisma: Loose): Promise<void> {
  a.say(`    prisma.patient.count({ where: { email: "ada@example.com" } })`);
  try {
    await prisma["patient"]?.["count"]?.({ where: { email: "ada@example.com" } });
    a.check("count() over an encrypted column is refused by the Prisma adapter", false, "it was served");
    return;
  } catch (e) {
    if (!(e instanceof FieldsealNotSupported)) throw e;
    a.say(`      -> ${e.constructor.name}:`);
    for (const line of wrap(e.message)) a.say(`         ${line}`);
    a.say();
    a.check(
      "count() over an encrypted column is refused, not approximated: the database computes the answer and only the answer comes back, so §7.5 re-verification has nothing to run on",
      true,
      e.constructor.name,
    );
  }

  a.say("      The Django adapter SERVES this call -- see act 6's other half.");
  a.say("      That is a real capability difference and a designed one: a");
  a.say("      Django manager can materialize the bucket and re-verify it; a");
  a.say("      Prisma extension is bound to the operation it was called for,");
  a.say("      and an operation whose result is a number cannot be turned");
  a.say("      into a row fetch.");
  a.say();

  a.say(`    prisma.patient.findMany({ where: { NOT: { email: "ada@example.com" } } })`);
  try {
    await prisma["patient"]?.["findMany"]?.({ where: { NOT: { email: "ada@example.com" } } });
    a.check("negation over an encrypted column is refused", false, "it was served");
  } catch (e) {
    if (!(e instanceof FieldsealNotSupported)) throw e;
    a.say(`      -> ${e.constructor.name}:`);
    for (const line of wrap(e.message)) a.say(`         ${line}`);
    a.say();
    a.check(
      "negation over an encrypted column is refused on both stacks (spec §10.2, G24): a superset can be narrowed to the answer, an exclusion cannot be widened back to it",
      true,
      e.constructor.name,
    );
  }
}

// -- driver -----------------------------------------------------------------

const STEPS: Record<string, [number, number, string, string]> = {
  read: [2, 2, "Prisma reads the row Django wrote", "the central claim: one row, two languages, one key"],
  search: [
    3,
    3,
    "Prisma searches by the encrypted address",
    "the index Python derived is derivable by TypeScript",
  ],
  write: [4, 4, "Prisma writes a patient", "the claim in the other direction starts here"],
  "write-shared": [7, 5, "Prisma writes the shared plaintext", "half of the act that compares two writers"],
  refusals: [10, 6, "Prisma refuses what it cannot re-verify", "adapters throw rather than degrade"],
};

async function main(): Promise<number> {
  const step = process.argv[2] ?? "";
  const spec = STEPS[step];
  if (spec === undefined) {
    process.stderr.write(`usage: node scenario.ts {${Object.keys(STEPS).join(",")}}\n`);
    return 2;
  }
  const a = new Act(spec[0], step, spec[1], spec[2], spec[3]);
  const { base, prisma } = clients(a);
  const loose = prisma as unknown as Loose;
  a.head();
  try {
    switch (step) {
      case "read":
        await act2Read(a, base, loose);
        break;
      case "search":
        await act3Search(a, loose);
        break;
      case "write":
        await act4Write(a, base, loose);
        break;
      case "write-shared":
        await act5WriteShared(a, base, loose);
        break;
      case "refusals":
        await act6Refusals(a, loose);
        break;
    }
  } catch (e) {
    a.write();
    process.stderr.write(`    FAILED: ${e instanceof Error ? e.message : String(e)}\n`);
    return 1;
  } finally {
    // Risk R3: `PrismaPg` holds pg sockets open, and Node will not exit while
    // it does -- the step would burn to the job timeout rather than failing.
    await base.$disconnect();
  }
  a.write();
  return 0;
}

process.exitCode = await main();
