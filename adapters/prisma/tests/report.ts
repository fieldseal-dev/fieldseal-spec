/**
 * The `docs/14` §4 conformance report for this adapter.
 *
 *   npm run --silent report > conformance-prisma-adapter.json
 *
 * It runs the suite itself unless handed a previous run with `--results`, which
 * is how CI reuses the run it already paid for. It runs the suite *itself*
 * rather than being chained after `vitest` in the npm script because vitest's
 * JSON reporter announces its output file on **stdout**, which would land in
 * the middle of the report; silencing that portably from an npm script means
 * `>/dev/null` or `>NUL` depending on the platform's shell.
 *
 * An adapter's report is not a core's, and the differences are the interesting
 * part:
 *
 * - **It runs no vector families.** This package contains no cryptography
 *   (AD-1, spec §11.3), so `results` is empty and `L0` is not claimed. The
 *   suite is exercised by `@fieldseal/core`, whose own report carries the L0
 *   claim and the six `pinned_decisions` keys `docs/14` §4 obliges a core to
 *   declare. Recorded in `harness_notes` rather than left to be noticed.
 * - **Its evidence is the `coverage_matrix`**, which `docs/14` §4 requires an
 *   adapter to attach "mirroring their README table so the claim and the docs
 *   cannot drift apart". This generator takes that literally: the block is
 *   **parsed out of `README.md`** and each row's status is the status of the
 *   tests that row names, read from the run. So the README is the source, not a
 *   description of one, and the two cannot disagree.
 * - **A row that names a test which does not exist fails the report.** That is
 *   the anti-drift mechanism doing its job: a renamed or deleted test leaves a
 *   README row asserting something nothing verifies, which is exactly the
 *   quiet decay the block exists to prevent.
 *
 * Exit status is 1 if any matrix row failed, any named test is missing, or any
 * row claiming behaviour names no test at all -- the same condition that denies
 * a level claim, so CI turns red on it.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ADAPTER = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = resolve(ADAPTER, "../..");

/** A backtick escaped inside a README table cell, parked while spans are cut. */
const ESCAPED_BACKTICK = "\u0000";

type Behaviour = "served" | "caveat" | "refused" | "absent";
type RowStatus = "pass" | "fail" | "not-implemented" | "unverified";

interface MatrixRow {
  path: string;
  behaviour: Behaviour;
  claim: string;
  tests: string[];
  status: RowStatus;
}

interface Assertion {
  title: string;
  fullName: string;
  status: string;
}

function gitCommit(): string {
  if (process.env["GITHUB_SHA"]) return process.env["GITHUB_SHA"];
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO, encoding: "utf-8" }).trim();
  } catch {
    return "unknown";
  }
}

/** The `## Coverage matrix` table, as rows. */
function readMatrix(): Array<{ path: string; claim: string; testCell: string }> {
  const md = readFileSync(join(ADAPTER, "README.md"), "utf-8");
  const start = md.indexOf("## Coverage matrix");
  if (start === -1) throw new Error("report: README has no `## Coverage matrix` section");
  const body = md.slice(start).split("### Why refusals")[0]!;
  const lines = body.split(/\r?\n/).filter((l) => l.startsWith("|"));
  // Drop the header row and its separator.
  return lines.slice(2).flatMap((line) => {
    const cells = line.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
    if (cells.length < 3) return [];
    return [{ path: cells[0]!, claim: cells[1]!, testCell: cells[2]! }];
  });
}

/**
 * The test names a matrix row cites.
 *
 * Backtick-quoted spans, minus file references (`helpers.ts`) and minus a
 * trailing ellipsis, which the README uses to keep long titles readable. What
 * remains is a prefix, which is how it is matched.
 */
function testPatterns(cell: string): string[] {
  const parked = cell.replaceAll("\\`", ESCAPED_BACKTICK);
  const out: string[] = [];
  for (const m of parked.matchAll(/`([^`]*)`/g)) {
    const name = m[1]!.replaceAll(ESCAPED_BACKTICK, "`").trim();
    if (name.endsWith(".ts")) continue; // a file, not a test
    out.push(name.replace(/…$/, "").trim());
  }
  return out;
}

function behaviourOf(claim: string): Behaviour {
  if (claim.startsWith("✅")) return "served";
  if (claim.startsWith("⚠️")) return "caveat";
  if (claim.startsWith("🛑")) return "refused";
  if (claim.startsWith("❌")) return "absent";
  throw new Error(`report: a coverage-matrix row does not start with a legend symbol: ${claim}`);
}

/** Run the suite, keeping vitest's own stdout out of the report. */
function runSuite(): string {
  const out = join(ADAPTER, ".vitest-results.json");
  execFileSync(
    process.execPath,
    [
      join(ADAPTER, "node_modules", "vitest", "vitest.mjs"),
      "run",
      "--reporter=json",
      `--outputFile=${out}`,
    ],
    { cwd: ADAPTER, stdio: ["ignore", "ignore", "inherit"] },
  );
  return out;
}

function main(): number {
  const flag = process.argv.indexOf("--results");
  if (flag !== -1 && process.argv[flag + 1] === undefined) {
    console.error("usage: report.ts [--results <vitest-json>]");
    return 2;
  }
  const resultsPath = flag === -1 ? runSuite() : process.argv[flag + 1]!;
  const run = JSON.parse(readFileSync(resultsPath, "utf-8")) as {
    numTotalTests: number;
    numPassedTests: number;
    numFailedTests: number;
    numPendingTests: number;
    testResults: Array<{ assertionResults: Assertion[] }>;
  };
  const assertions = run.testResults.flatMap((f) => f.assertionResults);

  const problems: string[] = [];
  const rows: MatrixRow[] = readMatrix().map(({ path, claim, testCell }) => {
    const behaviour = behaviourOf(claim);
    const patterns = testPatterns(testCell);
    const matched: Assertion[] = [];
    for (const pattern of patterns) {
      const hits = assertions.filter(
        (a) => a.title.startsWith(pattern) || a.fullName.includes(pattern),
      );
      if (hits.length === 0) {
        problems.push(`row "${path}" names a test that does not exist: "${pattern}"`);
        continue;
      }
      matched.push(...hits);
    }
    let status: RowStatus;
    if (behaviour === "absent") {
      status = "not-implemented";
    } else if (patterns.length === 0) {
      // A row that claims behaviour and cites nothing is a claim with no
      // evidence, which is worse than an honest ❌.
      status = "unverified";
      problems.push(`row "${path}" claims ${behaviour} behaviour but names no test`);
    } else if (matched.some((a) => a.status !== "passed")) {
      status = "fail";
    } else {
      status = "pass";
    }
    return { path, behaviour, claim, tests: patterns, status };
  });

  const counts = (s: RowStatus): number => rows.filter((r) => r.status === s).length;
  const pkg = JSON.parse(readFileSync(join(ADAPTER, "package.json"), "utf-8")) as {
    version: string;
  };
  const manifest = JSON.parse(
    readFileSync(join(REPO, "vectors", "MANIFEST.json"), "utf-8"),
  ) as { vector_suite_version: string; spec_version: string };

  const failed = problems.length > 0 || counts("fail") > 0 || run.numFailedTests > 0;

  const report = {
    schema: "fieldseal-conformance/v1",
    implementation: {
      name: "prisma-adapter",
      version: pkg.version,
      commit: gitCommit(),
      language: "typescript",
    },
    vector_suite_version: manifest.vector_suite_version,
    spec_version: manifest.spec_version,
    // L0 belongs to the core beneath this package; see harness_notes. L2(a) is
    // an explicit index property, which this adapter deliberately does not
    // offer -- index siblings are stripped from results and refused as filter
    // targets. L3 is a documented side channel that spec §10.1 marks partial
    // for Prisma, and a boolean cannot say ⚠️, so it is recorded false rather
    // than claimed.
    claimed_levels: {
      L0: false,
      L1: !failed,
      "L2(a)": false,
      "L2(b)": !failed,
      L3: false,
      "L3-row": false,
      L4: !failed,
    },
    suites_supported: ["0xFF01"],
    provisional_suites: true,
    environment: {
      runtime: `Node ${process.versions.node}`,
      os: `${process.platform} ${process.arch}`,
      // AD-1: no cryptography in this package. The backend is the core's, and
      // is recorded because FIPS conversations turn on it (PRD CL-9).
      crypto_backend: `via @fieldseal/core on OpenSSL ${process.versions.openssl}`,
      unicode_platform: `ICU ${process.versions.icu} / Unicode ${process.versions.unicode} (not used for nfc-casefold-v1)`,
      unicode_tables: "via @fieldseal/core (vendored UCD; see that core's report)",
      database:
        process.env["FIELDSEAL_TEST_DB"] === "postgres"
          ? "PostgreSQL (@prisma/adapter-pg driver adapter)"
          : "SQLite (@prisma/adapter-better-sqlite3 driver adapter)",
      orm: `Prisma ${prismaVersion()}`,
    },
    pinned_decisions: {
      "codec-renderings":
        "spec §3.6, all eight logical types (string, bytes, int, decimal, float, boolean, date, datetime), " +
        "pinned by the codec/ family in MANIFEST.adapter_files and run by tests/codec-vectors.test.ts, so a " +
        "failing rendering fails this report's L1. JavaScript conventions §3.6 states: decimal read back as its " +
        "canonical string, date as a Date at UTC midnight, sub-millisecond datetimes refused on read. " +
        "The cross-language producer (cross/prisma/as-*) carries six of the types across languages.",
      "storage-forms":
        'binary (a Bytes column holds the envelope) and base64 (a String column holds its base64, ~33% overhead, spec §3.3). ' +
        "The cross producer emits the decoded envelope for both.",
      "l2-verifiable-sites":
        "Measured against Prisma 7.10.0: the top-level `where` of findMany, and a relation `where` " +
        "under include/select. Everywhere else the database answers before spec §7.5 can run and " +
        "the shape is refused -- so this adapter's L2 is narrower than Django's (no served " +
        "count/first/get), which docs/13 §6 states rather than implying parity.",
      "l4-warm-policy":
        "KEY_UNAVAILABLE -> await keyProvider.warm(the contexts this operation built) -> run the " +
        "pass again, over a journal-rolled-back tree. No cache-membership probe. A further cycle " +
        "runs only if the next attempt needs a context no cycle warmed (strict progress, accounted " +
        "per pass -- the write and read passes each keep their own ledger, so an eviction between " +
        "them is retried rather than misread as an unproductive warm); a miss " +
        "on a just-warmed context is raised. Off when the provider has no warm, or " +
        "warmOnKeyMiss: false.",
      "adapter-error-codes":
        "FieldsealNotSupported reports code INVALID_ARGUMENT and FieldsealConfigurationError " +
        "reports CONFIGURATION_ERROR, because the TypeScript core's ErrorCode is a closed union " +
        "with no adapter member. The Django adapter inherits the Python core's generic " +
        "FIELDSEAL_ERROR, so the same refusal reports a different code in the two adapters. " +
        "Discriminate on the class or the name, never on code.",
    },
    harness_notes: [
      "This package runs no vector families and claims no L0: it contains no cryptography (AD-1, " +
        "spec §11.3). The families, and the six pinned_decisions keys docs/14 §4 obliges a core to " +
        "carry, belong to @fieldseal/core's own report. The keys above are this adapter's own, " +
        "which docs/14 §4 permits.",
      "coverage_matrix is parsed out of README.md and each row's status is the status of the tests " +
        "that row names, so the block and the documentation cannot drift apart. A row naming a " +
        "test that does not exist fails this report.",
      "L3 (tenant binding) works through an AsyncLocalStorage or a callback -- documented side " +
        "channels that spec §10.1 marks ⚠️ partial for Prisma. claimed_levels is boolean and cannot " +
        "say partial, so it records false.",
      "The suite runs against SQLite and PostgreSQL, as separate CI legs, and this report " +
        "describes the leg that produced it (environment.database). This adapter builds no SQL, " +
        "so the backend-sensitive surface is the Bytes/base64 column type -- a BLOB on one and a " +
        "bytea on the other -- rather than the predicate.",
    ],
    results: [],
    held_out: [],
    out_of_band: [],
    async_companions: false,
    coverage_matrix: {
      source: "adapters/prisma/README.md#coverage-matrix",
      rows,
      summary: {
        rows: rows.length,
        pass: counts("pass"),
        fail: counts("fail"),
        not_implemented: counts("not-implemented"),
        unverified: counts("unverified"),
        tests_named: rows.reduce((n, r) => n + r.tests.length, 0),
      },
    },
    suite: {
      total: run.numTotalTests,
      passed: run.numPassedTests,
      failed: run.numFailedTests,
      pending: run.numPendingTests,
    },
    summary: {
      pass: run.numPassedTests,
      fail: run.numFailedTests + counts("fail") + problems.length,
      skipped: run.numPendingTests,
      held_out: 0,
    },
  };

  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  for (const p of problems) console.error(`coverage matrix: ${p}`);
  return failed ? 1 : 0;
}

function prismaVersion(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(join(ADAPTER, "node_modules", "@prisma", "client", "package.json"), "utf-8"),
    ) as { version: string };
    return pkg.version;
  } catch {
    return "unknown";
  }
}

process.exitCode = main();
