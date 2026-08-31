/**
 * WS-C's Argon2id benchmark, second leg: a **real Prisma request path**.
 *
 *   npm run bench:argon2 -- --out <file>
 *
 * `docs/11` §2 does not ask whether a synchronous Argon2id is slow -- spec §7.3
 * already records the per-call cost. It asks whether the sync path is
 * "untenable in a real Prisma request path", and spec §11.1's justification
 * says what that means: a sync derivation "stalls *every* concurrent request in
 * the process". So this measures **the latency of a query that touches no
 * encrypted column at all**, while indexed lookups on another table run.
 *
 * The core-level leg (`core/typescript/tests/bench/argon2-eventloop.ts`)
 * establishes the mechanism with a `setImmediate` probe. This one establishes
 * that the mechanism survives the layer people actually deploy, which is the
 * criterion as written -- and it is the layer where the request being stalled
 * is a real query rather than a synthetic tick.
 *
 * **The fixture's indexes declare `hmac-sha512`**, deliberately: it is what the
 * §7.3 domain table recommends for an email column, and it costs microseconds.
 * This benchmark overrides one index to `argon2id` **in the field map only**,
 * in memory, so nothing about the committed schema changes. The stored index
 * values in the fixture database were derived under HMAC and will not match --
 * which is fine and is in fact the point: every lookup returns zero rows, so
 * what is measured is the derivation on the query path and not the row work
 * behind it.
 *
 * Not a CI job (`docs/14` §7), not committed output, and not the start of
 * `bench/` (`docs/07` §8 puts that in Phase 2). Decision evidence for one open
 * question; the result of record is a `docs/07` §7 entry.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { FieldMap } from "../../src/index.ts";
import { fieldsealFieldMap } from "../fixture/generated/fieldseal-map.ts";
import { loose, makeClient } from "../helpers.ts";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");

/** The fixture's map with `Patient.email`'s index switched to Argon2id. */
function argon2Map(): FieldMap {
  return {
    ...fieldsealFieldMap,
    models: fieldsealFieldMap.models.map((m) =>
      m.model !== "Patient"
        ? m
        : {
            ...m,
            indexes: (m.indexes ?? []).map((i) =>
              // No `argon2` block: absent means the spec §7.3 minima, which is
              // the parameter set the decision is about.
              i.source === "email" ? { ...i, idf: "argon2id" as const } : i,
            ),
          },
    ),
  };
}

interface Stats {
  n: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
}

function stats(xs: number[]): Stats {
  const s = [...xs].sort((a, b) => a - b);
  const q = (x: number): number => s[Math.min(s.length - 1, Math.floor(x * s.length))] ?? NaN;
  return { n: s.length, p50: q(0.5), p95: q(0.95), p99: q(0.99), max: s[s.length - 1] ?? NaN };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Class B: requests that touch no encrypted column, issued **open-loop**.
 *
 * Open-loop is not a detail. A closed-loop probe waits for its own previous
 * request, so when the process stalls it simply issues fewer requests and its
 * measured latency barely moves -- coordinated omission, and it would hide the
 * entire effect being measured. Firing on a fixed schedule regardless of
 * whether the last one came back is what makes the stall visible.
 */
function openLoopProbe(
  fn: () => Promise<unknown>,
  hz: number,
  stop: { done: boolean },
): { latencies: number[]; finished: Promise<void> } {
  const latencies: number[] = [];
  const inflight: Array<Promise<void>> = [];
  const finished = (async () => {
    const period = 1000 / hz;
    let next = Date.now();
    while (!stop.done) {
      next += period;
      const t = process.hrtime.bigint();
      inflight.push(
        fn()
          .then(() => {
            latencies.push(Number(process.hrtime.bigint() - t) / 1e6);
          })
          .catch(() => {
            /* a failed probe query is not a latency sample */
          }),
      );
      const wait = next - Date.now();
      if (wait > 0) await sleep(wait);
    }
    await Promise.all(inflight);
  })();
  return { latencies, finished };
}

async function main(): Promise<number> {
  const outFlag = process.argv.indexOf("--out");
  const outPath = outFlag === -1 ? undefined : process.argv[outFlag + 1];

  const { base, prisma } = makeClient({ fieldMap: argon2Map() });
  const lp = loose(prisma);

  // Class B: a plaintext-only table. `Referral` declares nothing encrypted, so
  // this query never enters the value path -- it is exactly the request that
  // "did not ask for an index" and should not pay for one.
  const classB = (): Promise<unknown> => base.referral.findMany({ take: 1 });
  // Class A: an equality on the Argon2id-indexed column. One derivation per
  // call, on the query path, through the extension.
  const classA = (i: number): Promise<unknown> =>
    lp["patient"]!["findMany"]!({ where: { email: `nobody-${String(i)}@example.com` } });

  await classB(); // warm the connection pool before anything is timed
  await classA(0);

  const results: Record<string, Stats> = {};
  const WINDOW = 3000;

  for (const concurrency of [0, 1, 4, 8]) {
    const stop = { done: false };
    const probe = openLoopProbe(classB, 20, stop);
    let issued = 0;
    const until = Date.now() + WINDOW;
    const load =
      concurrency === 0
        ? Promise.resolve()
        : Promise.all(
            [...Array(concurrency)].map(async () => {
              while (Date.now() < until) await classA(issued++);
            }),
          );
    await sleep(WINDOW);
    stop.done = true;
    await Promise.all([probe.finished, load]);
    const label = concurrency === 0 ? "unloaded" : `under-${String(concurrency)}`;
    results[label] = stats(probe.latencies);
    results[label] = { ...results[label]!, n: probe.latencies.length };
    console.log(
      `class B (no encrypted column), ${label.padEnd(9)} ` +
        `n=${String(results[label]!.n).padStart(3)} | p50 ${results[label]!.p50.toFixed(1).padStart(7)} ` +
        `p95 ${results[label]!.p95.toFixed(1).padStart(8)} p99 ${results[label]!.p99.toFixed(1).padStart(8)} ` +
        `max ${results[label]!.max.toFixed(1).padStart(8)} ms` +
        (concurrency > 0 ? `  (${String(issued)} indexed lookups)` : ""),
    );
  }

  await base.$disconnect();

  let commit = "unknown";
  try {
    commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO, encoding: "utf-8" }).trim();
  } catch {
    /* not a git checkout */
  }

  const report = {
    schema: "fieldseal-bench/argon2-request-path/v1",
    question:
      "docs/11 §2: is the synchronous blindIndex path untenable in a real Prisma request path?",
    commit,
    environment: {
      runtime: `Node ${process.versions.node}`,
      os: `${process.platform} ${process.arch}`,
      database: process.env["FIELDSEAL_TEST_DB"] === "postgres" ? "postgres" : "sqlite",
    },
    method:
      "Class B (findMany on a table with no encrypted column) issued open-loop at 20 Hz, " +
      "measured while N concurrent Class A queries (equality on an Argon2id-indexed encrypted " +
      "column, spec §7.3 minima) run. Open-loop deliberately: a closed-loop probe would issue " +
      "fewer requests during a stall and under-report it.",
    class_b_latency_ms: results,
  };

  if (outPath !== undefined) {
    mkdirSync(dirname(resolve(outPath)), { recursive: true });
    writeFileSync(outPath, JSON.stringify(report, null, 2) + "\n");
    console.error(`\nwrote ${outPath}`);
  }
  return 0;
}

process.exitCode = await main();
