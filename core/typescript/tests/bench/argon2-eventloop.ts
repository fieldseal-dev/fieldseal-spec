/**
 * WS-C's Argon2id benchmark: the evidence `docs/11` §2 named, and nothing else.
 *
 *   npm run bench:argon2 -- --out <file>
 *
 * **What is being decided.** `docs/11` §2 leaves `blindIndexAsync` "permitted,
 * not yet decided" and pre-commits three outcomes, all turning on one
 * measurement: whether the synchronous path is untenable in a real request
 * path. Spec §11.1's own justification says why that is the question -- a sync
 * Argon2id "stalls *every* concurrent request in the process", not just the one
 * that asked for an index. So the thing to measure is **what happens to work
 * that never asked for an index** while indexes are being derived.
 *
 * **What is deliberately not being built.** `docs/07` §8 puts `bench/`
 * methodology in Phase 2 (PRD DO-4), and `docs/14` §7 forbids making a
 * benchmark a CI gate -- "CI machines produce noise". This is decision
 * evidence for one open question, so it lives beside the core it decides
 * about, writes a machine-specific artifact that is never committed, and is
 * wired into no workflow. The result of record is a `docs/07` §7 entry.
 *
 * ---
 *
 * ## The instrument, and why the obvious one is wrong
 *
 * `perf_hooks.monitorEventLoopDelay` is the natural choice and it **cannot see
 * this**. It is now recorded on every run beside the real measurement, so the
 * claim is checkable rather than asserted, and both shapes of its failure have
 * been observed on Node 24.16 / Windows: a 428 ms block reported
 * `count = 3, max = 15.84 ms` (27x too small, and equal to that platform's
 * timer granularity), and an 893 ms block reported **`count = 0, max = 0`**.
 * A histogram of delays *between samples* cannot report a stall during which
 * no sample was taken -- so it either says nothing or says something
 * comfortable, and never says what happened. Believing either would have
 * concluded that the sync path is fine.
 *
 * `setInterval` fails for a related reason: on Windows it cannot fire faster
 * than ~15.6 ms, so "ticks per elapsed millisecond" measures the clock rather
 * than the loop. An idle 5 ms interval measured 15.5 ms gaps here.
 *
 * So the instrument is **`setImmediate` chaining**: it fires once per event-loop
 * turn, is not timer-based, and therefore has no granularity floor. An idle loop
 * turns ~860 000 times in 900 ms with a max gap under 1 ms. A starved one turns
 * **zero** times, which is a number no histogram will give you.
 *
 * Every configuration is measured against its own unloaded baseline, because
 * an absolute turn count means nothing across machines.
 */

import { argon2, argon2Sync } from "node:crypto";
import { readFile } from "node:fs/promises";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../../../..");

/** Spec §7.3's pinned invocation, at the minima a deployment MAY raise from. */
const MINIMA = { passes: 3, memory: 32768, parallelism: 1, tagLength: 64 } as const;

interface Params {
  readonly passes: number;
  readonly memory: number;
  readonly parallelism: number;
  readonly tagLength: number;
}

function syncOnce(p: Params): void {
  argon2Sync("argon2id", { message: Buffer.alloc(16), nonce: Buffer.alloc(16), ...p });
}

function asyncOnce(p: Params): Promise<void> {
  return new Promise((res, rej) =>
    argon2("argon2id", { message: Buffer.alloc(16), nonce: Buffer.alloc(16), ...p }, (e) =>
      e ? rej(e) : res(),
    ),
  );
}

// ---------------------------------------------------------------------------
// The event-loop probe.

interface LoopResult {
  wallMs: number;
  turns: number;
  gapP50: number | null;
  gapP99: number | null;
  gapMax: number | null;
  /**
   * What `perf_hooks.monitorEventLoopDelay` says about the same window.
   *
   * Recorded **beside** the real measurement rather than instead of it, so the
   * claim that this instrument cannot see a full stall is testable on every
   * machine the benchmark runs on instead of resting on one. On the first
   * Windows run it reported `count = 3, max = 15.84 ms` for a 428 ms block --
   * 27x too small, and suspiciously equal to that platform's timer
   * granularity, which is exactly why it should not be asserted from one
   * platform.
   */
  monitorCount: number;
  monitorMaxMs: number;
}

/**
 * Run `work` while counting event-loop turns.
 *
 * `setImmediate` re-arms itself every turn, so the count is the number of
 * times the loop got to run and each gap is how long it was held. Zero turns
 * is the signal that matters and it is a real outcome, not a failure of the
 * probe.
 */
async function withLoopProbe(work: () => Promise<void>): Promise<LoopResult> {
  const gaps: number[] = [];
  const monitor = monitorEventLoopDelay({ resolution: 1 });
  let stop = false;
  let last = process.hrtime.bigint();
  const turn = (): void => {
    const now = process.hrtime.bigint();
    gaps.push(Number(now - last) / 1e6);
    last = now;
    if (!stop) setImmediate(turn);
  };
  setImmediate(turn);
  await sleep(50); // let the loop settle before the window opens
  gaps.length = 0;
  monitor.enable();
  last = process.hrtime.bigint();

  const t = process.hrtime.bigint();
  await work();
  const wallMs = Number(process.hrtime.bigint() - t) / 1e6;
  monitor.disable();
  stop = true;
  await sleep(5);

  gaps.sort((a, b) => a - b);
  const q = (x: number): number | null =>
    gaps.length === 0 ? null : gaps[Math.min(gaps.length - 1, Math.floor(x * gaps.length))]!;
  return {
    wallMs,
    turns: gaps.length,
    gapP50: q(0.5),
    gapP99: q(0.99),
    gapMax: gaps.length === 0 ? null : gaps[gaps.length - 1]!,
    monitorCount: monitor.count,
    monitorMaxMs: monitor.max / 1e6,
  };
}

// ---------------------------------------------------------------------------
// The threadpool probe.

/**
 * Latency of trivial `fs` work while `concurrency` derivations run.
 *
 * This is the line item that keeps the async recommendation honest. The async
 * form does not make the cost vanish; it moves it off the event loop and onto
 * the **libuv threadpool**, which `fs`, `dns` and `zlib` also use. Relocating a
 * stall is not the same as removing one, and an async companion that starved
 * every file read in the process would not be an improvement.
 */
async function threadpoolProbe(
  p: Params,
  concurrency: number,
  windowMs: number,
): Promise<{ samples: number; p50: number | null; p99: number | null; max: number | null }> {
  const lat: number[] = [];
  const inflight: Array<Promise<void>> = [];
  let stop = false;
  // **Open-loop**, at a fixed 100 Hz. The first version of this probe awaited
  // each read before issuing the next, which is coordinated omission -- the
  // same trap this file's Class B design correctly avoids and this probe fell
  // into. Under saturation it issued fewer reads exactly when they were
  // slowest, so the loaded cases were scored from a handful of samples (2, on
  // the first Windows run) and their percentiles meant nothing. Found by
  // running the benchmark on a second machine and noticing the sample counts
  // collapse precisely where the latency was worst.
  const probe = (async (): Promise<void> => {
    const period = 10;
    let next = Date.now();
    while (!stop) {
      next += period;
      const t = process.hrtime.bigint();
      inflight.push(
        readFile(fileURLToPath(import.meta.url))
          .then(() => {
            lat.push(Number(process.hrtime.bigint() - t) / 1e6);
          })
          .catch(() => {
            /* the file is only a payload; a read error is not a sample */
          }),
      );
      const wait = next - Date.now();
      if (wait > 0) await sleep(wait);
    }
    await Promise.all(inflight);
  })();
  const until = Date.now() + windowMs;
  const load =
    concurrency === 0
      ? Promise.resolve()
      : Promise.all(
          [...Array(concurrency)].map(async () => {
            while (Date.now() < until) await asyncOnce(p);
          }),
        );
  await sleep(windowMs);
  stop = true;
  await Promise.all([probe, load]);
  lat.sort((a, b) => a - b);
  const q = (x: number): number | null =>
    lat.length === 0 ? null : lat[Math.min(lat.length - 1, Math.floor(x * lat.length))]!;
  return { samples: lat.length, p50: q(0.5), p99: q(0.99), max: lat.length === 0 ? null : lat[lat.length - 1]! };
}

// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function commit(): string {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO, encoding: "utf-8" }).trim();
  } catch {
    return "unknown";
  }
}

async function perCallCost(p: Params, n: number): Promise<{ sync: number; async: number }> {
  syncOnce(p); // warm the allocator; the first call is not representative
  await asyncOnce(p);
  let t = process.hrtime.bigint();
  for (let i = 0; i < n; i++) syncOnce(p);
  const sync = Number(process.hrtime.bigint() - t) / 1e6 / n;
  t = process.hrtime.bigint();
  for (let i = 0; i < n; i++) await asyncOnce(p);
  const async_ = Number(process.hrtime.bigint() - t) / 1e6 / n;
  return { sync, async: async_ };
}

async function main(): Promise<number> {
  const outFlag = process.argv.indexOf("--out");
  const outPath = outFlag === -1 ? undefined : process.argv[outFlag + 1];
  const N = 20;

  const cost = await perCallCost(MINIMA, 5);

  // The three configurations, each against its own idle baseline.
  const idle = await withLoopProbe(async () => {
    await sleep(Math.round(cost.sync * N));
  });
  const syncSerial = await withLoopProbe(async () => {
    for (let i = 0; i < N; i++) syncOnce(MINIMA);
  });
  const asyncSerial = await withLoopProbe(async () => {
    for (let i = 0; i < N; i++) await asyncOnce(MINIMA);
  });
  const asyncConcurrent = await withLoopProbe(async () => {
    let left = N;
    await Promise.all(
      [...Array(8)].map(async () => {
        while (left-- > 0) await asyncOnce(MINIMA);
      }),
    );
  });

  const poolSize = process.env["UV_THREADPOOL_SIZE"] ?? "4 (default)";
  const pool = {
    unloaded: await threadpoolProbe(MINIMA, 0, 1200),
    at4: await threadpoolProbe(MINIMA, 4, 1200),
    at16: await threadpoolProbe(MINIMA, 16, 1200),
  };

  // A cost curve for outcome 3 only -- "untenable at *every* parameter set" is
  // a §7.3 question rather than an API one, and it needs the shape of the
  // curve rather than one point. Serial and sync: the point is the cost, not
  // the concurrency.
  const sweep: Array<{ passes: number; memoryMib: number; ms: number }> = [];
  for (const passes of [3, 4, 6]) {
    for (const memoryMib of [32, 64, 128, 256]) {
      const p = { ...MINIMA, passes, memory: memoryMib * 1024 };
      syncOnce(p);
      const t = process.hrtime.bigint();
      syncOnce(p);
      sweep.push({ passes, memoryMib, ms: Number(process.hrtime.bigint() - t) / 1e6 });
    }
  }

  const report = {
    schema: "fieldseal-bench/argon2-eventloop/v1",
    question: "docs/11 §2: does the synchronous blindIndex path stall a real request path?",
    commit: commit(),
    environment: {
      runtime: `Node ${process.versions.node}`,
      openssl: process.versions.openssl,
      os: `${process.platform} ${process.arch}`,
      cpus: (await import("node:os")).cpus().length,
      uv_threadpool_size: poolSize,
    },
    parameters: { ...MINIMA, note: "spec §7.3 minima" },
    per_call_ms: cost,
    event_loop: { idle, syncSerial, asyncSerial, asyncConcurrent, derivations: N },
    threadpool_ms: pool,
    parameter_sweep: sweep,
  };

  const line = (l: string, r: LoopResult): string =>
    `${l.padEnd(26)} wall ${r.wallMs.toFixed(0).padStart(5)} ms | turns ${String(r.turns).padStart(7)} | ` +
    `max gap ${(r.gapMax === null ? "n/a (never ran)" : `${r.gapMax.toFixed(2)} ms`).padStart(15)} | ` +
    `monitorEventLoopDelay says max ${r.monitorMaxMs.toFixed(2)} ms over ${String(r.monitorCount)} samples`;

  console.log(`Argon2id at spec §7.3 minima (t=3, m=32 MiB, p=1) -- ${report.environment.runtime}, ${report.environment.os}`);
  console.log(`per call: sync ${cost.sync.toFixed(1)} ms | async ${cost.async.toFixed(1)} ms\n`);
  console.log("EVENT LOOP -- turns taken while N=20 derivations run");
  console.log(line("  idle baseline", idle));
  console.log(line("  sync, serial", syncSerial));
  console.log(line("  async, serial", asyncSerial));
  console.log(line("  async, 8 concurrent", asyncConcurrent));
  console.log(`\nLIBUV THREADPOOL (size ${poolSize}) -- latency of an unrelated fs.readFile`);
  for (const [k, v] of Object.entries(pool)) {
    console.log(
      `  ${k.padEnd(24)} samples ${String(v.samples).padStart(4)} | p50 ${(v.p50 ?? NaN).toFixed(2).padStart(8)} p99 ${(v.p99 ?? NaN).toFixed(2).padStart(8)} ms`,
    );
  }

  if (outPath !== undefined) {
    mkdirSync(dirname(resolve(outPath)), { recursive: true });
    writeFileSync(outPath, JSON.stringify(report, null, 2) + "\n");
    console.error(`\nwrote ${outPath}`);
  }
  return 0;
}

process.exitCode = await main();
