/**
 * Emits the docs/14 §4 conformance report to stdout. Exit status is 1 if any
 * result failed or any out-of-band assertion is not a pass, so CI turns red
 * on the same condition that denies a level claim.
 *
 *   node tests/run_vectors.ts > conformance-typescript.json
 */

import { execSync } from "node:child_process";
import { runSuite } from "./harness/run.ts";

function gitCommit(): string | undefined {
  try {
    return execSync("git rev-parse HEAD", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  } catch {
    return undefined;
  }
}

const commit = gitCommit();
const report = await runSuite(commit === undefined ? {} : { commit });
process.stdout.write(JSON.stringify(report, null, 2) + "\n");
process.exitCode = report.summary.fail === 0 ? 0 : 1;
