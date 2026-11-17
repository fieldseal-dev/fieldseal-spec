/**
 * Emits the docs/14 §4 conformance report to stdout. Exit status is 1 if any
 * result failed, any out-of-band assertion is not a pass, or the tests behind
 * a test-backed pinned decision (`index-role-use-budget`, #225) are missing or
 * red, so CI turns red on the same condition that denies a level claim.
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
// docs/14 §4: an unbacked test-backed pinned decision withholds L0 without
// counting in `summary`, so the exit status follows the level claim as well.
for (const note of report.harness_notes) {
  if (note.startsWith("pinned_decisions.") && note.includes("NOT backed")) process.stderr.write(`PINNED UNBACKED ${note}\n`);
}
process.exitCode = report.summary.fail === 0 && report.claimed_levels.L0 === true ? 0 : 1;
