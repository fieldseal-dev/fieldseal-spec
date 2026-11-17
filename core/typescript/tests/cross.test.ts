/**
 * The cross producer and consumer at `fieldseal-vectors/cross/v3`
 * (docs/08 §4.7, spec §7.2, #213), run as the CI job runs them: as child
 * processes over files.
 *
 * Each consumer guard is shown against a document broken in exactly one way
 * from a document the consumer accepts, so a guard cannot pass by the document
 * being wrong in some other way too.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const FF02_CASE = "cross/typescript/index/exact-ascii-suite-ff02";

interface IndexCase {
  id: string;
  declaration: Record<string, unknown>;
  index: string;
}
interface Doc {
  schema?: string;
  index_cases: IndexCase[];
  [k: string]: unknown;
}
interface Verdict {
  pairs: { id: string; kind: string; status: string; reason?: string }[];
  summary: { pass: number; fail: number; index: number; envelope: number; document: number };
}

let dir: string;
let produced: Doc;

function node(script: string, args: string[]): { status: number | null; stderr: string } {
  const r = spawnSync(process.execPath, ["--no-warnings=ExperimentalWarning", join(ROOT, "tests/cross", script), ...args], { cwd: ROOT, encoding: "utf-8" });
  return { status: r.status, stderr: r.stderr };
}

function consume(name: string, doc: unknown): { status: number | null; verdict: Verdict; stderr: string } {
  const file = join(dir, `${name}.json`);
  const out = join(dir, `${name}.verdict.json`);
  writeFileSync(file, JSON.stringify(doc));
  const r = node("consume.ts", [file, "--verdict", out]);
  return { status: r.status, stderr: r.stderr, verdict: JSON.parse(readFileSync(out, "utf-8")) as Verdict };
}

/** A deep copy of the produced document, for a test to break one way. */
const copy = (): Doc => JSON.parse(JSON.stringify(produced)) as Doc;
const ff02 = (d: Doc): IndexCase => d.index_cases.find((c) => c.id === FF02_CASE) as IndexCase;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "fieldseal-cross-"));
  const out = join(dir, "produced.json");
  const r = node("produce.ts", ["--out", out]);
  expect(r.status, r.stderr).toBe(0);
  produced = JSON.parse(readFileSync(out, "utf-8")) as Doc;
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("producer (cross/v3)", () => {
  it("writes schema cross/v3 and carries the corpus's declared suite in every index case", () => {
    expect(produced.schema).toBe("fieldseal-vectors/cross/v3");
    expect(produced.index_cases.length).toBeGreaterThan(0);
    for (const c of produced.index_cases) expect(c.declaration.suite_id, c.id).toMatch(/^0x[0-9A-F]{4}$/);
  });

  it("emits the 0xFF02 case, derived under 0xFF02 although the client's write suite is 0xFF01", () => {
    const c = ff02(produced);
    expect(c, "the corpus's 0xFF02 index case").toBeDefined();
    expect(c.declaration.suite_id).toBe("0xFF02");
    // The same value and context under 0xFF01 differ (see the sibling case): the
    // producer did not derive this one from its write suite.
    const sibling = produced.index_cases.find((x) => x.id === "cross/typescript/index/exact-ascii") as IndexCase;
    expect(sibling.declaration.suite_id).toBe("0xFF01");
    expect(c.index).not.toBe(sibling.index);
  });
});

describe("consumer (cross/v3)", () => {
  it("accepts the producer's own output, the 0xFF02 case included", () => {
    const r = consume("own", produced);
    expect(r.status, r.stderr).toBe(0);
    expect(r.verdict.summary.fail).toBe(0);
    expect(r.verdict.summary.index).toBe(produced.index_cases.length);
    expect(r.verdict.pairs.find((p) => p.id === FF02_CASE)?.status).toBe("pass");
  });

  it("fails a v3 index case without suite_id, and says so", () => {
    const d = copy();
    delete ff02(d).declaration.suite_id;
    const r = consume("no-suite", d);
    expect(r.status).toBe(1);
    const p = r.verdict.pairs.find((x) => x.id === FF02_CASE);
    expect(p?.status).toBe("fail");
    expect(p?.reason).toMatch(/no suite_id/);
    // Exactly one pair fails: the guard is per case, not a blanket refusal.
    expect(r.verdict.summary.fail).toBe(1);
  });

  it("does not default a missing suite_id from its own write suite (every other case still passes)", () => {
    const d = copy();
    for (const c of d.index_cases) delete c.declaration.suite_id;
    const r = consume("no-suite-any", d);
    expect(r.status).toBe(1);
    expect(r.verdict.pairs.filter((p) => p.kind === "index" && p.status === "pass")).toHaveLength(0);
  });

  it("fails when the 0xFF02 case's declared suite is rewritten to 0xFF01 (no substitution of the write suite)", () => {
    const d = copy();
    ff02(d).declaration.suite_id = "0xFF01";
    const r = consume("rewritten", d);
    expect(r.status).toBe(1);
    const p = r.verdict.pairs.find((x) => x.id === FF02_CASE);
    expect(p?.status).toBe("fail");
    expect(p?.reason).toMatch(/index differs/);
    expect(r.verdict.summary.fail).toBe(1);
  });

  it("fails a declared suite that is not registered, as a refused declaration", () => {
    const d = copy();
    ff02(d).declaration.suite_id = "0x0001";
    const r = consume("unregistered", d);
    expect(r.status).toBe(1);
    expect(r.verdict.pairs.find((x) => x.id === FF02_CASE)?.reason).toMatch(/CONFIGURATION_ERROR|not a registered suite/);
  });

  it("fails a malformed suite_id", () => {
    const d = copy();
    ff02(d).declaration.suite_id = "ff02";
    const r = consume("malformed", d);
    expect(r.status).toBe(1);
    expect(r.verdict.pairs.find((x) => x.id === FF02_CASE)?.reason).toMatch(/0xXXXX/);
  });

  it("refuses cross/v2, whose index cases carry no declared suite", () => {
    const d = copy();
    d.schema = "fieldseal-vectors/cross/v2";
    const r = consume("v2", d);
    expect(r.status).toBe(1);
    expect(r.verdict.summary.index).toBe(0); // nothing was derived from a document it does not read
    expect(r.verdict.pairs.find((p) => p.kind === "document")?.reason).toMatch(/cross\/v2.*no longer read/);
  });

  it("fails an unknown schema", () => {
    const d = copy();
    d.schema = "fieldseal-vectors/cross/v9";
    const r = consume("unknown", d);
    expect(r.status).toBe(1);
    expect(r.verdict.pairs.find((p) => p.kind === "document")?.reason).toMatch(/unrecognised producer schema/);
    expect(r.verdict.summary.index).toBe(0);
  });

  it("fails a missing schema", () => {
    const d = copy();
    delete d.schema;
    const r = consume("missing", d);
    expect(r.status).toBe(1);
    expect(r.verdict.pairs.find((p) => p.kind === "document")?.reason).toMatch(/unrecognised producer schema undefined/);
  });

  it("still reads cross/v1, which carries no index half", () => {
    const d = copy();
    d.schema = "fieldseal-vectors/cross/v1";
    d.index_cases = [];
    const r = consume("v1", d);
    expect(r.status, r.stderr).toBe(0);
    expect(r.verdict.pairs.find((p) => p.kind === "document")?.status).toBe("pass");
  });

  it("fails a v3 document whose index half is empty (a producer that lost its index cases)", () => {
    const d = copy();
    d.index_cases = [];
    const r = consume("v3-empty", d);
    expect(r.status).toBe(1);
  });
});
