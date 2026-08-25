/**
 * The pinned vector suite, one vitest case per harness result, plus the
 * suite-level invariants the report must satisfy (docs/14 §4).
 */

import { describe, expect, it } from "vitest";
import { runSuite, type Report } from "./harness/run.ts";

const report: Report = runSuite();

describe("vector suite (MANIFEST.files only)", () => {
  for (const r of report.results) {
    it(r.id, () => {
      if (r.status === "skipped") return;
      expect(r.reason ?? "", r.id).toBe("");
      expect(r.status).toBe("pass");
    });
  }
});

describe("out-of-band assertions (docs/08 §5 item 8)", () => {
  for (const o of report.out_of_band) {
    it(o.id, () => {
      expect(o.reason ?? "", o.id).toBe("");
      expect(o.status).toBe("pass");
    });
  }
});

describe("report invariants (docs/14 §4)", () => {
  it("iterates every pinned file and no held-out file", () => {
    const ids = new Set(report.results.map((r) => r.id.split("/")[0]));
    for (const fam of ["envelope", "kdf", "context", "commitment", "blind-index"]) expect(ids.has(fam), fam).toBe(true);
    expect(report.results.some((r) => r.id.includes("argon2id"))).toBe(false);
    expect(report.held_out.map((h) => h.status)).toEqual(["not-run"]);
    expect(report.held_out[0]?.path).toBe("blind-index/argon2id.json");
  });
  it("declares the provisional status honestly", () => {
    expect(report.provisional_suites).toBe(true);
    expect(report.suites_supported).toEqual(["0xFF01"]);
    expect(report.vector_suite_version.endsWith("-provisional")).toBe(true);
    expect(report.pinned_decisions["decrypt-order"]).toBeTruthy();
  });
  it("carries every pinned_decisions key docs/14 §4 requires", () => {
    for (const key of [
      "decrypt-order",
      "aad-mismatch",
      "api-boundary-order",
      "unimplemented-registered-suite",
      "commitment-construction",
      "key-material-ownership",
    ]) {
      expect(report.pinned_decisions[key], key).toBeTruthy();
    }
  });
  it("does not declare decisions the specification has since taken over", () => {
    // Issue #48 (G15) closed these four into the text: a pinned decision
    // records where a core had to choose with nothing behind it, so once the
    // clause exists, continuing to declare it would misreport the core as
    // having made a choice it no longer makes.
    for (const key of [
      "unknown-format-version-set", // → spec §3.1, §3.4, §9, §10.3
      "provisional-arming", // → spec §4.8
      "rotate-in-permissive", // → spec §11.1
      "normalizer-text-over-bytes", // → docs/09 §7
    ]) {
      expect(report.pinned_decisions[key], key).toBeUndefined();
    }
  });
  it("has no failures and no silent skips", () => {
    expect(report.summary.fail).toBe(0);
    for (const r of report.results) if (r.status === "skipped") expect(r.reason).toBeTruthy();
  });
  it("intermediates agree wherever they were checked", () => {
    for (const r of report.results) {
      const inter = (r.details as { intermediates?: Record<string, string> } | undefined)?.intermediates;
      if (inter) for (const [k, v] of Object.entries(inter)) expect(v, `${r.id} ${k}`).not.toBe("DISAGREE");
    }
  });
});
