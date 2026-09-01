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
    // Nothing is held out as of suite 0.6.0-provisional, so the rule is what
    // is asserted here; the case it used to name is the next test.
    for (const h of report.held_out) expect(h.status).toBe("not-run");
    expect(report.summary.held_out).toBe(report.held_out.length);
  });
  it("runs the Argon2id family rather than merely listing it", () => {
    // Until 2026-08-31 this asserted the opposite: argon2id was held out and
    // MUST NOT appear in results (docs/07 §7 records the promotion). Assert on
    // derived results, not on the manifest -- a harness that counted the file
    // without running it, or fell back to HMAC, would satisfy a manifest check.
    const argon2 = report.results.filter((r) => r.id.startsWith("blind-index/argon2id/"));
    expect(argon2.length).toBeGreaterThan(0);
    expect(argon2.every((r) => r.status === "pass")).toBe(true);
    // The assertion shapes are the ones the hold-out hid: they carried no
    // idf_params until promotion, and this harness rejects a missing cost
    // rather than assuming the minimum (docs/08 §4.4).
    expect(argon2.some((r) => r.id.endsWith("/unindexable-marker-b15"))).toBe(true);
    expect(argon2.some((r) => r.id.endsWith("/unindexable-bucketed-b15"))).toBe(true);
    // A vector off the minima is the only one that can tell a harness that
    // derives at the declared cost from one that derives at its default and
    // happens to agree (docs/08 §4.4) -- the #108 review caught this harness's
    // marker check doing exactly that. Both raised-cost shapes, and the
    // primitive's #pipeline companion, must be present and passing.
    expect(argon2.some((r) => r.id.endsWith("/raised-cost-t4-b15"))).toBe(true);
    expect(argon2.some((r) => r.id.endsWith("/raised-cost-t4-b15#pipeline"))).toBe(true);
    expect(argon2.some((r) => r.id.endsWith("/unindexable-marker-t4-b15"))).toBe(true);
    expect(report.held_out).toEqual([]);
  });
  it("carries no harness note that contradicts the results", () => {
    // The #108 review found this report describing blind-index/argon2id.json
    // as held out and not iterated while listing 30 of its results as passing:
    // HARNESS_NOTES is emitted verbatim (docs/14 §4) and nothing asserted on
    // it. A note that names a file whose vectors appear in `results` may not
    // say the file was held out or not run.
    const ran = new Set(report.results.map((r) => r.id.split("/").slice(0, 2).join("/")));
    const file = /([\w-]+\/[\w-]+)\.json/g;
    for (const note of report.harness_notes) {
      let m: RegExpExecArray | null;
      while ((m = file.exec(note)) !== null) {
        const fam = m[1];
        if (fam !== undefined && ran.has(fam)) expect(/held out|held-out|not-run|not iterated/i.test(note), note).toBe(false);
      }
    }
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
