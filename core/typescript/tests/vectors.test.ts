/**
 * The pinned vector suite, one vitest case per harness result, plus the
 * suite-level invariants the report must satisfy (docs/14 §4).
 */

import { describe, expect, it } from "vitest";
import { runSuite, type Report } from "./harness/run.ts";

// Top-level await: vitest awaits the test module during collection, so the
// `it` cases below are registered once both passes have run.
const report: Report = await runSuite();

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
  it("carries the docs/08 §5 item 10 second pass, and declares it", () => {
    const async = report.results.filter((r) => r.id.endsWith("#async"));
    const sync = report.results.filter((r) => !r.id.endsWith("#async"));
    // The flag and the pass are one claim: a report that said `true` while
    // carrying one pass, or carried two while saying `false`, would misstate
    // what was actually run (docs/14 §4).
    expect(report.async_companions).toBe(async.length > 0);
    expect(async.length).toBe(sync.length);

    // docs/14 §126 defines the flag as an `iff` over three conditions, and
    // the emitter now computes it from all three rather than emitting a
    // literal. Assert the definition here rather than only the flag's
    // agreement with one of its own inputs: a `true` that rested on a second
    // pass of pure synchronous re-runs would satisfy the line above and still
    // tell a reader the companions were exercised when none was.
    const routed = async.filter((r) => r.details?.async_route === "companion");
    expect(report.async_companions).toBe(sync.length > 0 && async.length === sync.length && routed.length > 0);
    expect(routed.length).toBeGreaterThan(0);
    // Every async result is one or the other, and no synchronous result is
    // marked at all -- the marker names the pass it belongs to.
    for (const r of async) expect(["companion", "sync-rerun"], r.id).toContain(r.details?.async_route);
    for (const r of sync) expect(r.details?.async_route, r.id).toBeUndefined();

    const bySync = new Map(sync.map((r) => [r.id, r]));
    for (const r of async) {
      const original = bySync.get(r.id.slice(0, -"#async".length));
      // An async runner that invented an id -- or dropped one -- would
      // otherwise look like a pass.
      expect(original, r.id).toBeDefined();
      expect(r.status, r.id).toBe(original?.status);
    }
    const byAsync = new Set(async.map((r) => r.id.slice(0, -"#async".length)));
    for (const r of sync) expect(byAsync.has(r.id), r.id).toBe(true);
  });

  it("runs the raised-cost Argon2id vectors through the companion too", () => {
    // The three shapes that can tell a companion deriving at the declared
    // cost from one deriving at this core's default (#108 review), each
    // through blindIndexAsync / idfAsync / unindexableMarkerAsync.
    for (const suffix of ["/raised-cost-t4-b15#async", "/raised-cost-t4-b15#pipeline#async", "/unindexable-marker-t4-b15#async"]) {
      const r = report.results.find((x) => x.id.endsWith(suffix));
      expect(r, suffix).toBeDefined();
      expect(r?.status, suffix).toBe("pass");
    }
  });

  it("verifies the lone-surrogate refusal on both paths out of band", () => {
    // Every blind_index error vector in the suite is a positive control, so
    // the companion's *error* parity has no vector to rest on: this entry and
    // tests/async-companions.test.ts are what hold spec §11.1's "the same §9
    // error for the same condition".
    const ids = report.out_of_band.map((o) => o.id);
    expect(ids).toContain("docs/09/7.1/lone-surrogate-refusal");
    expect(ids).toContain("docs/09/7.1/lone-surrogate-refusal#async");
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
