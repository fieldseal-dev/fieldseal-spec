# Conformance & CI Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** how conformance is claimed, proven, and continuously enforced. This is the machinery behind the project's central claim — spec §12's "CI MUST fail on divergence" and PRD CL-7/M1/M2.

---

## 1. Principles

1. **A conformance claim is a build artifact, not a README sentence.** Every claim traces to a machine-readable report produced by running the vectors in CI at a named vector-suite version.
2. **Cross-implementation round trips run on every merge to the integration branch**, not just releases. The Phase 1 exit criterion (PRD §8: "a value written by Python is read by TypeScript, and vice versa, in CI") is a permanent gate once first met — regressions on it block merge.
3. **Third-party implementations can run everything without this repo's CI.** The harness contract (docs/08 §5), report format (§4 below), and the CC0-licensed vectors (settled 2026-08-09 — `LICENSES.md`) are the entire interface; PRD metric M2 (an implementation not written by us passes) depends on nothing here being private.

## 2. Repository and workflow topology

Monorepo (current layout). GitHub Actions **[assumption: GitHub remains the host — the design below uses only artifacts + matrix jobs and ports to any CI]**:

```
.github/workflows/
  vectors.yml        validates vector files against schema + MANIFEST hashes; runs on any vectors/ change
  core-python.yml    lint, typecheck, unit, property, vector harness  (paths: core/python/**, vectors/**)
  core-typescript.yml  same for TS
  adapter-django.yml   adapter matrix (Django versions × Postgres/SQLite), needs core-python
  adapter-prisma.yml   adapter matrix (Prisma version × Postgres/SQLite), needs core-typescript
  cross.yml          the N×N cross-implementation job (below)
  conformance.yml    assembles per-run conformance reports into the published summary
```

Path filtering keeps unrelated changes cheap; `cross.yml` runs on changes to any `core/**`, `vectors/**`, or on a nightly schedule (catching toolchain drift — a Node or OpenSSL upgrade changing behavior is exactly the class of bug this project exists to surface).

## 3. The cross job (the one that matters)

Two stages, artifact-mediated, full N×N including self-pairs:

```
stage produce (matrix over implementations):
  each impl runs its cross-producer (docs/08 §4.7) with its REAL production path
  (runtime CSPRNG, no injection), against vectors/keys/test-keys.json
  → uploads cross-<impl>.json artifact

stage consume (matrix over consumer × producer pairs):
  consumer downloads producer's artifact, decrypts every case, compares plaintext byte-exact
  → uploads verdict-<consumer>-<producer>.json

gate:
  all pairs green, or the workflow fails. A pair may be `skipped` ONLY for a suite the
  consumer does not claim (0xFF02), and skips are visible in the summary, never silent.
```

Self-pairs (`python→python`) stay in the matrix deliberately: they distinguish "producer broke" from "pair broke," halving diagnosis time.

Static cross vectors (`vectors/cross/static/`) are additionally verified by each core's ordinary vector harness — they catch drift against *released* implementations, while the dynamic job catches drift at head.

## 4. Conformance report format

Every harness (core or adapter) emits `conformance-report.json`:

```json
{
  "schema": "fieldseal-conformance/v1",
  "implementation": { "name": "python-core", "version": "0.1.0", "commit": "…", "language": "python" },
  "vector_suite_version": "0.1.0-provisional",
  "spec_version": "0.1-draft",
  "claimed_levels": { "L0": true, "L1": false },
  "suites_supported": ["0xFF01"],
  "provisional_suites": true,
  "environment": { "runtime": "CPython 3.12.x", "os": "ubuntu-24.04", "crypto_backend": "OpenSSL 3.x" },
  "results": [
    { "id": "envelope/ff01/basic-roundtrip", "status": "pass" },
    { "id": "envelope/ff02/basic-roundtrip", "status": "skipped", "reason": "suite 0xFF02 not implemented" }
  ],
  "held_out": [
    { "path": "blind-index/argon2id.json", "status": "not-run", "reason": "held out of the suite; primitive unverified against any external known-answer source" }
  ],
  "out_of_band": [
    { "id": "spec/3.5/length-bound", "status": "pass", "method": "unit test asserting 2^31 refused with LENGTH_EXCEEDED" }
  ],
  "async_companions": false,
  "summary": { "pass": 412, "fail": 0, "skipped": 18, "held_out": 5 }
}
```

`out_of_band` carries normative requirements that have no vector — currently just the spec §3.5 plaintext length bound, whose 2-GiB input is not a repository artifact.

`held_out` mirrors `MANIFEST.json`'s held-out list. A harness MUST iterate the manifest's `files` and MUST NOT iterate `held_out`; the block is reported so that a held-out family is *visibly* not run rather than silently absent. `status` is `not-run`, never `pass` or `skipped` — "skipped" already means "this implementation does not claim that suite," which is a different statement and one that a reader could mistake for a capability gap rather than a suite-integrity decision. An implementation MAY exercise a held-out family in its own development, and MUST NOT report the result here.

`provisional_suites` is `true` whenever any identifier in `suites_supported` falls in spec §4.8's reserved `0xFF00`–`0xFFFF` range. It exists so that a report cannot be quoted as evidence of conformance to a frozen format when no format has been frozen (PRD §8, Gate 0b).

Rules: `fail > 0` ⇒ no level claimable ⇒ CI red. An `out_of_band` entry that is not `pass` counts as a failure for level-claim purposes on the same terms. `claimed_levels` must be consistent with the vector families passed (L0 requires every family the implementation's suites reach; adapter levels additionally require the adapter's own integration matrix green — adapters attach a `coverage_matrix` block mirroring their README table so the claim and the docs cannot drift apart). `environment.crypto_backend` is recorded because FIPS conversations turn on it (PRD CL-9).

Reports are uploaded as artifacts on every run; `conformance.yml` assembles the latest per-implementation reports into `bench/conformance-summary.md` (committed by CI on release tags only, so history is release-granular and the working tree stays quiet).

## 5. Release and versioning discipline

- **Vector suite:** semver, tagged `vectors-vX.Y.Z`. Additive = minor; retirement of a vector = major (consumers must re-check); no in-place edits ever (docs/08 §1).
- **Cores/adapters:** independent semver per package; each release records the vector-suite version it certifies against. A core release is blocked unless the cross job at that commit is green.
- **Spec:** already versioned (`02-spec-v0.1.md` → `spec/` as versioned releases per repo layout). A spec change that alters bytes ⇒ new vectors ⇒ vector-suite major bump — the CONTRIBUTING.md chain (issue → citation → breakage statement → vectors) is enforced by review checklist, and mechanically by the fact that changed vectors fail every implementation until they're updated in the same PR train.
- **Toolchain pinning:** CI pins language toolchains by version file (`.python-version`, `.nvmrc`, lockfiles committed). Nightly cross runs use *floating* latest-patch toolchains on purpose — divergence between pinned and floating runs is signal, not noise.

## 6. Non-CI conformance (third parties)

`docs/` gains (Phase 1, DO-track) a short "Certifying an implementation" page: run the harness contract against a tagged vector suite, produce the §4 report, open a PR adding it under `bench/third-party/`. Listing requires: report with `fail: 0`, named contact, and the implementation being publicly available — mirroring M2's spirit that the strongest signal is an implementation we didn't write.

## 7. Explicitly not in CI

Benchmarks (bench/ is honest *measurement*, PRD DO-4 — CI machines produce noise, so benchmarks run on dedicated hardware with pinned specs and are published with methodology, not gated); coverage percentage gates (the vector suite and path matrices are the meaningful coverage measure); auto-formatting commits; scheduled dependency-bump auto-merges for `cryptography`/crypto-adjacent packages (human review required — supply-chain caution for a crypto project).
