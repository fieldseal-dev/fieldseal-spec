# Phase 1 Implementation Plan

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the engineering plan for Phase 1 ("prove the format," PRD §8): what gets built, in what order, gated by what, defined-done how. This is the umbrella document for the tech-spec suite:

| Doc | Covers |
|---|---|
| `docs/08-test-vector-spec.md` | Vector suite: formats, schemas, harness contract, injection, cross protocol |
| `docs/09-core-architecture.md` | Language-agnostic core design all implementations follow |
| `docs/10-core-python.md` / `docs/11-core-typescript.md` | Phase 1 core bindings |
| `docs/12-adapter-django.md` / `docs/13-adapter-prisma.md` | Phase 1 adapters |
| `docs/14-conformance-ci.md` | Conformance claims, CI, the cross job |
| `docs/15-tooling.md` | Backfill and leakage estimator (P1; constraints known now) |
| `docs/adr/` | Decision records for the Phase-1-blocking choices (spec §13.1, §13.2) |

**Standing constraint:** none of this authorizes writing code before the Phase 0 exit gate. The gate (PRD §8) is: *at least two people with real cryptographic credentials have read the spec and their objections are addressed or documented*. Independent review is a release gate, not a nice-to-have (PRD §9, top risk). This plan exists so that Phase 1 starts fast when the gate opens — not instead of the gate.

---

## 1. Gate 0 — what must close before code

In dependency order:

1. **ADR-0001** (envelope: profile AWS or define fresh) — everything serializes the envelope; spec §13.1 calls it the highest-leverage open decision. The expressibility-mapping task in the ADR can start immediately; it needs no reviewer.
2. **ADR-0002** (suite 0x0001 AEAD) — determines envelope arithmetic and whether gap G1 applies to the mandatory suite.
3. **The spec-gap issues G1–G13 (§5 below)** — each is a spec issue per `CONTRIBUTING.md` (justification + citation, breakage statement, vectors); ready-to-post drafts live in `docs/issues/`. Scope within the gate: G1–G8 (the vector-blocking set) must merge before M0; G9–G13 must be *filed* before M0 but may close during Phase 1 alongside the workstreams they touch (G8/G12 before adapter DDL ships, G13 before the Prisma conformance claim).
4. **Cryptographic review** covering, at minimum: the per-write-key nonce argument (§4.4/§5.3), the commitment construction chosen for G1, the blind-index construction (§7), and the envelope-format novelty question posed in ADR-0001.

Items 1–3 produce artifacts reviewers can react to; run them concurrently with reviewer recruitment, not before it.

## 2. Workstreams and dependency graph

```
Gate 0 ──► WS-A vectors & harness ──► WS-B Python core ──► WS-E Django adapter ──► WS-G example app
                    │                      │                                            ▲
                    │                      ▼                                            │
                    └────────────► WS-C TypeScript core ──► WS-F Prisma adapter ────────┘
                                           │
              WS-D cross CI ◄──────────────┘   (needs both cores)
              WS-H docs & certification page   (parallel, continuous)
```

- **WS-A** — vector generator (`tools/vector-gen/`, Python), JSON Schemas, `MANIFEST.json`, `errors/format+policy` families (authorable now), remaining families as G-issues close. Output: vector suite `v0.1.0-provisional`.
- **WS-B** — Python core per `docs/10`. Also hosts the generator's primitive checks (docs/08 §7).
- **WS-C** — TypeScript core per `docs/11`, under the **independence rule** (docs/11 §6): built from spec + docs only, no reading Python source, until first freeze. Divergences it finds are recorded in §7 below and are the cheap substitute for a second review pass.
- **WS-D** — CI per `docs/14`: per-core workflows first, then the N×N cross job. The cross job green is **the Phase 1 exit criterion** (PRD §8).
- **WS-E / WS-F** — adapters per `docs/12`/`docs/13`, each shipping its coverage matrix and refusal tests.
- **WS-G** — one end-to-end demonstration app (PRD Phase 1 deliverable). Proposal: a small patient-directory service with **both** a Django and a Prisma frontend over one shared Postgres schema — making the demo itself a live cross-language proof (a row written by either stack reads from the other), which is the project's pitch in runnable form.
- **WS-H** — "Certifying an implementation" page (docs/14 §6), operational docs skeletons (threat-model-as-deployed, KMS degradation modes — PRD DO-1/DO-6), and keeping `docs/06-verification-log.md` current as library-fact **[VERIFY]** flags in docs/10–13 get resolved.

## 3. Milestones

| # | Milestone | Exit test |
|---|---|---|
| M0 | Gate 0 closed | ADRs 0001/0002 ACCEPTED; G1–G8 spec PRs merged with vector obligations attached; two credentialed reviewers' objections addressed or logged as open questions |
| M1 | Python core passes provisional vectors | `conformance-report.json` with `fail: 0` at vectors `v0.1.0-provisional`; property/fuzz suites green |
| M2 | Independent reproduction | TypeScript core reproduces every expected value from spec+docs alone; divergence log triaged (each = impl bug or spec ambiguity → new G-issue); vector suite frozen at `v0.1.0` |
| M3 | **Cross CI green** | N×N produce/consume matrix green including self-pairs, on merge and nightly — the PRD Phase 1 exit criterion, permanent gate thereafter |
| M4 | Adapters at level | Django L1+L2(a)(b), Prisma L1+L2(b)-with-throws; coverage matrices generated from green test suites; refusal tests complete |
| M5 | Phase 1 done | Demo app runs the two-frontend cross-language scenario; docs current; Phase 1 retro decides Phase 2 entry |

Sequencing within the ~12-week PRD window is deliberately not calendarized per-week here: there is no calibration data for this team on this kind of work, and invented week numbers would be false precision (the PRD's own DO-5 makes *measured* effort a deliverable). Relative sizing instead: WS-A M · WS-B L · WS-C L · WS-D M · WS-E L · WS-F L · WS-G S · WS-H S — with WS-B/WS-C not parallelizable with each other under a single implementer *by design* (M2's independence value assumes different authors or at minimum a hard sequencing with the vectors frozen in between; if one person writes both cores, say so in M2's report — it weakens the independence claim and the honest move is stating it).

## 4. Definition of done (applies to every workstream)

- Tests green in CI including the vector harness at a named suite version; for adapters, the path matrix and refusal tests.
- Every **[VERIFY]** flag in the workstream's tech spec resolved: confirmed (flag removed, fact dated) or corrected (spec doc updated + note in `docs/06-verification-log.md` style).
- Docs shipped with the artifact: README, coverage matrix (adapters), honest-limitations section (per spec's MUST-document items — §3.3 overhead, §5.5 cache exposure, §7.3 Argon2id cost, §8.1 KMS dependency).
- No overclaim audit: someone other than the author reads the README against `CONTRIBUTING.md`'s two standing rules.

## 5. Spec gaps found while writing the tech-spec suite

Each becomes a spec issue (label: the section it touches, per `CLAUDE.md`); **full ready-to-post drafts live in [`docs/issues/`](../docs/issues/README.md)**. "Proposed direction" is a starting point for the issue, **not** a decision — several need a cryptographer's sign-off (noted). Consolidates docs/08 §9 (G1–G8), G9–G11 found in the core/adapter specs, and G12–G13 found in the suite's consistency review.

| # | Section | Gap | Proposed direction | Needs crypto review |
|---|---|---|---|---|
| G1 | §4.6, §3.1 | Commitment construction undefined (32 B reserved, no formula) | Derive a commit value from the record key via the suite KDF with a dedicated label (the AWS ESDK v2 key-commitment shape its algorithm-suite docs describe; also cf. Albertini et al., *How to Abuse and Fix Authenticated Encryption Without Key Commitment*, USENIX '22); verify constant-time pre-decrypt | **Yes** |
| G2 | §7.3 | Argon2id invocation incomplete: parallelism, output length, version, and the password/salt/secret layout unspecified (deterministic salt strategy needed — Argon2 requires a salt, but the index must be deterministic per key) | Full parameter tuple in the spec, RFC 9106 as the normative reference; salt derived from the index key via HKDF with a dedicated label | **Yes** |
| G3 | §7.2, §7.4 | `truncate(raw, b bits)` bit semantics undefined | Keep the leading `ceil(b/8)` bytes, zero the trailing `8·⌈b/8⌉−b` bits of the final byte (MSB-first); state byte order | No (but vectors pin it) |
| G4 | §6.2 | `tenant_id = null` encoding unspecified (omission defined only for `row_id`); null vs zero-length ambiguity | Define explicitly; consider a field-count or presence-bitmap discriminator so omission can never alias a crafted value | **Yes** (canonical-encoding forgery surface) |
| G5 | §9, §3.4 | Error classification order undefined: format → policy → key → commitment → AEAD precedence, and how context mismatch (which surfaces as a wrong derived key under dual binding) maps to `AAD_MISMATCH` vs `COMMITMENT_INVALID` | The decrypt state machine in docs/09 §3.2, pinned normatively; acknowledge the §6.3 ambiguity honestly in §9 | Partly |
| G6 | §9, §10.3 | No error code for mode violations (`encrypt()` in `readonly`); whether `readonly` may compute blind indexes for queries unstated; `readonly`'s non-envelope read behavior undefined (§10.3 defines the other two modes by exactly that behavior) | Add a code; clarify readonly = no *writes*, index computation for WHERE permitted, non-envelope input passes through as `permissive` | No |
| G7 | §4.2 | Suite 0x0002's XChaCha20-Poly1305 has no IETF RFC; no normative definition named | Name libsodium's construction as normative (draft-irtf-cfrg-xchacha expired), or drop 0x0002 to keep the registry lean | Partly |
| G8 | §7 | Blind-index **stored** representation undefined — two languages sharing one database must byte-agree | Raw bytes, length `ceil(b/8)`, binary column; hex alternative for text-only stores, declared per column | No |
| G9 | §11.1 | Sync-only `blind_index` blocks the Node event loop 10–100 ms per Argon2id term (docs/11 §2); L4-capable adapters (Prisma) could use an async variant the spec currently forbids | Optional async companions for L4 adapters, sync remains mandatory and primary | No |
| G10 | §3 | No plaintext length bound; implementations should reject at the same limit | 2³¹−1 bytes at the API boundary (docs/09 §4) | No |
| G11 | §6.1, §7.2 | `purpose`/`index-id` grammar unconstrained (charset, length) — interacts with G4's encoding-aliasing concern | Constrain to `[a-z0-9-]{1,32}` after the `index:` prefix | No |
| G12 | §7.10, §7.4 | §7.10 permits unique constraints "on the index column only" while §7.4 mandates collisions (`P × 2^(−b) ≥ 2`) — a UNIQUE truncated index rejects legitimate distinct values | §7.10 row becomes "No"; application-level uniqueness fallback documented with its race honesty | No |
| G13 | §10.2, §7.10 | §10.2's Prisma bullet unconditionally MUST-rejects `in:` while §7.10 supports membership ("N indexes OR'd") | Scope the MUST to non-rewriting adapters; a correct index rewrite + §7.5 re-verify is conformant | No |

## 6. Risk register (delta to PRD §9 — implementation-phase risks)

| Risk | Mitigation |
|---|---|
| A G-issue closes differently than a tech spec assumed | The specs mark every dependent section with the G-number; closure includes a sweep of those markers (grep for `G<n>` across docs/07–15, docs/adr, docs/issues — **not** repo-wide: docs/00 uses G1–G6 as *market*-gap numbers, a different namespace) |
| Sync Argon2id in Node is a product-killer for Prisma users | Surface early: benchmark in WS-C week one at spec-minimum parameters; if unacceptable, G9 escalates from nice-to-have to Phase 1 spec change |
| Unicode normalization drift across languages silently breaks shared indexes | `nfc-casefold-v1` pinned to a vendored folding table, not platform Unicode (docs/09 §7 flag); vectors carry pre- and post-normalization forms |
| Library-fact flags wrong (pyca XChaCha, sync argon2 APIs, DMMF access) | Every **[VERIFY]** is a tracked task at workstream start, not discovered mid-build |
| Single-author cores weaken M2's independence claim | State it in the M2 report if so; recruit a second implementer for one core as the preferred fix (also feeds the OpenSSF multi-maintainer requirement, PRD §9) |
| Vector generator becomes a de-facto oracle | docs/08 §7 rule: agreement of two independent implementations freezes a vector, never the generator alone |
| Windows/line-ending corruption of vector bytes | Generator writes bytes; `.gitattributes` already pins LF; harness verifies MANIFEST hashes before use |

## 7. Decision & divergence log

Append-only, verification-log style (`docs/06`): every M2 divergence, every G-issue outcome, every ADR closure with date and consequence sweep.

- **2026-08-08** — Suite-wide consistency review (two independent read-through passes) applied 26 corrections across docs/08–15; the substantive ones: decrypt-side `suite_id` sourcing pinned to the parsed header (docs/09 §3.2 step 4 — a write-suite-sourced context breaks mixed-suite reads and rotation); example blind-index declarations corrected to the §7.4 band (16 → 15 bits at P = 100,000); adapter-owned core-client construction (the index registry cannot reach construction-time validation any other way); the determinism-injection arming gate (`FIELDSEAL_TEST_MODE`); and two newly found spec-internal contradictions filed as G12 (§7.10 unique-constraint row vs §7.4 collision mandate) and G13 (§10.2 Prisma `in:` reject vs §7.10 membership support).
- **2026-08-08** — `docs/02` §7.1 cross-reference corrected: the prefix-index mechanism is §7.9, not §7.7 (pure pointer typo; prose-clarification bar per `CONTRIBUTING.md`).
- **2026-08-08** — ADR-0001's expressibility-mapping task delivered as first-pass evidence (`docs/adr/0001-appendix-a-expressibility-mapping.md`); headline findings: §6.3 dual-layer binding not expressible in the AWS format; per-cell embedding costs 1.4×–2.4× the fresh envelope. ADR remains OPEN pending reviewer input and the appendix's own §8 verification items.

## 8. What Phase 1 deliberately does not build

Java/.NET/Go cores and their adapters (Phase 2) · TypeORM/Sequelize adapters (deferred, PRD §8) · benchmarks beyond the demo app's incidental numbers (bench/ methodology work is Phase 2, DO-4) · any hosted service · GUI/console tooling beyond the two CLIs in `docs/15`.
