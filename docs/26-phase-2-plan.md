# Phase 2 Implementation Plan

**Date:** 2026-09-22 · **Status:** Draft 1; four of the five §5 decisions made by the maintainer on 2026-09-22, the .NET framework open · **Purpose:** the engineering plan for Phase 2 ("prove the breadth", PRD §8): what gets built, in what order, gated by what, and when each piece is done. It is the Phase 2 counterpart of [`docs/07-implementation-plan.md`](07-implementation-plan.md), which stays the Phase 1 plan as written. Phase 2 was opened by the retrospective's decision ([`docs/25-phase-1-retro.md`](25-phase-1-retro.md) §10, 2026-09-22): the full scope PRD §8 gives it, Java core first.

| Doc | Covers | State |
|---|---|---|
| `docs/02-spec-v0.1.md`, `docs/08`, `docs/09`, `docs/14` | The specification, vector suite, core architecture and conformance format every Phase 2 artifact is built against | Exist; `docs/14` §4 is amended first (§1) |
| `docs/17-m2-implementer-brief.md` | The isolation protocol each new core is built under | Exists; applies unchanged (§2.2) |
| `docs/NN-core-java.md` | Java core binding (WS-I) | Written at P2-M0 from the reviewed JVM design (§1 item 3) |
| `docs/NN-core-dotnet.md` | .NET core binding (WS-J) | Written before WS-J starts, from the reviewed .NET design |
| `docs/NN-core-go.md` | Go core binding (WS-K) | No design exists yet |
| `docs/NN-adapter-{sqlalchemy,hibernate,efcore,gorm}.md` | The four Phase 2 adapters, in the shape of `docs/12` and `docs/13` | Each written before its adapter's code |
| `docs/NN-benchmarks.md` | `bench/` methodology (PRD DO-4) | WS-Q, first deliverable |
| `docs/15-tooling.md` §1 | Backfill design (PRD AD-6, CL-8) | Exists; §1.1's config hash gets defined inputs in WS-R |

`NN` is the next free number when each document is written. None is reserved in advance: `docs/22` was once proposed for a binding doc and collided.

**Standing constraints, unchanged by Phase 2** (`docs/25` §10 item 3). Gate 0b is open and nothing here moves it. Every MUST NOT in PRD §8 holds: no non-provisional suite identifier, no vector suite other than `-provisional`, nothing at 1.0, no production adoption invited, no Phase 3 dissemination track. Experimental pre-1.0 releases stay permitted under PRD §8's five conditions and are not a Phase 2 milestone (§7). The provisional suite and its regeneration rule stand, and every core built in Phase 2 multiplies what a regeneration costs (§6).

**One log, one gap table.** Phase 2 decisions are logged in `docs/07` §7, append-only, as Phase 1's were, and new spec gaps are added to `docs/07` §5's table and `docs/issues/`. A second log for Phase 2 would drift from the first, and a reader could not tell which one supersedes.

---

## 1. Entry — what must land before the first line of Phase 2 core code

In dependency order. Together these are milestone P2-M0 (§3).

1. **This plan**, with the §5 decisions made or explicitly deferred to the workstream that needs them.
2. **The `docs/14` §4 amendment for unrepresentable operands (G26, tracker [#176](https://github.com/fieldseal-dev/fieldseal-spec/issues/176), filed 2026-09-22).** `docs/14` §4 has a runtime that cannot run an `out_of_band` entry record `not-run`, and a `not-run` entry blocks the level claim on the same terms as a failure. That is right for an operand that is merely too large to allocate. It is wrong for one the language cannot represent, which `docs/14` §4 already names as a category — "excluded by *representability*, which is a property of the requirement itself and will not go away" — without giving it a passing status. Read literally, the Java and .NET cores could never claim L0 (their byte arrays have `int` lengths, so a 2³¹-byte operand does not exist), and neither could Go (its string literals cannot hold the lone-surrogate operand). The need was recorded in the closure comment on #167 (2026-09-20). The issue should propose, and the discussion decide:
   - an entry whose operand the language cannot represent records `pass` when **(a)** the refusal is proven on a synthetic operand through the same internal path every public call takes, and **(b)** the entry's `method` states the representability argument and the core's binding doc states it too;
   - the vocabulary: `docs/14` §4 specifies `not-run`, while the TypeScript harness's report type also admits `not-verified`. One of them goes.

   It is filed and closed before any Phase 2 core emits a report. Without it, `docs/25` §10 item 3 applies as written — a core that passes with `not-run` entries does not count toward PRD metric M1 — and the Phase 2 exit criterion is unreachable for three of the five languages (§6).
3. **The Java binding doc** (`docs/NN-core-java.md`), written from the reviewed JVM design, with the JDK floor decided (§5 item 1). The design becomes the binding doc; it does not also land as a separate document. On the way in it loses what was true only when it was drafted on 2026-09-19: the premise that the `docs/09` §4 buffer-maxima flag waits on this core (#167 removed it, and #168 turned it into a per-binding obligation), every "M5 is not closed" sentence, and every reference to a file outside the repository. Its §0 review record stays, because the corrections it lists are the evidence the design was checked.
4. **The conformance tooling grows from two cores to N** (WS-L). `tools/conformance/compare_result_ids.py` reads exactly two reports today (`docs/14` §2), and the `cross-consume` job's consumer matrix is `[python, typescript]`. Both are generalised, with their tests, before a third core arrives, so that the third core's arrival is a one-line matrix change and not a redesign under pressure.

## 2. Workstreams and dependency graph

### 2.1 The graph

Letters continue from `docs/07` §2's WS-A to WS-H. The reviewed JVM and .NET designs already call themselves WS-I and WS-J.

```
P2-M0: plan · G26 amendment · WS-L (N-report tooling) · Java binding doc
   │
   ▼
WS-I Java core ──► WS-N Hibernate ──► WS-M SQLAlchemy
                                          │
   ┌──────────────────────────────────────┘
   ▼
WS-J .NET core ──► WS-O EF Core          (WS-K's Go design drafted meanwhile, §5 item 5)
                        │
   ┌────────────────────┘
   ▼
WS-K Go core   ──► WS-P GORM

Alongside, not on that line:
   WS-L conformance & cross CI   grows with every core: N-report compare, N×N matrix
   WS-Q benchmarks (DO-4)         can start against the two shipped cores
   WS-R migration tooling          PROCEDURE.md, then Django and Prisma frontends;
                                   must land before WS-N closes (§5 item 4)
```

- **WS-I** — Java core per its binding doc, under the `docs/17` protocol. Hosts the `tools/ucd-gen` Java emitter, so CI's `--check` covers the Java tables.
- **WS-J** — .NET core per its binding doc, same protocol, on Linux **and** Windows CI legs: the platform crypto is OpenSSL on one and CNG on the other, and a suite run on one of them silently picks a side. Hosts the C# `ucd-gen` emitter.
- **WS-K** — Go core. **No design exists.** WS-K's first deliverable is one, reviewed as the JVM and .NET designs were (a second reader checks it against the repository and primary platform sources, and the corrections are recorded in a §0), and then turned into the binding doc. Known before it is written: the lone-surrogate entry is a representability case (`docs/14` §4), and Go has no exceptions, so the §9 error taxonomy maps to error values. Hosts the Go `ucd-gen` emitter.
- **WS-L** — conformance and cross CI, per `docs/14`, extending Phase 1's WS-D: the N-report result-id comparison, each new core as producer and consumer in the cross job, and a per-core job for each language. The amendment in §1 item 2 is WS-L's first output.
- **WS-M, WS-N, WS-O, WS-P** — the SQLAlchemy, Hibernate, EF Core and GORM adapters, each with a binding doc in the shape of `docs/12`/`docs/13` written before its code, its own backfill frontend (§5 item 4), a coverage matrix generated from green tests (PRD AD-2), refusal tests for every carve-out in spec §10.2 that names its ORM, and the AD-1 zero-cryptography grep that already guards `adapters/*/src`.
- **WS-Q** — benchmarks. A methodology document first (`docs/NN-benchmarks.md`): what is measured (per-operation latency and throughput for each core, suite and IDF; per-ORM write- and read-path overhead; storage overhead measured on real tables, as DO-4 requires), on what hardware, with what disclosure. Results land under `bench/` with the raw data and the environment they came from. The PRD's line is "measured, not estimated", and a benchmark that cannot be re-run from the repository is an estimate.
- **WS-R** — migration tooling: `tools/backfill` per `docs/15` §1, resumable, rate-limited and idempotent (PRD CL-8, AD-6). `docs/15` §1.2 designs it as thin per-language frontends over one shared `PROCEDURE.md` (the state-table schema and cursor semantics), not a universal binary. WS-R writes `PROCEDURE.md`; gives `docs/15` §1.1's configuration hash its inputs, which it could not have until a client's resolved index registry was readable (G18, closed 2026-08-26); and builds the two frontends for the shipped adapters, a Django management command and a Node CLI for Prisma. The frontends for the four Phase 2 adapters are built in those adapters' workstreams (§5 item 4). `docs/15` §1.2's "Phase 1 ships two thin frontends" was never true, and is corrected when WS-R lands.

**WS-H is not reopened.** Its outstanding items are carried by name in the `docs/07` §7 entry of 2026-09-22: DO-1 and DO-6 go to Phase 3, the "Certifying an implementation" page waits for a first third-party report, and the `docs/06` re-run is owed before the dissemination track.

### 2.2 Isolation: three more cores, one implementer

The independence rule (`docs/17` §1) applies to every Phase 2 core exactly as it did to the TypeScript core: a core's implementer does not open, read, grep or list any other core or `tools/vector-gen/**`, and resolves a mismatch by recording it, not by looking. **Each new core adds its predecessors to the forbidden list** — a sibling binding is an implementation, not a specification — so the Go implementer may not read `core/java/**` or `core/dotnet/**` either.

What this can and cannot buy is already on record. The same AI assistant wrote both Phase 1 cores, in sessions with the other tree unread, and `docs/18` §1 says so; `docs/25` §6 records that the independence claim is weakened by it, and §10 item 4 that the bus-factor risk is accepted rather than mitigated. Phase 2 does not change the arrangement, so it does not change the claim. It does make the obligation explicit:

- **Every core's report carries a single-implementer statement** in the form `docs/18` §1 established: who wrote it, what they had read, and what the protocol can still find (spec ambiguities) and cannot (a shared misreading).
- **Every design and binding doc is a read input**, and the isolation statement names it. The JVM design's author read the TypeScript harness; the .NET design was written with the JVM design open. Where a design is wrong, that is a bug in the design and goes in the divergence log, not a reason to consult a core.
- **This plan is a read input too.** It was written from the specification, `docs/`, the two designs and the tracker. No core source was read to write it.
- **Cores are sequenced, never interleaved** (`docs/07` §3's rule for WS-B and WS-C, extended). The vector suite is pinned between them, as it was in Phase 1.

## 3. Milestones

Prefixed `P2-` so they cannot be confused with Phase 1's M0–M5, with PRD §7's metrics M1–M6, or with the stage numbers inside each core design.

| # | Milestone | Exit test |
|---|---|---|
| P2-M0 | **Phase 2 entry** | §1's four items: this plan merged with §5 settled or deferred by name; the `docs/14` §4 amendment closed on `main`; `compare_result_ids.py` and the cross job generalised to N with tests that bite; the Java binding doc merged |
| P2-M1 | **Java core passes the pinned suite** | A `docs/14` §4 report with `fail: 0` at the pinned vector suite version, every `out_of_band` entry `pass` (the length-bound pair under the amendment, the lone-surrogate entry by running it: Java strings can hold the operand), all six `pinned_decisions` keys, a divergence report with its isolation and single-implementer statements; `cross-core-result-ids` green across three reports; the cross job green at 3×3 including self-pairs |
| P2-M2 | **.NET core passes the pinned suite** | P2-M1's test for `core/dotnet`, met on **both** OS legs, with `environment.crypto_backend` distinguishing OpenSSL from CNG; the cross job green at 4×4 |
| P2-M3 | **Go core passes the pinned suite: the PRD Phase 2 exit criterion** | P2-M1's test for `core/go`; the cross job green at 5×5. Five languages pass identical vectors: one pinned suite version, reached by all five reports, with no `not-run` entry standing in for a pass (`docs/25` §10 item 3) |
| P2-M4 | **Adapters at level** | SQLAlchemy, Hibernate, EF Core and GORM each at L1 (PRD AD-4) and at the L2 shape spec §10.1 gives its ORM, with the §10.2 throws, and each with a backfill frontend passing the shared `PROCEDURE.md` scenarios; coverage matrices generated from green suites; each adapter a producer in the cross job, as the Django and Prisma adapters are. A cell spec §10.1 marks ⚠️ is claimed only as far as the adapter's binding doc says, and a ❌ is not attempted |
| P2-M5 | **Benchmarks published, migration tooling built** | `docs/NN-benchmarks.md` merged and `bench/` holding results for every shipped core and adapter, each re-runnable from the repository; `tools/backfill`'s `PROCEDURE.md` and its Django and Prisma frontends passing their resumability, idempotence and rate-limit tests. The four Phase 2 frontends count toward P2-M4, with their adapters |
| P2-M6 | **Phase 2 done** | Every workstream meets §4; a Phase 2 retrospective, in the shape of `docs/25`, measures this plan against what happened and decides what Phase 3 opens with, given the state of Gate 0b at that time |

**Sequencing is not calendarized.** `docs/25` §3 now supplies what `docs/07` §3 lacked, a calibration: Phase 1 took four and a half weeks against an estimate of about twelve. It is a fact about one maintainer directing an AI assistant, not about the work, and it measured calendar time and review load rather than person-hours. Relative sizing, on that basis: WS-I L · WS-J L · WS-K L (plus a design round) · WS-L M · WS-M M · WS-N L · WS-O L · WS-P L · WS-Q M · WS-R M. Each adapter's size includes its backfill frontend. SQLAlchemy is sized below the other adapters because its ORM is the closest to Django's in spec §10.1 and its core exists; that is an expectation, and P2-M6's retro checks it.

A vector-suite version bump during Phase 2 — a new G-issue's vectors, or a Gate 0b outcome — resets P2-M1 to P2-M3 for every core already past them: "identical vectors" is one version, reached by all five.

## 4. Definition of done (delta to `docs/07` §4)

`docs/07` §4 applies to every Phase 2 workstream unchanged: tests green in CI at a named suite version, every **[VERIFY]** in the workstream's docs resolved as *confirmed* or *corrected* with a dated `docs/07` §7 entry, the honest-limitations section shipped with the artifact, and a no-overclaim read by someone other than the author. Phase 2 adds, for a **core**:

- The binding doc's buffer section states the platform's largest byte buffer and whether it or spec §3.5's bound binds first — the per-binding obligation `docs/09` §4 has carried since #168.
- The single-implementer and isolation statements of §2.2, in the report and in the divergence report.
- Its `ucd-gen` emitter covered by CI's `--check`, so no Unicode table in the repository is hand-edited.
- Every OS the binding doc names as supported has a CI leg.

And for an **adapter**: a binding doc written before the code, the coverage matrix and refusal tests (PRD AD-2, AD-3), a backfill frontend that implements `PROCEDURE.md` unchanged through the adapter's encrypting write path (`docs/15` §1.1, *Safe writes*), zero cryptographic imports under `src/` asserted by the existing CI grep, and a cross-job producer leg.

## 5. Decisions

Four were made by the maintainer on 2026-09-22 and are logged in `docs/07` §7 when this plan merges. One is open.

1. **JDK floor for the Java core: 21. Decided.** HKDF is RFC 5869 written over `Mac.getInstance("HmacSHA512")`, about twenty lines, checked by the `kdf/` family, with the PRK erased after expand. The alternative was 25, with JEP 510's `javax.crypto.KDF`; neither needs a third-party HKDF. The ground is that the Hibernate adapter is in Phase 2's scope and is the reason this core exists, so the floor follows the audience. The JVM design's further claim, that Hibernate deployments skew toward 17 and 21, is unsourced and is not part of the ground; if the binding doc wants to state it, it cites a usage survey first.
2. **.NET target framework: open.** `net10.0` only, or also `net8.0` (the API floor, where the tag-size `AesGcm` constructors arrived). The .NET design recommends `net10.0` only; adding `net8.0` later is a build change, not a crypto change. **[VERIFY before deciding: which EF Core versions run on which frameworks, since WS-O inherits this floor.]** Needed before WS-J starts. The Argon2id library (Konscious or BouncyCastle) is decided by test at the design's capability-audit stage, not here.
3. **Order of work: each adapter straight after its core. Decided.** Java, Hibernate, SQLAlchemy, .NET, EF Core, Go, GORM (§2.1). The alternative was all three cores first, which reaches the exit criterion (P2-M3) sooner. The ground is Phase 1's evidence: the first adapter built on each core found a gap in that core's public surface that no vector could (G18 on the Python core, G22 on the TypeScript core, both closed as `docs/09` changes). Found right after the Java core, such a gap reaches the .NET and Go binding docs before those cores copy it; found after all three, it is fixed three times. The cost, accepted: P2-M3 comes later. SQLAlchemy's core already exists, so nothing forces its position. It goes after Hibernate, so that the Java-to-Hibernate feedback loop stays short, and before .NET.
4. **Migration tooling: a backfill frontend for all six adapters. Decided.** PRD AD-6 asks for backfill "per adapter", and `docs/15` §1.2 already designs per-language frontends over one `PROCEDURE.md`, so this takes AD-6 as written. The alternative, frontends for the two shipped adapters only, was set aside. WS-R builds `PROCEDURE.md` and the Django and Prisma frontends; each Phase 2 adapter builds its own as part of its definition of done (§4), against `PROCEDURE.md` unchanged. **What this requires of the order:** `PROCEDURE.md` is merged before WS-N, the first Phase 2 adapter, can close, so WS-R runs during WS-I, not after it. PRD DO-5, the migration cost model, is still **not** a Phase 2 deliverable: it asks for person-hours "from real migrations", and none is invited before Gate 0b (`docs/25` §3). The rows per second the tool reports (`docs/15` §1.3) are an input to that model, not the model.
5. **The Go design: drafted while WS-J is under way. Decided.** This keeps its review round off the critical path. A design is a read input for the Go implementer, not an implementation, so drafting it early breaks no isolation rule, provided its author does not read `core/java/**` or `core/dotnet/**` (§2.2).

## 6. Risk register (delta to `docs/07` §6 and PRD §9)

| Risk | Mitigation |
|---|---|
| **The `docs/14` §4 amendment is rejected**, leaving Java and .NET (length bound) and Go (lone surrogate) unable to claim L0 | Filed and decided at P2-M0, before any core is built on the assumption. If rejected, those cores report `not-run` honestly and do not count toward metric M1 (`docs/25` §10 item 3), and the Phase 2 exit criterion is restated as a decision in `docs/07` §7. It is not met by reading `not-run` as a pass |
| **Gate 0b changes a construction** (G1's commitment, ADR-0002's AEAD) after several cores ship | The cost is bounded — the vector expected values and the suite identifier (PRD §8) — and it is multiplied by the number of cores, which `docs/25` §10 accepts. Each binding keeps the construction behind `docs/09` §1's module boundaries (`internal/commitment`, `internal/aead` in the designs), so a regeneration touches one module per core, and the vectors say whether it worked |
| **The single-implementer arrangement repeats a misreading across five cores** | The same reader cannot find their own misreading, and the `docs/17` protocol only finds ambiguities. Stated in every report (§2.2). The fixes are outside engineering: a second human implementer for one core (`docs/07` §6's preferred fix, still not recruited), or Gate 0b |
| **Maintenance load and bus factor** grow with five toolchains, four more ORMs, and nightly runs of all of them | Accepted explicitly by `docs/25` §10 item 4. What this plan can do is keep every job reproducible from the repository and every toolchain pinned, so the load is operating the project, not remembering it |
| **Platform crypto differs between providers** (.NET's OpenSSL and CNG; JCA providers on the JVM) | Known-answer tests on every CI leg at each core's capability-audit stage. A divergence is a finding, recorded and resolved in the spec or the binding, never pinned per platform |
| **An Argon2id library differs from the vectors, deadlocks, or keeps a copy of its salt** | Decided per core by test against `blind-index/argon2id.json` and a salt-copy observation (both designs); the salt behaviour is documented, not claimed |
| **A new ORM's interception surface is narrower than `docs/04` says** (`docs/04`'s claims were partly unverified against source; AGENTS.md lists this as a standing review focus) | Each adapter's binding doc verifies its `docs/04` section against the ORM's source before claiming a level, and corrects `docs/04` where it is wrong |
| **Six backfill frontends drift apart** — four languages implementing one procedure | `PROCEDURE.md` is versioned from its first commit (`docs/15` §3), and every frontend runs one shared set of resumability and idempotence scenarios against a live database, the way the demo runs two stacks against one table. A frontend that needs a procedure change files an issue; it does not diverge locally |
| **Benchmarks become marketing** — CI runners are noisy and shared | WS-Q publishes its methodology before any number, discloses hardware and variance with every result, and publishes no cross-language ranking the methodology does not support |
| **CI time grows past usefulness** at five cores, six adapters and a 5×5 matrix | WS-L measures job time as it adds each core. The per-file workflow split that `docs/14` §2 argues against is reconsidered only on measured cost |

## 7. What Phase 2 deliberately does not build

TypeORM and Sequelize adapters (deferred by PRD §8 and still deferred) · the leakage estimator (`docs/15` §2; not in PRD §8's Phase 2 scope) · the migration cost model (DO-5; §5 item 4) · the standalone threat model and KMS-outage runbooks (DO-1, DO-6; Phase 3) · suite `0xFF02` in any core (registered and unbuilt while G7 is open) · async companions in the Java, .NET and Go cores, as their designs decide, revisited when the EF Core adapter's async write path is designed · any hosted service. Package releases of the new cores and adapters are allowed under PRD §8's five conditions and through `tools/release`, but are not a milestone, and none happens before the package's registry name is settled (Maven Central verifies ownership of a group id's namespace before it accepts one).
