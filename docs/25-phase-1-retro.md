# Phase 1 Retrospective

**Date:** 2026-09-22 · **Status:** Draft 1, decision made (§10) · **Purpose:** the third clause of milestone M5's exit test in [`docs/07-implementation-plan.md`](07-implementation-plan.md) §3: "Phase 1 retro decides Phase 2 entry." This document records what Phase 1 set out to do, what it did, what it measured, what it got wrong, and the decision on Phase 2. It is written by the maintainer, for the maintainer's own future reference and for anyone deciding whether to trust or join the project.

**This document is informative.** Nothing in it changes the specification, the vector suite, or any gate. Gate 0b (PRD §8) is open and stays open; nothing here invites adoption.

---

## 1. What Phase 1 was for

PRD §8 defines Phase 1 as "prove the format": Python and TypeScript cores, a shared vector suite in CI, Django and Prisma adapters at L1, one end-to-end demonstration, with the exit criterion *a value written by Python is read by TypeScript, and vice versa, in CI*. `docs/07` §3 refines that into five milestones, M1 to M5, and §4 into a definition of done per workstream.

Phase 1 was also the first measured unit of work for this project. `docs/07` §3 declined to calendarize it because there was "no calibration data for this team on this kind of work", and PRD DO-5 makes measured effort a deliverable. §3 below is that calibration.

## 2. Exit criterion and milestones

| | Exit test (`docs/07` §3) | Met | When | Evidence |
|---|---|---|---|---|
| PRD Phase 1 exit | A value written by Python is read by TypeScript, and vice versa, in CI | ✅ | 2026-08-23 | The N×N cross job, `docs/07` §7 entry of that date |
| M1 | Python core passes provisional vectors | ✅ | 2026-08-22 | §7 entry "M1: the Python core passes the pinned suite" |
| M2 | Independent reproduction from spec alone | ✅ with a stated weakness | 2026-08-22 | [`docs/18-m2-report.md`](18-m2-report.md), §1 isolation statement; see §6 below on independence |
| M3 | N×N cross CI green, on merge and nightly | ✅ | 2026-08-23 | `.github/workflows/conformance.yml` |
| M4 | Django L1+L2(a)(b), Prisma L1+L2(b)-with-throws, matrices generated, refusal tests | ✅ | 2026-08-25 to 2026-08-27 | `docs/12` §7, `docs/13` §6; the Prisma L2 claim was *narrowed* by the audit of 2026-08-27, not widened |
| M5, clause 1 | Demo runs the two-frontend cross-language scenario | ✅ | 2026-09-09 | [`docs/20-demo-patient-directory.md`](20-demo-patient-directory.md); CI job `demo` |
| M5, clause 2 | Docs current | ✅ | 2026-09-22 | Read as "the shipped artifacts describe themselves accurately", `docs/07` §7 entry of 2026-09-22; WS-H carried forward by name (§9 below) |
| M5, clause 3 | Phase 1 retro decides Phase 2 entry | this document | 2026-09-22 | §10 |

## 3. Calibration: estimate against measurement

PRD §8 estimated Phase 0 at about eight weeks and Phase 1 at about twelve. The plan's relative sizing (`docs/07` §3) put WS-B and WS-C, the two cores, at L and made them non-parallel under a single implementer.

| | Estimate | Measured | Bounds |
|---|---|---|---|
| Phase 0 (design, to Gate 0a) | ~8 weeks | 2 weeks | 2026-08-08 (first commit) to 2026-08-22 (Gate 0a closed) |
| Phase 1 (M1 to M5) | ~12 weeks | 4½ weeks | 2026-08-22 to 2026-09-22 |
| Both cores (WS-B, WS-C) | L each, sequential | M1 and M2 on the same day, 2026-08-22 | The vectors were pinned between them per the `docs/17` protocol |

Volume over the whole period, 2026-08-08 to 2026-09-22, from `git` and the tracker, counted on 2026-09-22:

| Measure | Count |
|---|---|
| Commits on `main` | 344 |
| Pull requests merged | 142 |
| Tracker issues opened / closed / open | 29 / 23 / 6 (all six open are Gate-0b-blocked) |
| Specification gaps filed as G-issues (`docs/issues/`) | 25 |
| Vector suite | `0.7.0-provisional`: 13 families, 286 cases |
| Test functions in tracked files, Python / TypeScript | 456 / 412 |
| Packages published (experimental, pre-1.0) | 4, at v0.1.3, on PyPI and npm |

Tracked source lines, rounded, excluding generated files and lockfiles: Python core 7k, TypeScript core 9k, Django adapter 10k, Prisma adapter 11k, tooling 6k, demo 3k, docs 8k.

**What the calibration means, and what it does not.** The estimates assumed a human team. The measured figures are for one maintainer directing an AI assistant, with the assistant writing most code and prose under the maintainer's review ([`docs/18`](18-m2-report.md) §1 says so for the TypeScript core; it holds for the rest). The compression is a fact about that arrangement, not about the problem. Two consequences follow. First, effort in person-hours, which DO-5 asks for, is not what was measured; calendar time and review load were. Second, the number that matters for a future adopter, DO-5's *migration* cost, was not measured at all: no real migration has happened, because none is invited before Gate 0b.

## 4. PRD goals, checked

| Goal (PRD §4) | Status after Phase 1 |
|---|---|
| **G1 Portability** | Proven at the provisional level: every vector passes in both cores, the N×N job runs both directions on every merge and nightly, and the demo moves rows between a Django and a Prisma frontend through a live Postgres database with no in-memory channel. Not proven at a frozen format, which Gate 0b controls. |
| **G2 Least-common-denominator implementability** | Tested for two of the seven ORMs named. The Prisma adapter is the evidence that the LCD is real: L2 is served at two `where` sites and refused with a throw everywhere the database answers first (`docs/13` §2.0). Five ORMs are untested. |
| **G3 Defensible cryptography** | The traceability is in the specification. The part that makes it defensible, a cryptographer reading it, has not happened. One outside input exists: the CFRG list on G7 (2026-08-23). |
| **G4 Honest limits** | Present in the specification and in all four package READMEs, and audited: the M5 sweep of 2026-09-09 found "one shipped claim that was the opposite of the truth" and the 2026-09-10 pass found an omission covering a false claim. The audit process works; it also shows the failure mode is live. |
| **G5 Auditability** | `docs/03` exists at clause level. Its citations were verified once, on 2026-08-08, and the re-run is owed before dissemination (`docs/06`, standing rule). DO-1, the standalone threat model, does not exist; spec §2 is the normative one. |
| **G6 Time-to-adoption under two weeks** | No data. Adoption is not invited before Gate 0b. |

## 5. Success metrics (PRD §7)

| Metric | Target | Now |
|---|---|---|
| M1 independent implementations passing the full suite | 3 by v1.0, 5 by v1.1 | 2 |
| M2 an implementation not written by the maintainers | 1 within 12 months of v1.0 | 0 |
| M3 named production deployments | 3 by 12 months post-v1.0 | 0, by design (Gate 0b) |
| M4 median time to first encrypted column | under two weeks | no data |
| M5 independent security review, published in full | before v1.0 | none; this is Gate 0b |
| M6 citations from a source the project does not control | — | 0. The Crypto Stack Exchange thread and the CFRG replies were project-initiated and do not count |

Every metric that can move before Gate 0b is M1, and only by writing more cores ourselves, which the metric's own wording discounts.

## 6. Risks, as they turned out

**Implementation-phase register, `docs/07` §6.**

| Risk | What happened |
|---|---|
| A G-issue closes differently than a tech spec assumed | Happened repeatedly (G15, G16, G22: "the signature it needed was not the one the issue described"). The `G<n>` marker sweep did its job each time. |
| Sync Argon2id is a product-killer for Prisma users | Measured on 2026-08-31 at spec minima: twenty synchronous derivations let the event loop take one turn in 871 ms; a `findMany` on an unencrypted table went from p99 0.8 ms to 352 ms under eight concurrent indexed lookups. `blindIndexAsync` shipped (2026-09-04). The cost is relocated to the threadpool, not removed; the same entry says so. |
| Unicode normalization drift across languages | No cross-core divergence recorded. The vendored folding table is untested beyond two languages. |
| Library-fact `[VERIFY]` flags wrong | The flagged facts held. The library fact that bit was one nobody flagged: Node caps HKDF `info`, found after M2 (2026-08-22 entry). Flags catch what you thought to doubt. |
| Single-author cores weaken M2's independence claim | Materialized and stated in `docs/18` §1: the same AI assistant wrote both cores, in a fresh session with the Python tree unread. The protocol still found real ambiguities (`docs/18` §3), but a second human implementer was not recruited. |
| Vector generator becomes a de-facto oracle | The rule held: `blind-index/argon2id.json` stayed held out until both cores agreed (2026-08-31). |
| Windows/line-ending corruption of vector bytes | No incident recorded. The harness reads the MANIFEST before any vector file. |

**PRD §9 risks.** *The spec is wrong in a way only a cryptographer would catch* is unchanged and is the risk; nothing in Phase 1 could reduce it. *Nobody adopts it* is untested. *Overclaiming* nearly happened twice and was caught by the M5 audit, which argues for keeping the non-author read as a standing rule rather than a milestone step. *Performance* is measured and real, and the mitigation is per-column IDF choice plus the async path. *Bus factor* got worse, not better: the project has one maintainer and no second human contributor, and the OpenSSF Sandbox threshold of three maintainers across two organizations is further away than when the PRD was written.

## 7. What worked

- **Spec first, vectors second, code third.** Every disagreement between the cores was settled by a vector, and every vector traces to a spec section. The 25 G-issues are the spec growing by what implementation found, not by what was imagined.
- **The M2 isolation protocol** (`docs/17`) found ambiguities the author of the spec could not see, even with the independence caveat in §6.
- **N×N in CI, both directions, on every merge and nightly.** It turned the central claim into a regression test.
- **The demo was not presentational.** Two adapters pointed at one live database found a live defect, three tool facts and one design conclusion that the N×N job, which compares each producer against its own recorded plaintext, structurally could not see (`docs/07` §7, 2026-09-09).
- **Refuse by default in the adapters.** Every unsupported operation throws with a typed error; the audits narrowed claims rather than widening them.
- **The append-only decision log** with dated entries and a present-tense sweep. When two entries disagreed, the later one superseded and said so.

## 8. What cost time

Recorded so that Phase 2, if it opens, does not pay for them twice.

- **Every review round found a claim the change made about itself that no test checked** (#101, #103, #108, #111, #114, #170). The fix that stuck: re-run every check against the final head, and treat "the last one" as a repo-wide grep, not a read of the named files.
- **Reviews are useful, not authoritative.** Some reviewed the wrong diff or assumed state the runner resets. Reproduce a finding's mechanism before acting on it. One high-effort review consumed two working sessions and produced nothing; reviews since have been kept cheap and incremental.
- **Release mechanics** took three attempts in one day (v0.1.0 to v0.1.2, 2026-09-18) before both registries had a complete release, and `pip install fieldseal-django` from the registry could not save to an indexed column, because every CI job installed the `argon2` extra explicitly and a bare install never ran. The dependency is fixed as of v0.1.3; the entry of 2026-09-18 records the gap that hid it.
- **Standing rules can be passed without noticing.** `docs/06`'s "before any public release" trigger was passed on 2026-09-18 and found on 2026-09-22.
- **A stated ground can be wrong while the conclusion is right.** Five log entries gave a reason for logging in `docs/07` §7 that `docs/06`'s own method line contradicts.
- **Windows.** Long or non-ASCII heredocs, tool-shim child spawns under Git Bash, and `localhost` resolving to IPv6 each cost a debugging round. All are written down in the contributor notes.

## 9. What Phase 1 did not do

- **WS-H, the documentation workstream**, carried forward by name in the `docs/07` §7 entry of 2026-09-22: PRD DO-1 (standalone threat model) and DO-6 (KMS-outage runbooks) to Phase 3; the "Certifying an implementation" page when the first third-party report arrives; the `docs/06` re-run before the dissemination track.
- **`docs/07` §8's list**, unchanged: no Java, .NET or Go core; no TypeORM or Sequelize adapter; no `bench/` methodology (DO-4); no hosted service; no tooling beyond the two `docs/15` CLIs, which are themselves designed and not built.
- **Backfill** (`docs/15` §1) is designed, not built; its §1.1 config hash has no defined inputs yet.
- **L3-row binding** in both adapters, deferred deliberately in v0.
- **A second human contributor.** Not attempted beyond the reviewer outreach in `docs/16` §4.

## 10. Phase 2 entry

PRD §8 defines Phase 2 as "prove the breadth": Java, .NET and Go cores; Hibernate, EF Core, GORM and SQLAlchemy adapters; published benchmarks; migration tooling; exit criterion five languages passing identical vectors. Design plans for the Java and .NET cores were drafted and reviewed on 2026-09-19 and are held outside the repository until a decision opens the work. One prerequisite is known and unbuilt: a `docs/14` §4 amendment for out-of-band entries whose operand a language cannot represent, without which no int-length core can claim L0 (closure comment on #167, 2026-09-20).

**What argues for opening Phase 2 now.** The five-language claim is the one no existing option can make, and it is the project's differentiator. Each additional core, built under the `docs/17` protocol, finds spec ambiguities the first two did not. M1 is the only PRD metric that can move before Gate 0b. The maintainer's calibration (§3) says a core is weeks, not months.

**What argues against.** Gate 0b is the bottleneck, and more cores do not attract cryptographers; reviewer recruitment has not succeeded in five weeks of trying (`docs/16` §4), and the one route that does not depend on a volunteer, a funded scoped review, is a budget decision that has not been made. Every core built before Gate 0b multiplies the regeneration cost if G1 or ADR-0002 change: bounded, but multiplied by N. The bus-factor risk worsens with every ten thousand lines a single maintainer must keep current. And the PRD's own ordering puts the independent review (metric M5) before v1.0, which Phase 2 does not reach either.

**The options considered.**

- **A. Open Phase 2 as scoped.** Three cores and four adapters. Highest surface area, highest regeneration exposure, and no adopter has asked for any of it.
- **B. Hold at Phase 1 until Gate 0b closes.** Spend the interval on outreach and on the funded-review decision. Nothing new to maintain; nothing new learned about the spec either.
- **C. Open Phase 2 narrowly: one core, no adapters.** One JVM or Go core under the `docs/17` protocol, preceded by the `docs/14` §4 amendment. Moves M1 to three, tests the spec against a third type system, and bounds the regeneration exposure to one more implementation. Adapters and the remaining cores wait for either Gate 0b or a first outside signal (an adopter, a reviewer, a third-party report).

**Decision (2026-09-22): A. Phase 2 opens as PRD §8 scopes it, with the Java core first.** The arguments against were weighed and stand as written above; the decision accepts the regeneration exposure and the maintenance load they describe, in exchange for the breadth claim. M5 is closed by this section, and the `docs/07` §3 row says so.

**What the decision commits to.**

1. **Sequencing.** The `docs/14` §4 amendment for out-of-band entries lands first, because without it no int-length core can claim L0. Then the Java core, under the `docs/17` isolation protocol, with the single-implementer statement in the form `docs/18` §1 established. Then .NET and Go. Each adapter follows its core; none precedes one.
2. **A Phase 2 plan.** `docs/07` is the Phase 1 plan and stays as written. Phase 2 needs its own workstreams, milestones, and definition of done before the first core is started; that plan is the next planning deliverable, and the two core designs drafted on 2026-09-19 become repository documents when it is written.
3. **What does not change.** Gate 0b, every MUST NOT in PRD §8, the provisional suite and its regeneration rule. Nothing in Phase 2 is offered for production adoption. PRD metric M1 moves toward its target of three only if a core passes the full suite; a core that passes with `not-run` entries does not count.
4. **The bus-factor risk is now the maintainer's explicit accepted risk.** §6 says it worsened; Phase 2 worsens it further. The mitigation the PRD names, a second human maintainer, is not scheduled. Recording that it is accepted is the honest alternative to pretending it is mitigated.
