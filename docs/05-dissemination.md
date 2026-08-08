# Dissemination and Evidence Track

**Date:** 2026-08-08 · **Status:** Draft 1

> **Separation of concerns.** Nothing in the research memo, the PRD, the specification, or the code should be written *for* a petition. This document tracks dissemination as a project-management concern. The record is a byproduct of doing the work well and publishing it properly — which is also the only version that survives scrutiny.

---

## 1. Sequencing principle

Cheapest credible thing first. Each step's output becomes the credential for the next.

```
OWASP Cheat Sheet PR  ──►  IACR ePrint + arXiv  ──►  OpenSSF Sandbox
   (days, high reach)         (weeks, citable)         (needs 3 maintainers)
                                     │
                                     ▼
                    Enigma track + OWASP Global AppSec
                                     │
                                     ▼
                       IEEE S&P magazine ──► CACM Practice
```

Adopter case studies and the independent security review run in parallel from Phase 2 onward.

---

## 2. Step 1 — OWASP Cheat Sheet Series (do this first)

**The clearest, cheapest opportunity found in the entire research pass.**

The current [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) covers the stack levels at which encryption can occur ("at the application level… at the database level… at the filesystem level… at the hardware level"), key management, and envelope encryption with DEK/KEK hierarchies.

**Confirmed gaps — none of the following are covered:**

- No ORM or framework guidance whatsoever (no Hibernate, SQLAlchemy, Active Record, Entity Framework, Django, GORM)
- No field/column-level specifics — database-native TDE is named but not developed
- **No searchable-encryption coverage at all**
- No practical code examples — the sheet remains theoretical
- No schema design guidance (how to structure encrypted columns, store per-row key metadata, handle indexes)
- No performance or query-efficiency trade-off discussion

That is almost exactly the surface this project covers.

**Mechanism:** a pull request to [`OWASP/CheatSheetSeries`](https://github.com/OWASP/CheatSheetSeries). No membership, no fees, days of effort. The Cheat Sheets are among the most-read practitioner security documents in existence.

**Do this before any standards body.** It is also the best possible test of whether the writing is clear to practitioners.

---

## 3. Step 2 — Preprints

| Venue | What goes there | Effort | Notes |
|---|---|---|---|
| **[IACR ePrint](https://eprint.iacr.org/)** | The ciphertext-format and blind-index design note | Low | Rolling submission, light admin screening, near-immediate. Gives a citable artifact before any RWC or CFRG conversation. |
| **arXiv cs.CR** | The architecture and evaluation paper (ORM interception analysis, benchmarks, migration cost model) | Low | Rolling. **First-time authors need endorsement in cs.CR** — arrange this early. |

The benchmark and migration-cost work is the strongest candidate for the arXiv paper precisely because **the literature has none of it** — no published person-months, no measured latency deltas, no storage-overhead measurements for application-layer encryption.

---

## 4. Step 3 — Governance home

| Option | Requirements | Assessment |
|---|---|---|
| **OpenSSF Sandbox** (recommended) | 3+ maintainers from **2+ organizations**; mission alignment; **1 TAC or Working Group sponsor**; security best practices. Apply by PR to [`ossf/tac`](https://github.com/ossf/tac/blob/main/process/project-lifecycle.md). | **Best fit.** Genuinely attainable. The binding constraint is *3 maintainers across 2 organizations* — which you need **before** applying, so recruit early. Incubating adds a Silver badge and multi-party adoption; Graduated adds 5 maintainers across 3 orgs, Gold badge, and a third-party security audit. Archived if dormant 9+ months. |
| CNCF Sandbox | GitHub issue form; TOC reviews ~every two months, ~7–10 applications per session, FIFO. | **Poor fit.** CNCF scope is cloud-native infrastructure; an ORM-layer library is not obviously that, and the docs tell non-fitting projects to consider other foundations. |
| OASIS Open Project | One or more organizations committed as **Project Sponsors** whose combined annual dues meet a Board-set threshold. Standards path: Releases → Project Specifications (Special Majority Vote) → **OASIS Standard, requiring three Statements of Use**. | **Viable but costs money.** Only worth it once a real multi-vendor interop story exists and someone will fund sponsorship. The three-Statements-of-Use requirement is a good long-term north star. |
| Apache Incubator | A Champion who knows the ASF, a `[PROPOSAL]` to the general list, IPMC vote. | **Wrong shape.** ASF grows *communities around code*, not *specifications*. |

**Recommendation:** OpenSSF Sandbox for the reference implementations. OASIS only later, if at all.

---

## 5. Step 4 — Standards track

| Route | Assessment |
|---|---|
| **IETF Independent Submission (ISE)** | **The pragmatic route.** Publishes RFCs outside working-group consensus; the IESG performs a conflict review under RFC 5742 rather than approving content. Yields a citable RFC number without WG adoption politics. Governed by RFC 8730 / RFC 5744. See [RFC Editor — Independent Submissions](https://www.rfc-editor.org/about/independent/). |
| **IRTF CFRG** | Chartered as "a general forum for discussing and reviewing uses of cryptographic mechanisms"; adopts Informational RFCs (lineage: RFC 1321, RFC 2104). Chairs: Alexey Melnikov, Nick Sullivan, Stanislav V. Smyshlyaev. **Realistic read:** CFRG reviews *cryptographic mechanisms*, not application data-layer architectures. The **ciphertext wire format** (AEAD construction, AAD binding, key-hierarchy encoding) is arguably in scope; the ORM architecture is not. Expect a long, skeptical process. |
| **IETF COSE WG** | Worth considering and rarely mentioned: COSE is chartered for CBOR-based object signing and encryption, and a compact encrypted-field envelope is closer to COSE's remit than CFRG's. CBOR compactness suits per-cell overhead far better than JWE's base64+JSON. |
| IETF LAMPS | Scoped to PKIX/S/MIME. **Not a fit.** |
| **NIST / NCCoE** | **No live vehicle.** The directly relevant NCCoE project — *Data Confidentiality: Identifying and Protecting Assets Against Data Breaches* → **NIST SP 1800-28** — is **completed and finalized**, with no open comment period. The current NCCoE portfolio (PQC Migration, Genomic Data, Genomics PETs, mDL, Ransomware CSF Profile, Digital Identity Lab) has no data-at-rest project. **The one legitimate and underused angle:** frame ciphertext-format crypto-agility as PQC-migration-relevant and respond to the PQC Migration work — re-encrypting every field in a database *is* the PQC migration problem for data at rest. |
| OASIS TC formation | Minimum **5 people from ≥2 OASIS member organizations**; 14-day public comment on the charter; 30-day Call for Participation; ~2 months from finished charter to first meeting. An alternative to the Open Project route. |

---

## 6. Step 5 — Conferences

**Honest read: only two venues on this list are a natural fit for a defensive reference architecture.**

| Venue | CFP window (verified) | Difficulty | Notes |
|---|---|---|---|
| **USENIX Security — Enigma Track** | '26 track: submissions 31 Mar 2026, notify 13 May 2026. Expect ~March for '27. | **Moderate — genuinely attainable** | **Best fit.** Explicitly "looking for submissions from outside of academia." 20-min talk + 10-min Q&A. Must be vendor-neutral. Requires a video of prior speaking — **film a meetup talk early to satisfy this.** ⚠️ The standalone Enigma conference is **suspended** ("no immediate plans"); it survives only as this track. |
| **OWASP Global AppSec US** | 2026: CFP 8 Apr → 29 Jun 2026; event 5–6 Nov 2026, SF. EU 2027 Vienna. | **Moderate** | **Best strategic fit** given the Cheat Sheet gap in §2 — land the PR first, then submit the talk. Rejects product pitches and AI-generated submissions; rewards detailed outlines and real-world application. |
| **Real World Crypto 2027** | Submit **15 Oct 2026**; notify 10 Dec 2026; event 5–7 Apr 2027, Seattle. | **Hard — treat as a long shot** | Right audience for the crypto/format half. ≤3-page abstract; explicitly values speakers who can address non-academics. Very few contributed slots against a large, strong field. Do not plan around acceptance. |
| **Regional BSides** | Rolling, year-round | **Easy** | Not usually on these lists, but the right place to iterate the talk (and film the speaking video) before Enigma and AppSec. |
| **DEF CON Villages** (AppSec Village, Crypto & Privacy Village) | Separate, far less competitive CFPs than the main stage | **Easy–moderate** | ⚠️ Official DEF CON CFP window not verified; check defcon.org. Main stage is offense-biased and a poor fit. |
| **PyCon US** | 2026 closed. Expect ~Sep–Dec opening for 2027. | **Moderate** | Good venue for the Python reference implementation. Hundreds of proposals annually; max 3 per speaker. |
| **RubyConf** | — | Moderate | ⚠️ **RailsConf is dead** — 2025 (Philadelphia, 8–10 Jul) was the final edition; Ruby Central refocused on RubyConf. Redirect any Ruby outreach there. |
| **RSA Conference** | RSAC 2027 CFP opens **15 Sep 2026** | **Hard** | Enormous submission volume, no published acceptance rate, skews vendor/CISO. Open-source content can land but needs a business-outcome framing. |
| **Black Hat** | USA '26 closed 23 Mar 2026; **Asia '27 CFP open 26 Aug – 16 Oct 2026** | **Hard / poor fit** | Review board prioritizes novel vulnerabilities, tools, and PoC code. A defensive spec rarely lands. |
| **KubeCon NA** | 2026 CFP closed 31 May 2026 | **Very hard / poor fit** | ORM-layer encryption is not cloud-native infrastructure. |
| **QCon SF** | ⚠️ **No open CFP** | **Unreachable by submission** | Sessions are curated by an international program committee and track hosts; speakers are effectively invited. The route is relationship-building with a track host. |
| IEEE S&P / ACM CCS / USENIX Security main track | S&P '27 Cycle 1: abstract 4 Jun / paper 11 Jun 2026. CCS '26 Cycle B: abstract 22 Apr / paper 29 Apr. USENIX Sec '27 Cycle 1: 25 Aug 2026. | **Very hard / poor fit** | These demand research novelty. A reference architecture without new results will desk-reject. |

**Confirmed dead or dormant — do not target:** Strange Loop (final edition 2023) · RailsConf (final edition 2025) · standalone USENIX Enigma (suspended) · LocoMocoSec (no edition since 2024, no discontinuation notice — treat as dormant).

---

## 7. Step 6 — Written publication

| Venue | Process | Difficulty |
|---|---|---|
| **USENIX ;login:** | **Proposal-first** to `login@usenix.org` — six questions on topic, type, audience, timeliness, visuals, length. 2–5 pages / 1,200–3,000 words. Rejects previously-published work and marketing. Authors retain copyright. | **Easiest peer-facing venue.** Proposal-first means a cheap, fast go/no-go. ⚠️ The page actively solicits submissions but current publication cadence could not be confirmed (;login: moved away from the traditional print magazine after 2020). **Email before investing.** |
| **IEEE Security & Privacy magazine** | Peer-reviewed; accepts case studies, tutorials, surveys. Explicitly "not a research journal." | **Moderate — excellent fit.** A reference architecture plus tutorial plus comparative analysis is precisely what they say they want. **The anchor peer-reviewed practitioner piece.** Contact the EiC if scope is uncertain. |
| **ACM Queue** | Editorial-board driven; the effective route is pitching a board member. | **Moderate.** Strong prestige-to-effort ratio for a "here's the pattern and why it's hard" piece. |
| **CACM Practice Section** | ≤10 pages / ~6,000 words. Excludes vocational tutorials and opinion. Prior *blog* publication is OK; prior formal publication is not. CC-BY, authors retain copyright. Co-chairs **Nachi Nagappan and Terence Kelly** explicitly invite pre-submission contact. | **Moderate–hard, highest prestige.** Must clear "broadly interesting to all practitioners," not just security people. The named-editor pre-pitch materially de-risks it. **The stretch target.** |

---

## 8. Industry bodies

| Body | Route | Assessment |
|---|---|---|
| **OWASP** | PR to the Cheat Sheet Series | See §2. Do it first. |
| **CSA (Cloud Security Alliance)** | Join a working group (individual or via a chapter); participate in Open Peer Reviews with published deadlines. | **Moderate effort, real reach into enterprise procurement**, since CAIQ is what buyers actually send. The CCM v4 CEK domain (21 controls) is the natural anchor. ⚠️ The mechanism for proposing a *brand-new* document isn't published — join a WG and propose internally. |
| **CIS** | Free account at CIS WorkBench; contribute as SME, Editor, Technical Writer, or Tester. | **Awkward fit** for a new benchmark (Benchmarks are platform-hardening configs). **The better target is influencing Safeguard 3.11 guidance**, which currently frames application-layer encryption as merely optional — and which is one of the strongest arguments *against* this project's premise. Changing it would be high-leverage. |
| **HITRUST** | — | ⚠️ **No open external contribution pathway found.** Proprietary, commercially licensed. Matters as a demand signal in healthcare; not a dissemination target. **Deprioritize.** |

---

## 9. Third-party evidence opportunities

These are the artifacts that carry weight because someone else produced them.

1. **An independent implementation passing the test vectors, written by someone outside the project.** The single strongest signal that the specification is well written, and PRD metric M2.
2. **An independent security review, published in full including unresolved findings.** A release gate, not a nice-to-have. 37signals had one and it caught a deterministic-encryption flaw days before launch.
3. **Named adopter organizations** willing to be referenced. Three is worth more than three hundred GitHub stars.
4. **Adoption by an existing library.** Rails, Prisma, or CipherSweet maintainers adopting the envelope format would be decisive. Their users already have the problem.
5. **Citation in a framework or standard** — an OWASP page, a CSA document, an auditor's guidance, a competing library's docs.
6. **Conference acceptances** at Enigma or OWASP Global AppSec.
7. **Peer-reviewed publication** in IEEE Security & Privacy or CACM Practice.

---

## 10. Near-term calendar

| Window | Action |
|---|---|
| **Aug–Sep 2026** | Circulate spec v0.1 for informal cryptographic review. Recruit maintainer #2 and #3 (OpenSSF prerequisite). Arrange arXiv cs.CR endorsement. Draft the OWASP Cheat Sheet PR. |
| **Sep–Oct 2026** | Submit the OWASP PR. Post the IACR ePrint format note. **RWC 2027 contributed-talk deadline is 15 Oct 2026** — submit even though it is a long shot; the abstract is reusable. |
| **Oct–Dec 2026** | Phase 1 build (Python + TypeScript cores, cross-language CI). Film a meetup or BSides talk to satisfy the Enigma speaking-video requirement. Email `login@usenix.org` with a ;login: proposal. |
| **Jan–Mar 2027** | Phase 2 build. **Enigma '27 track submission (~March).** Publish benchmarks and the migration cost model to arXiv. |
| **Apr–Jun 2027** | **OWASP Global AppSec CFP (Apr–Jun).** OpenSSF Sandbox application, assuming maintainer count is met. Commission the independent security review. |
| **H2 2027** | IEEE S&P magazine submission. First adopter case studies. v1.0 tag gated on the security review. |

---

## 11. Standing rules

1. **Never write a document, a spec section, or a commit message for the record.** If it would not survive the question "would you have written this anyway?", do not write it.
2. **Publish negative results.** The finding that SOC 2 does not require this, that CIS says storage-layer encryption suffices, and that insurers do not ask — that analysis is more useful to practitioners than another vendor claim, and it is the kind of thing that gets cited.
3. **Every claim gets a citation or a flag.** The compliance document's "not verified" list (§8 there) is a feature. Reviewers trust documents that say what they don't know.
4. **Third-party artifacts beat self-produced ones, every time.** Prefer one external implementation over ten blog posts.
