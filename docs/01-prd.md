# PRD — Fieldseal

**Fieldseal: a portable specification and reference implementations for transparent field-level encryption-at-rest at the data-access layer.**

**Status:** Draft 1 · **Date:** 2026-08-08 · **Owner:** Manuel Rivera
**Naming note:** `Fieldseal` was selected 2026-08-08 after collision vetting; the earlier working name `OpenFLE` was dropped for one-letter confusability with OpenFHE, the prominent homomorphic-encryption library. As of 2026-08-08 the npm (`fieldseal` and the `@fieldseal/*` scope) and PyPI (`fieldseal`) names are claimed with placeholders, the GitHub org is `fieldseal-dev`, and crates.io / NuGet / Maven Central remain free. Still outstanding before public release: the PyPI `field-seal` upload, domain registration (`fieldseal.dev`, also required for the `dev.fieldseal` Maven groupId), and a trademark search of Classes 9 and 42 in USPTO TMSearch — which replaced TESS, named in earlier drafts. The full status table lives in the [README](../README.md); the checklist behind it is `internal/naming-tasks.md`.

---

## 1. Problem

A mid-size US software company holding regulated consumer data — patient records, financial account data, identity documents — has two realistic options for encryption at rest today, and both are inadequate.

**Option A: storage-layer encryption (TDE, encrypted EBS volumes, managed-database encryption).** One checkbox, near-zero cost, and it defends exactly one thing: physical loss of a disk. It provides transparent decryption to anything that can authenticate to the database, which means a compromised application, a leaked read-replica credential, a misconfigured backup bucket, or a curious DBA all see plaintext. PCI DSS v4.0.1 Req. 3.5.1.2 now says so explicitly, and has been enforceable since 31 March 2025.

**Option B: build application-layer encryption yourself.** 37signals — a company with unusual engineering depth — spent roughly two years of a senior engineer's time building this for one framework in one language, abandoned the first prototype, shipped an RCE via `Marshal` serialization that was caught by luck, and had a security audit find a deterministic-encryption flaw days before launch. A 60-person SaaS company with two platform engineers will not do better.

Between those, there is Option C: buy a data-privacy vault. Entry pricing starts around $12k–$23k/year plus per-tenant fees, and the architecture requires either moving PII out of your own database into a vendor's vault or routing all traffic through a proxy that discards your ORM's semantics. Several of these vendors have repositioned away from this use case in the last twelve months.

**What is missing is the middle: a well-specified, freely available pattern that a competent team can implement in weeks rather than years, in whatever language they already use, without handing custody of their data to a third party.**

And underneath that sits a problem nobody has addressed at all: **there is no portable format.** Data encrypted by Rails cannot be read by a Python analytics job. Data encrypted by a Java service cannot be read by a Go migration tool. Every implementation invents its own ciphertext layout, so application-layer encryption silently becomes a one-way door into a single language ecosystem.

---

## 2. What we are building

Three artifacts, in dependency order:

**1. A specification.** A normative, RFC-2119-language document defining a self-describing ciphertext envelope for a single database cell, a frozen cipher-suite registry, a key-derivation hierarchy, a blind-index construction with a declared leakage budget, and a key-provider interface. Accompanied by machine-readable test vectors.

**2. Reference implementations.** A core library per language implementing the spec and passing the shared vectors, plus a thin per-ORM adapter that wires the core into that ORM's value path. Core knows nothing about SQL; adapters know nothing about cryptography.

**3. An operational playbook.** Threat model, data-classification gate, zero-downtime migration procedure, key-rotation runbook, KMS-outage degradation modes, backup/restore semantics under rotation and crypto-shredding, and a published benchmark and cost model.

---

## 3. Users

**Primary — the platform or security engineer at a 50–500 person US software company handling regulated consumer data.** They have been handed a security questionnaire asking whether customers can bring their own keys. They have a Postgres database, one ORM, no cryptographer, and a quarter to deliver. They need a design they can defend to an auditor and implement without inventing crypto. **They are the person the entire project is written for.**

**Secondary — the compliance or GRC lead** who needs to map a control to a citation and produce evidence for a SOC 2 auditor, a PCI QSA, or a GLBA-covered client's vendor assessment. They need the compliance mapping document and the threat model, not the code.

**Secondary — the maintainer of an existing ORM encryption library.** If the envelope format is good, adopting it costs them little and buys their users interoperability. Rails, Prisma, and CipherSweet maintainers are the highest-value adopters because their users are already doing this.

**Explicit non-user — the large enterprise with a dedicated cryptography team and an HSM budget.** They will build or buy something bespoke. Designing for them adds complexity that the primary user pays for and does not need.

---

## 4. Goals

**G1. Portability.** A value encrypted by any conformant implementation is decryptable by any other conformant implementation given the same key material. Proven by a shared test-vector suite that every implementation runs in CI. *This is the goal that justifies the project's existence; if it is not met, the project is another library.*

**G2. Implementability at the least common denominator.** The mandatory conformance level must be achievable in every one of Django, SQLAlchemy, Prisma, TypeORM, Hibernate, EF Core, and GORM. Capabilities available in only some ORMs become optional, independently-claimable conformance levels.

**G3. Defensible cryptography.** Every mandate traceable to a NIST publication, an IETF RFC, or peer-reviewed literature. Every known-broken construction explicitly forbidden by name. A threat model that states what the design does *not* protect.

**G4. Honest limits.** A normative "Non-Goals and Known Limitations" section that reproduces the unsupported-operations list, the storage-overhead formula, the KMS-availability dependency, and the greenfield-versus-retrofit distinction. *A spec that oversells will be dismissed by the audience whose endorsement it needs.*

**G5. Auditability.** Compliance mapping at clause level, with caveats where the mapping is imperfect, so a user can hand it to a QSA or auditor without translation.

**G6. Time-to-adoption.** A team should get one encrypted column into production, with per-tenant keys and a working migration, in under two weeks — versus the roughly two years the best-documented from-scratch effort took.

---

## 5. Non-goals

**N1. Protecting against a compromised application process.** The keys are in that process. This is stated as a limitation, not solved.

**N2. Range queries, sorting, `LIKE`, regex, full-text search, or aggregates over ciphertext.** Order-preserving and order-revealing encryption are explicitly forbidden by the spec; the attack literature is unambiguous. Where these are needed, the honest answer is a deliberately-coarse plaintext bucket column with its own risk assessment, or a separate search system with its own access controls.

**N3. Replacing storage-layer encryption.** TDE and volume encryption stay in place underneath. This is a narrower control against a different adversary, not a substitute.

**N4. Becoming a hosted service, a proxy, or a vault.** Those architectures exist and are well served commercially. This is a pattern that runs inside the user's application against the user's own database.

**N5. Homomorphic encryption, secure enclaves, or trusted execution.** Out of scope. Where a TEE is available (SQL Server Always Encrypted with enclaves), it does more than this design can and users should know that.

**N6. Encrypting everything.** The spec mandates a data-classification gate. The marginal cost per encrypted column is high and non-obvious; "encrypt everything at the ORM layer" is the failure mode, not the goal.

**N7. A GDPR Article 17 erasure guarantee.** Key destruction is positioned as a documented technical measure supporting an erasure argument, subject to the EDPB's stated conditions. No regulator has endorsed it as standalone erasure and the spec will not claim otherwise.

---

## 6. Requirements

Priority: **P0** = required for v1.0 · **P1** = required for a credible v1.0 but can slip to 1.1 · **P2** = post-1.0.

### 6.1 Specification

| ID | Priority | Requirement |
|---|---|---|
| SP-1 | P0 | A versioned, self-describing ciphertext envelope: `format_version` (1B), `suite_id` (2B naming a complete frozen suite), `key_id`, a random 32-byte per-write derivation seed, nonce, ciphertext, tag, and (for non-committing AEADs) a key-commitment value. `format_version`, `suite_id`, `key_id`, and the seed are inside the AEAD's AAD and therefore authenticated. |
| SP-2 | P0 | A cipher-suite registry with **at most two suites in v1.0**: one FIPS-approved default, one clearly-labelled non-FIPS alternative. No per-algorithm header fields; no caller-settable `alg`. |
| SP-3 | P0 | Key commitment, either via a committing construction or an explicit commitment value. Rationale: partitioning-oracle attacks; AWS shipped a remediation for exactly this in December 2025. |
| SP-4 | P0 | A three-tier key hierarchy: KMS/HSM root KEK → per-tenant DEK (wrapped, cached with TTL and max-uses) → per-write derived key via an SP 800-108/800-56C approved KDF over the envelope's random derivation seed. Per-write derivation makes the SP 800-38D 2³² invocation ceiling structurally unreachable, independent of row-identity configuration. |
| SP-5 | P0 | Key-update chaining is forbidden (SP 800-57 §8.2.3.2 prohibits it for federal use). |
| SP-6 | P0 | Multiple simultaneously-decryptable key versions with exactly one active-for-write version. |
| SP-7 | P0 | A blind-index construction: distinct key per (tenant, table, column, index); truncation length chosen inside the band `2 ≤ Population × 2^(−b) < √Population`, rounded down; **mandatory application-side re-verification of decrypted candidates** — the index is a filter, never an answer. Index keys derive from a per-tenant index key that is a sibling of — not derived from — the data DEK, so data-key rotation never invalidates an index, and index-key rotation is an explicit rebuild. |
| SP-8 | P0 | A memory-hard KDF (Argon2id) is required for enumerable-domain indexes (SSN, email, phone, national ID). Plain HMAC permitted only for high-entropy or low-sensitivity fields. |
| SP-9 | P0 | A default-deny gate: indexing refused for domains under a configured cardinality floor or with known heavy skew (booleans, enums, gender, region, test results, diagnosis codes), overridable only with an explicit, logged, reviewed declaration. |
| SP-10 | P0 | Index length and the population estimate are recorded in schema metadata and **cannot be changed after writes begin**; the spec requires a documented multi-year population projection at design time. |
| SP-11 | P0 | Forbidden by name: order-preserving encryption, order-revealing encryption, any range-queryable index, any `LIKE`/regex index, any cross-column shared index key, tag truncation below 128 bits, and runtime algorithm selection from data. |
| SP-12 | P0 | A normative threat-model section explicitly disclaiming protection against a compromised application process and against a persistent adversary observing queries and logs; and requiring DB query logs, slow-query logs, and audit logs be treated as in-scope sensitive artifacts. |
| SP-13 | P0 | A normative "Non-Goals and Known Limitations" section (see N-list above), including the storage-overhead formula and the KMS-availability dependency. |
| SP-14 | P0 | Conformance levels L0–L4, independently claimable, with a published matrix of which ORMs can reach which. |
| SP-15 | P0 | Machine-readable test vectors covering every suite, key-derivation path, blind-index construction, and error case. |
| SP-16 | P1 | Context binding as an **optional** conformance level (L3): `tenant_id` — and at L3-row, `row_id` — carried in the length-prefixed canonical AAD and KDF context (spec §6.2), immutable surrogate identifiers only, `row_id` omitted by default. Optional because Rails — the most mature implementation — omits AAD entirely, proving it cannot be mandatory for a type-decorator-shaped design. |
| SP-17 | P1 | Distinguishable error types (`AAD_MISMATCH` vs `TAG_INVALID` vs `UNKNOWN_SUITE` vs `KEY_UNAVAILABLE`) and a documented re-binding procedure for legitimate PK or tenant migrations. |
| SP-18 | P1 | A crypto-shredding section reproducing the SP 800-88r2 §3.2.2 preconditions verbatim, mandating that shredding destroy both the data key and every derived index key, and requiring an inventory of derived artifacts (indexes, caches, queues, replicas, exports) with a shred procedure for each. |
| SP-19 | P1 | A PQC section scoped to key wrapping and key transport, not the field cipher, requiring that any long-lived envelope signature be replaceable without re-encrypting the payload. |
| SP-20 | P2 | A registry process for adding suites, so a NIST accordion mode can be absorbed when published. |

### 6.2 Core library (per language)

| ID | Priority | Requirement |
|---|---|---|
| CL-1 | P0 | **Synchronous** primary API: `encrypt(plaintext, ctx)`, `decrypt(ciphertext, ctx)`, `blind_index(plaintext, ctx)`, `is_ciphertext(bytes)`. Synchronous because Django, SQLAlchemy, TypeORM, Hibernate, Rails, and Sequelize cannot await in the value path. |
| CL-2 | P0 | A separate **async** `warm(contexts)` prefetch API and a documented cache contract, so KMS calls never happen in the value path. |
| CL-3 | P0 | A pluggable `KeyProvider` interface: `encryption_key(ctx)`, `decryption_keys(envelope_headers)`. Implementations: static, derived, and envelope (KMS-wrapped DEK plus local cache). |
| CL-4 | P0 | DEK cache with both max-age and max-uses thresholds, zeroization on eviction, and (where the platform allows) `mlock`/no-swap. Cache TTL documented as a security parameter, not a performance knob. |
| CL-5 | P0 | Three read modes: `strict` (ciphertext only), `permissive` (accept plaintext during migration), `readonly` (decrypt but never encrypt). |
| CL-6 | P0 | A `previous_schemes` decryption chain so rotation is not a hard cutover. |
| CL-7 | P0 | The shared test-vector suite runs in CI for every language, and CI fails on any divergence. |
| CL-8 | P1 | A resumable, rate-limited, idempotent re-encryption sweep — the only mechanism that permits destroying an old key, and therefore the actual crypto-agility mechanism. |
| CL-9 | P1 | Delegation of primitives to a validated cryptographic module where one is configured, since FIPS validation is a property of the build, not the algorithm. |

### 6.3 ORM adapters

| ID | Priority | Requirement |
|---|---|---|
| AD-1 | P0 | Adapters contain **no cryptography**. Their only job is a declaration surface, `FieldContext` assembly, and query rewriting where the ORM supports it. |
| AD-2 | P0 | Each adapter ships a **documented coverage matrix** stating exactly which write, read, and query paths it does and does not intercept. |
| AD-3 | P0 | Where a path is not covered and would silently write plaintext or silently return empty results, the adapter **must throw**, not degrade. Specifically: Prisma must reject `in:`, `contains:`, `startsWith:` over encrypted fields rather than silently mis-encrypting them; GORM must reject or intercept map-based `Updates`. |
| AD-4 | P0 | Django, SQLAlchemy, Prisma, Hibernate, EF Core, GORM adapters at L1. |
| AD-5 | P1 | TypeORM adapter, documented as reduced-capability: spurious re-encryption on every `save()` (the dirty-check runs the randomized transform), equality only via the explicit index-typed property (spec L2 (a) — no transparent rewriting), CLS-carried tenant context. |
| AD-6 | P1 | Zero-downtime backfill tooling per adapter: add-columns → dual-write → batched backfill → drop-legacy, with resumability. |
| AD-7 | P2 | Sequelize, ActiveRecord, Laravel/Doctrine adapters. |

### 6.4 Documentation and evidence

| ID | Priority | Requirement |
|---|---|---|
| DO-1 | P0 | Threat model as a standalone document. |
| DO-2 | P0 | Compliance mapping at clause level with caveats where mapping is imperfect. |
| DO-3 | P0 | A data-classification gate: which columns to encrypt, which to index, and which to leave alone. |
| DO-4 | P1 | Published benchmarks: latency and throughput deltas per operation, per ORM, per suite; storage overhead measured, not estimated. **The literature has none of this.** |
| DO-5 | P1 | A migration cost model: measured person-hours to encrypt N columns across M rows, from real migrations. |
| DO-6 | P1 | KMS-outage degradation modes (fail-closed vs serve-cached) with tested runbooks. |

---

## 7. Success metrics

Deliberately few, and chosen so they cannot be gamed by activity.

**Primary — does the portability claim hold?**
- **M1.** Number of independent language implementations passing the full test-vector suite. *Target: 3 by v1.0, 5 by v1.1.* Below 2, the format claim is unproven and the project has failed at its central purpose.
- **M2.** At least one implementation **not written by this project's maintainers** passes the vectors. *Target: 1 within 12 months of v1.0.* This is the single strongest signal that the spec is well written.

**Secondary — is anyone using it?**
- **M3.** Production deployments with a named, referenceable organization. *Target: 3 by 12 months post-v1.0.* Quality over count — three organizations willing to be named is worth more than three hundred GitHub stars.
- **M4.** Median time from "first read the docs" to "one encrypted column in production," self-reported. *Target: under two weeks.*

**Tertiary — is it credible?**
- **M5.** An independent security review of the spec and at least one implementation, published in full including unresolved findings. *Target: before v1.0 is tagged.* This is a gate, not a metric.
- **M6.** Citations or adoption references from a source not controlled by the project — an OWASP page, a conference talk, a competing library's docs, an auditor's guidance.

**Explicitly not metrics:** GitHub stars, package download counts, social media engagement, number of blog posts published. All are trivially inflatable and none indicate the format works.

---

## 8. Scope and phasing

**Phase 0 — Design (now → ~8 weeks).** Spec v0.1 (this repo), threat model, compliance mapping, conformance-level definition, first-draft test vectors. Circulate for review.

**Exit criterion — split into two gates (revised 2026-08-22).** The original single criterion — *at least two people with real cryptographic credentials have read the spec and their objections are addressed or documented as open questions* — gated two different things at once: permission to write code, and permission to freeze the format and invite adoption. Reviewer recruitment has not succeeded on the timeline assumed, and the two permissions do not carry the same risk, so they are now separate gates.

- **Gate 0a — permission to implement.** Every specification gap either resolved or *provisionally* resolved with the provisional answer written normatively, marked **[PROVISIONAL]** in the spec, and linked to the tracker issue and reviewer question that would close it. ADR-0001 and ADR-0002 decided provisionally with reasoning recorded. All registered suites carry provisional identifiers in the reserved `0xFF00`–`0xFFFF` range (spec §4.8). **This gate can be closed by the project itself, and is what unblocks Phase 1.**
- **Gate 0b — permission to freeze.** Unchanged from the original criterion: at least two people with real cryptographic credentials have read the spec and their objections are addressed or documented as open questions. **Until this closes, the project MUST NOT** assign a non-provisional suite identifier, publish the vector suite as anything but `-provisional`, describe any implementation as conformant to a frozen format, invite production adoption, or run the Phase 3 dissemination track (§5 of `docs/05-dissemination.md` and beyond). Gate 0b is not deferred, weakened, or satisfiable by self-review.

*Why this is not a loophole.* Gate 0b's substance is untouched; what changed is that it no longer blocks work whose correctness does not depend on it. The Phase 1 deliverables — the vector harness, the cross-implementation CI matrix, the envelope framing, the two cores, the Django and Prisma adapters, the tooling — are unaffected by which commitment construction G1 settles on or which AEAD ADR-0002 picks. What *is* affected is a bounded, enumerable set: vector expected values, and the suite identifier they were produced under. The project is choosing to pay that regeneration cost rather than to stall, and spec §4.8 exists so that the choice cannot leak into anyone's production database while it is being made.

**Phase 1 — Prove the format (~12 weeks).** Core libraries in Python and TypeScript. Shared test vectors in CI. Django and Prisma adapters at L1. One end-to-end demonstration application. **Exit criterion:** a value written by Python is read by TypeScript, and vice versa, in CI.

**Phase 2 — Prove the breadth (~12 weeks).** Java, .NET, and Go cores. Hibernate, EF Core, GORM, SQLAlchemy adapters. Benchmarks published. Migration tooling. **Exit criterion:** five languages passing identical vectors — which is the claim that no existing option can make.

**Phase 3 — Harden and disseminate (ongoing).** Independent security review. OWASP Cheat Sheet contribution. IACR ePrint and arXiv. OpenSSF Sandbox application. Conference submissions. Adopter case studies.

**Deliberately deferred:** TypeORM and Sequelize adapters (reduced capability, high support cost); vector/embedding encryption (real forward gap, but early); anything involving a hosted service.

---

## 9. Key risks

| Risk | Assessment | Mitigation |
|---|---|---|
| **The spec is wrong in a way only a cryptographer would catch.** | High likelihood, catastrophic impact. 37signals shipped a deterministic-encryption flaw and an RCE with better resources than this project has. | Independent security review is a **release gate**, not a nice-to-have — it is Gate 0b (§8), and no suite freezes, no vector suite is published as stable, and no adoption is invited without it. Freeze suites rather than offering agility. Copy proven constructions (Tink, AWS ESDK, Vault) rather than inventing. **Gate 0a's residual risk, stated plainly:** implementation proceeds against constructions that are provisional, so a reviewer finding forces regenerated vectors and a retired suite identifier. Spec §4.8 bounds that cost — provisional identifiers live in a reserved range, so data written under one is identifiable from stored bytes alone, and cores refuse to write under one unless the operator explicitly armed it. |
| **Nobody adopts it, because the format problem is invisible until you hit it.** | Medium-high. Portability is a benefit you feel in year three. | Lead adoption messaging with the *immediate* pain — per-tenant keys and the BYOK questionnaire question — and treat portability as the reason to pick this one. Target existing library maintainers, whose users already have the problem. |
| **A vendor ships an equivalent open format first.** | Medium. AWS's structured-encryption spec is 80% of the way there and they could generalize it. | This would be a good outcome for the world and a bad one for the project. Mitigate by profiling AWS's format where compatible rather than competing with it, and by engaging AWS early. |
| **Blind-index leakage guidance turns out to be wrong for real datasets.** | Medium. AWS's beacon-length formulas are engineering heuristics, not peer-reviewed leakage bounds, and AWS hedges on them. | State this explicitly in the spec. Require dataset-specific evaluation. Ship a tool that measures actual distribution skew rather than trusting the formula. |
| **Maintainer bus factor.** | High. `lockbox`, `blind_index`, and Acra are all cautionary examples — the best options in this space are single-maintainer or stalled. | Structure for multiple maintainers from day one; OpenSSF Sandbox requires 3 maintainers across 2 organizations, which is a useful forcing function. Spec-first means the artifact outlives any implementation. |
| **Overclaiming compliance value damages credibility.** | Medium, and self-inflicted. SOC 2 does not require this; CIS says storage-layer encryption meets the minimum; insurers do not ask. | The compliance document states what each framework does *not* require, first. Lead with PCI 3.5.1.2, GLBA 314.4(c)(3), and NYDFS 500.15, which are unconditional, and with the BYOK commercial driver. |
| **The performance cost makes it impractical for the target user.** | Medium. Argon2id blind indexes at the spec §7.3 invocation (3 iterations / 32 MiB) run 10–100 ms per query term. | Benchmark early and publish honestly. Make KDF strength a per-column decision tied to domain enumerability. If a configuration is impractical, say so rather than shipping it. |

---

## 10. Open questions

1. **Profile AWS's structured-encryption format, or define a new one?** Profiling buys interoperability with a shipping implementation and reduces novelty risk; defining fresh buys freedom from DynamoDB item semantics and AWS KMS assumptions. This is the single highest-leverage unresolved decision and should be settled before Phase 1.
2. **Which FIPS-approvable AEAD?** AES-256-GCM is CAVP-testable but not key-committing and catastrophic under nonce reuse. AES-256-CBC-HMAC-SHA-512 is committing and FIPS-composable but 49–64 bytes of expansion per field. AES-GCM-SIV is the right engineering answer and is not FIPS-approved. Needs a decision with a lab's input.
3. **Is `row_id` in the AAD worth the operational hazard?** It prevents intra-database ciphertext swapping, and it makes any legitimate PK migration a decryption failure. Currently proposed as optional and off by default.
4. **Binary or text column storage?** Binary saves the 33% base64 tax on every row forever; text is vastly easier to migrate, debug, and move between systems. Probably: mandate binary, permit text with a documented penalty.
5. **How much does the spec say about non-relational stores?** Document databases, key-value stores, and search indexes all have the same problem with different mechanics. Probably out of scope for v1.0, mentioned as future work.

---

## 11. Appendix — evidence track

Kept deliberately separate from the engineering artifacts, in `05-dissemination.md`. Nothing in this PRD, the spec, or the code should be written *for* a petition; the record is a byproduct of doing the work well. The dissemination document tracks venues, timelines, and third-party evidence opportunities as a project-management concern, not a design input.
