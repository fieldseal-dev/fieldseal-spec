# Fieldseal

**A portable specification and reference implementations for transparent field-level encryption-at-rest at the data-access layer.**

**Read it on the web: [fieldseal.dev](https://fieldseal.dev)** — the specification and every design document below, rendered and cross-linked.

> **Status: pre-alpha design work.** The specification is a working draft. **It has not been independently reviewed**, and every cipher suite in the registry is provisional for that reason (spec §4.2, §4.8) — implementations refuse to encrypt under a provisional suite unless an operator explicitly acknowledges it. Nothing here is ready for production use.
>
> **Naming and namespaces — status checked 2026-08-10.** The earlier working name `OpenFLE` was dropped for one-letter confusability with [OpenFHE](https://openfhe.org/).
>
> | Namespace | Status |
> |---|---|
> | GitHub org `fieldseal-dev` | **Ours.** Canonical home; holds this repository |
> | `fieldseal.dev` | **Ours.** Registered and live — this repository's `www/` published to GitHub Pages, HTTPS enforced |
> | npm `fieldseal` | **Claimed** — 0.0.0 placeholder |
> | npm `@fieldseal/*` scope | **Claimed** — org created, `@fieldseal/core` 0.0.0 placeholder published |
> | PyPI `fieldseal` | **Claimed** — 0.0.0 placeholder |
> | PyPI `field-seal` | **Not yet claimed** — distribution built, upload pending. PEP 503 does *not* fold this into `fieldseal`; they are separate names |
> | Maven Central `dev.fieldseal` | **Unclaimed.** The groupId needs the domain, which is now held, so this is claimable whenever Phase 1 needs it |
> | crates.io · NuGet | **Unclaimed and free** |
> | `fieldseal.org` | **Available** — no DNS delegation as of this check |
> | `fieldseal.io` | **Gone.** Registered by someone else since the previous check and parked (serves HTTP 410). It was listed as available here on 2026-08-08; it is not |
> | `fieldseal.com` | **Held by someone else.** `.dev` is the canonical home; nothing here implies `.com` |
> | GitHub org `fieldseal` (bare) | **Unobtainable.** Squatted but empty, and GitHub does not reclaim names for inactivity — a registered trademark is the only route, which is not worth pursuing for the org name alone |
>
> Trademark clearance is **not yet run**. The only adjacency found in casual search is "Field Seal" farm toolboxes — a different class with no software presence — which is not a substitute for a search of Class 9 and Class 42 in [TMSearch](https://tmsearch.uspto.gov) (the USPTO retired TESS; earlier drafts of this file named it). Results will be recorded in `NAMING.md` with the search date and classes.

---

## The problem

A mid-size company holding regulated consumer data has three options today, and all three are bad.

**Storage-layer encryption (TDE, encrypted volumes)** defends exactly one thing: physical loss of a disk. It provides transparent decryption to anything that can authenticate to the database. PCI DSS v4.0.1 Req. 3.5.1.2 says so explicitly, and has been enforceable since 31 March 2025: *"disk-level encryption is not appropriate to protect stored PAN on computers, laptops, servers, storage arrays, or any other system that provides transparent decryption upon user authentication."*

**Building application-layer encryption yourself** took 37signals roughly two years of a senior engineer's time for one framework in one language — with an abandoned first prototype, an RCE via `Marshal` serialization caught by luck, and a deterministic-encryption flaw found by audit days before launch.

**Buying a data-privacy vault** starts around $12k–$23k/year plus per-tenant fees, and requires either moving your PII into a vendor's vault or routing traffic through a proxy that discards your ORM's semantics.

And underneath all three sits a problem nobody has addressed: **there is no portable format.** Data encrypted by Rails cannot be read by a Python job. Every implementation invents its own ciphertext layout, so application-layer encryption becomes a one-way door into a single language ecosystem.

## What this is

Three artifacts:

1. **A specification** — a self-describing ciphertext envelope for a single database cell, a frozen cipher-suite registry, a key hierarchy, a blind-index construction with a declared leakage budget, and a key-provider interface. With machine-readable test vectors.
2. **Reference implementations** — a core library per language (Python, TypeScript, Java, .NET, Go) that all pass the same vectors, plus thin per-ORM adapters. Core knows nothing about SQL; adapters know nothing about cryptography.
3. **An operational playbook** — threat model, data-classification gate, zero-downtime migration, key-rotation runbook, KMS-outage degradation modes, and published benchmarks.

## What this is not

- **Not protection against a compromised application process.** The keys are in that process.
- **Not range queries, sorting, `LIKE`, or full-text search over ciphertext.** Order-preserving and order-revealing encryption are explicitly forbidden by the spec; the attack literature is unambiguous (Grubbs et al., S&P 2017: 90–99% recovery rates on real data).
- **Not a replacement for storage-layer encryption.** Keep TDE underneath.
- **Not a hosted service, proxy, or vault.**
- **Not a GDPR Article 17 erasure guarantee.** No regulator has endorsed key destruction as standalone erasure.

## Documents

| Document | What it is |
|---|---|
| [`docs/00-research-memo.md`](docs/00-research-memo.md) | Landscape, prior art, gap analysis. Reads adversarially — states where the case is weak. |
| [`docs/01-prd.md`](docs/01-prd.md) | Problem, users, goals and non-goals, requirements, success metrics, phasing, risks. |
| [`docs/02-spec-v0.1.md`](docs/02-spec-v0.1.md) | **The specification.** Normative, RFC 2119 language, with justification inline. |
| [`docs/03-compliance-mapping.md`](docs/03-compliance-mapping.md) | Clause-level regulatory mapping. §1 states what these frameworks do *not* require. |
| [`docs/04-orm-adapter-notes.md`](docs/04-orm-adapter-notes.md) | Per-ORM interception points and hard limits, for whoever implements each adapter. |
| [`docs/05-dissemination.md`](docs/05-dissemination.md) | Publication and standardization pathways. |
| [`docs/06-verification-log.md`](docs/06-verification-log.md) | Independent re-verification of the 20 highest-risk factual claims, corrections applied, and what remains unverified. |
| [`docs/07-implementation-plan.md`](docs/07-implementation-plan.md) | Phase 1 engineering plan: workstreams, milestones, decision gates, and the spec gaps that block code. |
| [`docs/08-test-vector-spec.md`](docs/08-test-vector-spec.md) | Test-vector suite engineering spec: file formats, schemas, harness contract, cross-implementation protocol. |
| [`docs/09-core-architecture.md`](docs/09-core-architecture.md) | Language-agnostic core library architecture every implementation follows. |
| [`docs/10-core-python.md`](docs/10-core-python.md) / [`docs/11-core-typescript.md`](docs/11-core-typescript.md) | Per-language bindings for the Phase 1 cores. |
| [`docs/12-adapter-django.md`](docs/12-adapter-django.md) / [`docs/13-adapter-prisma.md`](docs/13-adapter-prisma.md) | Phase 1 adapter designs, including the normative throw lists and coverage matrices. |
| [`docs/14-conformance-ci.md`](docs/14-conformance-ci.md) | How conformance is claimed and proven; the N×N cross-implementation CI job. |
| [`docs/15-tooling.md`](docs/15-tooling.md) | Backfill/re-encryption tool and blind-index leakage estimator. |
| [`docs/adr/`](docs/adr/) | Decision records for the Phase-1-blocking choices (spec §13.1, §13.2), including the AWS-format expressibility mapping (Appendix A to ADR-0001). |
| [`docs/issues/`](docs/issues/) | The thirteen spec gaps (G1–G13) found during tech-spec authoring and review, posted as [issues #1–#13](https://github.com/fieldseal-dev/fieldseal-spec/issues). Eight are now resolved in the draft; the five that remain — G1, G2, G4, G5, G7 — are exactly the five that cannot close without cryptographic review. Each file carries the issue body and, where closed, the resolution. |
| [`docs/16-reviewer-brief.md`](docs/16-reviewer-brief.md) | The brief sent to prospective Phase 0 cryptographic reviewers: eight self-contained question cards, ground rules, outreach log. Answering one is a complete contribution. |
| [`docs/17-m2-implementer-brief.md`](docs/17-m2-implementer-brief.md) | The handoff for building a second core in isolation: the independence rule as a protocol, not a sentence. |
| [`docs/18-m2-report.md`](docs/18-m2-report.md) | What came back from that handoff: the TypeScript core's result against the pinned suite (42/42, nothing tuned), the isolation statement, and twenty recorded ambiguities — including that the commitment formula is not in the spec. |

All of these are published at **[fieldseal.dev/docs](https://fieldseal.dev/docs/)** if you would rather read them in a browser. The site is built from `docs/` in this repository — there is exactly one copy of the specification text, so the published version cannot drift from the source.

**Start with the research memo if you want to know whether this should exist. Start with the spec if you want to know whether it is correct.**

## Repository layout

```
spec/                  normative specification (the authoritative artifact)
vectors/               machine-readable test vectors — every implementation runs these
core/
  python/  typescript/  java/  dotnet/  go/
adapters/
  django/  sqlalchemy/  prisma/  hibernate/  efcore/  gorm/  typeorm/
tools/
  leakage-estimator/   measures actual column distribution skew vs. the assumed model
  backfill/            resumable migration tooling
bench/                 published benchmarks and the migration cost model
docs/                  design documents (above)
examples/              end-to-end demonstration applications
www/                   the fieldseal.dev site — Hugo, no theme, no JavaScript;
                       docs/ is synced in at build time, never edited here
internal/              namespace-placeholder packages (npm, PyPI), not a product
```

Everything under `core/`, `adapters/`, `tools/`, `bench/`, `examples/`, and `vectors/` is a
directory with a README describing what will land there in Phase 1. There is no code yet —
Gate 0a (see below) opened on 2026-08-22 and Phase 1 has not started. See
[`docs/07-implementation-plan.md`](docs/07-implementation-plan.md) for the plan.

## Design commitments

These are the decisions the specification will be judged on.

**One suite, maybe two.** A `suite_id` names a complete frozen suite — AEAD, nonce policy, KDF, index construction — as one indivisible unit. No per-algorithm header fields, no caller-settable `alg`. This is the PASETO model, not the JOSE model; the JWT `alg` header produced `alg=none` stripping and RSA→HMAC confusion. Data at rest has no peer and therefore no negotiation.

**Fresh nonce on every write, always.** Including UPDATEs. Never derived from row identity, never a counter, never persisted. A database breaks every construction NIST SP 800-38D permits: UPDATEs re-encrypt different plaintext at the same identity, restored backups rewind counters, and autoscaled app tiers cannot guarantee unique device identifiers.

**Per-write derived keys.** Every envelope carries a random 32-byte derivation seed (the AWS Encryption SDK v2 message-ID pattern), so no derived key ever encrypts more than one value and the SP 800-38D 2³² invocation ceiling is structurally unreachable rather than managed procedurally. A spec that asks operators to count encryptions fails the first time someone restores a backup.

**Key commitment is mandatory.** AES-GCM is not key-committing, which enables partitioning-oracle attacks in any multi-key system. AWS shipped [security bulletin AWS-2025-032](https://aws.amazon.com/security/security-bulletins/AWS-2025-032/) for exactly this in December 2025 (CVE-2025-14759 through -14764, six language SDKs), remediating by introducing key commitment. Their advisory: *"There are no known workarounds."*

**The synchronous API is a constraint, not a preference.** Django, SQLAlchemy, TypeORM, Hibernate, Rails, and Sequelize cannot await in the value path. SQLAlchemy raises `MissingGreenlet` if you try. An async-first core would be unimplementable in most target ORMs.

**AAD row-binding is optional and off by default.** Rails — the most mature implementation in existence — sets `cipher.auth_data = ""` because `ActiveModel::Type` has no access to the record. Mandating row binding would place the reference implementation of the pattern out of conformance. It is offered as conformance level L3.

**Blind indexes are filters, never answers.** Candidates are decrypted and re-verified in the application. Indexing is refused by default on low-cardinality domains, because Naveed–Kamara–Wright recovered mortality risk for 100% of patients in ≥99% of the 200 largest US hospitals from deterministic encryption alone.

**Adapters throw rather than degrade.** Where an ORM path would silently write plaintext (GORM's map-based `Updates`) or silently return zero rows (Prisma's `in:` and `contains:` over encrypted fields), the adapter must raise. Silent wrongness is worse than a missing feature.

## Honest limitations

Reproduced from the spec so nobody has to find them:

- No protection against a compromised application process, or against an adversary observing queries and logs over time.
- Database query logs, slow-query logs, and replication logs are **in scope as sensitive artifacts** — the ETH Zurich analysis of MongoDB Queryable Encryption recovered 40–100% of field values from logs alone, with the `opLog` attack requiring zero client queries.
- **Storage overhead is real.** A 9-byte SSN becomes ~120 bytes binary or ~160 bytes base64 (envelope header, derivation seed, nonce, tag, and key commitment). Across a 20-column, 100M-row table that is ~220 GB before index bloat and WAL amplification.
- **The key service becomes a hard dependency in the read path of every query.** AWS states it plainly of external key stores: *"The greater risk to availability and latency will, for most customers, exceed the perceived security benefits."*
- **Argon2id blind indexes cost 10–100 ms per query term.** That is a product constraint, not a tuning detail.
- **Retrofitting onto a populated table permanently voids crypto-shredding claims for pre-existing backups** — NIST SP 800-88r2 §3.2.2 requires that no sensitive data was previously stored in plaintext.
- Encrypted foreign keys, unique constraints on randomized ciphertext, collation-sensitive comparison, and aggregate functions do not work.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Specification changes go through an issue before a PR, and every normative change needs a citation and test vectors.

**Cryptographic review is the gate on the format freeze.** The Phase 0 exit gate was split on 2026-08-22 (`docs/01-prd.md` §8) because reviewer recruitment had not succeeded and one gate was holding two different permissions. **Gate 0a** — every spec gap resolved or provisionally resolved and marked, the registry on provisional suite identifiers — permits implementation and was closed by the project. **Gate 0b** — at least two people with real cryptographic credentials — permits freezing, and until it closes no suite identifier is assigned, no stable vector suite is published, no conformance claim is made against a frozen format, and no adoption is invited. The five review-gated spec gaps ([#1](https://github.com/fieldseal-dev/fieldseal-spec/issues/1), [#2](https://github.com/fieldseal-dev/fieldseal-spec/issues/2), [#4](https://github.com/fieldseal-dev/fieldseal-spec/issues/4), [#5](https://github.com/fieldseal-dev/fieldseal-spec/issues/5), [#7](https://github.com/fieldseal-dev/fieldseal-spec/issues/7)) are **provisionally adopted and still open** — the spec marks each `[PROVISIONAL]` and names the question that would close it.

[`docs/16-reviewer-brief.md`](docs/16-reviewer-brief.md) is the brief, and it is built so that **answering one question is a complete contribution** — each of the eight is a self-contained card naming the few pages to read, the concrete proposal, and the kind of answer that settles it. The cheapest is [Q4](docs/16-reviewer-brief.md#q4) (~20 minutes, an encoding-injectivity question needing no project context); the highest-leverage is [Q7](docs/16-reviewer-brief.md#q7).

Also valuable, and not requiring a cryptographer:

- **ORM internals.** Several claims in [`docs/04-orm-adapter-notes.md`](docs/04-orm-adapter-notes.md) were reasoned from documentation rather than verified against source. Corrections from people who know Django, SQLAlchemy, Prisma, Hibernate, EF Core, GORM, or TypeORM internals are wanted.
- **Compliance mapping.** [`docs/03-compliance-mapping.md`](docs/03-compliance-mapping.md) §8 lists what could not be verified.
- **Anything you have built in-house.** If you have shipped field-level encryption and watched it break, that is the experience the design is missing.

## Security

See [`SECURITY.md`](SECURITY.md). Do not open public issues for suspected vulnerabilities in the specification or any implementation.

## License

Three licenses, mapped by path in [`LICENSES.md`](LICENSES.md):

| What | License |
|---|---|
| Specification and documentation | [CC BY 4.0](LICENSE-SPEC) — quote it, profile it, fold it into another standard |
| Test vectors | [CC0 1.0](LICENSE-VECTORS) — public domain, so running the conformance suite carries no obligations |
| Code | [Apache 2.0](LICENSE) — permissive, with an explicit patent grant |

The rationale is in [`GOVERNANCE.md`](GOVERNANCE.md).
