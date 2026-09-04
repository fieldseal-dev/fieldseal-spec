# AGENTS.md

This file provides guidance to coding agents working in this repository. It is
the single instruction set, and it is agent-neutral on purpose: Claude Code is
not the only agent that works here.

**If you are Claude Code:** read this file as `CLAUDE.md`. The repository's
`CLAUDE.md` is a pointer to this file and carries no instructions of its own —
everything that would be in it is below, and applies unchanged.

---

## Project Overview

**Fieldseal** is a portable specification and reference implementations for transparent field-level encryption-at-rest at the data-access layer.

**Current status:** Pre-alpha design work (Phase 0 of 3). The specification is a working draft that has not been independently reviewed. The Phase 0 exit gate was split on 2026-08-22 (`docs/01-prd.md` §8): **Gate 0a** (spec gaps resolved or provisionally resolved and marked; registry on provisional suite identifiers) permits implementation and is closed; **Gate 0b** (two credentialed cryptographic reviewers) permits freezing the format and is still open. Phase 1 code may therefore begin, but nothing may be frozen, published as stable, or offered for adoption. See `docs/01-prd.md` for the complete roadmap and success metrics.

**Central claim:** A value encrypted by implementation A in one language is decryptable by implementation B in another language using the same key. This is verified through machine-readable test vectors (cross-implementation round trips in CI). If this claim fails, the project has failed — everything else is secondary.

---

## Architecture and Design Principles

Read these first to understand the design philosophy:

- **`docs/02-spec-v0.1.md`** — The normative specification (RFC 2119 language, justifications inline). This is the authoritative artifact. Every design decision is explained, and many contested claims are flagged as such.
- **`docs/01-prd.md`** — Product requirements, users, goals, non-goals, success metrics, phasing, open questions (§6 and §10), and risk mitigations.
- **`docs/00-research-memo.md`** — Landscape review, prior art, gap analysis. Reads adversarially — states where the case is weak.

### Key Design Commitments

These commitments define what the spec will be judged on. When proposing changes, check them against these:

1. **One suite, maybe two** — A `suite_id` is complete and frozen (AEAD + nonce policy + KDF + index construction as one unit). No per-algorithm header fields, no caller-settable `alg`. This is the PASETO model, not JOSE.
2. **Fresh nonce on every write** — Including UPDATEs. Never derived from row identity, never a counter, never persisted. Databases break every construction NIST SP 800-38D permits.
3. **Per-write derived keys** — The 32-byte `msg_seed` in the envelope makes every derived key single-use. The SP 800-38D 2³² ceiling is unreachable regardless of scale.
4. **Key commitment is mandatory** — AES-GCM is not key-committing. AWS shipped [AWS-2025-032](https://aws.amazon.com/security/security-bulletins/AWS-2025-032/) for partitioning-oracle attacks in December 2025; key commitment prevents it.
5. **Synchronous API** — Django, SQLAlchemy, TypeORM, Hibernate, Rails, Sequelize cannot await in the value path. The core API is sync-only; `warm()` is the async prefetch.
6. **Blind indexes are filters, never answers** — Candidates are decrypted and re-verified. Indexing is refused by default on low-cardinality domains (spec §7.6).
7. **Adapters throw rather than degrade** — Where an ORM path would silently write plaintext (GORM's `Updates(map[...])`), Prisma's `in:`, the adapter must raise.

### Repository Layout

```
spec/                     normative specification (moves here as versioned releases)
vectors/                  machine-readable test vectors — six families emitted and pinned
                          by hash in MANIFEST.json (146 vectors, 178 results), nothing
                          held out; cross/ runs as a dynamic CI exchange and cross/static/
                          waits for a first release (see vectors/README.md)
core/
  python/  typescript/    reference implementations — both built, both pass the pinned suite
  java/  dotnet/  go/      README placeholders (Phase 1+)
adapters/
  django/  prisma/       built and gated in CI (L1+L2, and L4 for Prisma);
                          zero cryptographic code, asserted by a CI grep
  sqlalchemy/  hibernate/  efcore/  gorm/  typeorm/   README placeholders (Phase 1+)
tools/
  vector-gen/             the vector generator (standalone; imports neither core)
  ucd-gen/                generates the vendored Unicode tables for both cores and
                          the vector generator from the published UCD (docs/09 §7.1);
                          CI re-runs it with --check, so a hand edit fails the build
  leakage-estimator/      measures actual vs. assumed column distribution skew (placeholder)
  backfill/               resumable migration tooling (placeholder)
bench/                    published benchmarks and migration cost model
docs/
  00-research-memo.md     prior art and gap analysis
  01-prd.md               requirements, goals, phasing, open questions, risks
  02-spec-v0.1.md         the specification (normative)
  03-compliance-mapping.md clause-level regulatory mapping
  04-orm-adapter-notes.md per-ORM interception points and hard limits
  05-dissemination.md     publication/standardization pathways
  06-verification-log.md  independent verification of key claims
  07-implementation-plan.md Phase 1 engineering plan, decision gates, spec-gap issue list
  08-test-vector-spec.md  vector suite formats, schemas, harness contract, cross protocol
  09-core-architecture.md language-agnostic core library architecture
  10-core-python.md       Python core binding of the architecture
  11-core-typescript.md   TypeScript core binding of the architecture
  12-adapter-django.md    Django adapter design (throw lists, coverage matrix)
  13-adapter-prisma.md    Prisma adapter design (throw lists, coverage matrix)
  14-conformance-ci.md    conformance claims, report format, N×N cross-implementation CI
  15-tooling.md           backfill tool and leakage-estimator design
  adr/                    architecture decision records for Phase-1-blocking decisions
                          (incl. Appendix A to ADR-0001: AWS-format expressibility mapping)
  issues/                 spec-gap issue drafts G01–G24 (see docs/07 §5)
  16-reviewer-brief.md    the Phase 0 cryptographic-review brief (reading path, gating questions)
  17-m2-implementer-brief.md  handoff for building a second core in isolation (the
                          independence rule as a followable protocol)
  18-m2-report.md         the M2 result: TypeScript core vs the pinned suite, isolation
                          statement, divergence/ambiguity list (D-01..D-20)
  19-what-encrypted-search-costs.md  the blind-index cost argument for readers who
                          will not read the spec
www/                      the fieldseal.dev site: Hugo, hand-written templates, no
                          theme and no third-party JavaScript. docs/ is synced in by
                          www/scripts/sync-docs.py; .github/workflows/pages.yml builds
                          and link-checks on PRs and deploys from main
examples/                 end-to-end demonstration applications (Phase 1+)
CONTRIBUTING.md           how to contribute spec changes
SECURITY.md               how to report security issues
GOVERNANCE.md             licensing and governance
```

---

## Working with the Specification

### Reading Strategy

The specification is self-contained but dense. Read in this order:

1. **Scope (§1)** — what's in and out
2. **Threat model (§2)** — what adversaries it does and doesn't protect against; §2.3 flags that query logs are in scope
3. **Your area of interest** — jump to envelope, key hierarchy, blind indexes, conformance levels, or adapters
4. **Open questions (§13)** — unresolved decisions that should be settled before code
5. **Contested claims (§14)** — explicitly flagged areas where the literature or standards are unsettled

### Specification Changes

From `CONTRIBUTING.md`:

**Every specification change needs:**
1. An issue first (before a PR)
2. A justification with a citation — NIST publication, IETF RFC, peer-reviewed literature, or shipping-product documentation
3. A statement of what it breaks (envelope format and suite registry changes are compatibility-breaking until v1.0)
4. Test vectors (a normative change without vectors cannot be verified across implementations)

**Scope:** Changes that clarify prose are held to a lower bar than changes that add a cipher suite. Adding a third suite needs to argue why the existing suites are inadequate.

**Review focus:** The highest-value contributions right now are:
1. **Cryptographic review** of the spec (especially open questions in §13 and contested claims in §14)
2. **Answers to open questions** (§13.1–§13.6 block Phase 1)
3. **ORM analysis corrections** (several claims in `docs/04-orm-adapter-notes.md` were not verified against source)
4. **Compliance mapping gaps** (§8 of that document lists what could not be verified)

---

## Compliance and Documentation Standards

Two standing rules (from `CONTRIBUTING.md`):

1. **Every claim gets a citation or a flag** — The "not verified" list is a feature. Reviewers trust documents that say what they don't know.
2. **Do not overclaim** — This project's credibility depends on being the document that says "SOC 2 does not require this," "CIS says storage-layer encryption meets the minimum," and "the 60% breach statistic is fabricated." A single unsupported claim costs more credibility than ten supported ones earn.

### Important Limitations (Normative)

These are stated in the spec and MUST NOT be omitted in any discussion:

- **No protection against a compromised application process.** The keys are in that process.
- **Storage overhead is real.** A 9-byte SSN becomes ~120 bytes binary or ~160 bytes base64. Across a 20-column, 100M-row table that is ~220 GB overhead before index bloat.
- **The key service becomes a hard dependency in the read path.** External key stores trade security for availability; KMS outages affect every query on encrypted fields.
- **Argon2id blind indexes cost 10–100 ms per query term.** That is a product constraint, not tuning.
- **Database query logs are in scope as sensitive artifacts.** The ETH Zurich MongoDB QE analysis (USENIX '23) recovered 40–100% of field values from logs alone, with zero client queries required.

---

## Test Vectors

The cross-implementation test vectors are the entire point of the project. From `vectors/README.md`:

**Layout (planned):**
- `envelope/` — encrypt/decrypt round trips per suite
- `kdf/` — key derivation verification
- `context/` — canonical context encoding
- `blind-index/` — index derivation for Argon2id and HMAC
- `commitment/` — key-commitment values
- `errors/` — every error case in spec §9 (unknown suite, AAD mismatch, TAG_INVALID, etc.)
- `cross/` — values produced by each implementation, decrypted by every other

**Format:** JSON, hex-encoded binary, fixed nonces/seeds (test affordance only — real implementations MUST use CSPRNG). Each vector carries a stable `id`, full input state, expected output, and `spec_ref` pointing at the section.

**Critical detail:** Nonces and derivation seeds are fixed in vectors for determinism. This is a *testing affordance only*. Spec §3.1 and §4.4 require a fresh CSPRNG seed and nonce on every real encryption, including UPDATEs. An implementation that accepts caller-supplied values outside test mode is non-conformant.

**Negative vectors matter as much as positive ones** — unknown `fmt_ver`, suite not on allow-list, truncated envelope, AAD altered, bit flips in ciphertext and tag, key-commitment cases, plaintext in strict mode. Each must produce the specific error type from spec §9.

---

## Conformance Levels

The spec defines independently-claimable conformance levels (§10):

- **L0** — Envelope format, suite registry, test vectors (baseline)
- **L1** — Transparent value mapping at the ORM layer (write/read)
- **L2** — Indexed equality (blind indexes)
- **L2(a) vs L2(b)** — Explicit index property vs. transparent query rewriting (varies by ORM)
- **L3** — Context binding (tenant, row)
- **L3-row** — Row-ID binding (more constrained; not all ORMs can do it)
- **L4** — Async key acquisition in value path (rare; Prisma, EF Core async paths only)

**Matrix available in spec §10.1** showing which ORMs can realistically reach which level.

---

## ORM-Specific Constraints

From `docs/04-orm-adapter-notes.md` and spec §10.2:

Each ORM has hard limits. When implementing adapters, consult the spec's per-ORM notes and the matrix. Key carve-outs:

- **Django** — Field types cannot see the record. Row binding requires a context var (side channel). Raw SQL parameters never encrypted.
- **SQLAlchemy** — Attempting to await raises `MissingGreenlet`. Type processors are sync-only.
- **Hibernate** — Best context-binding support via `Interceptor.onPersist` and full state array. Sequence/UUID generators allow L3-row binding.
- **EF Core** — `SavingChanges` hook gives record access; async available in write path only via `SavingChangesAsync`.
- **GORM** — Excellent callback access. Map-based `Updates(map[...])` and single-column `Update("col", v)` bypass the serializer entirely — adapters MUST reject these.
- **Prisma** — Async-first; good potential. Filter shapes like `in:`, `contains:`, `startsWith:` are not rewritten by extension points — adapters MUST reject these over encrypted fields.
- **TypeORM** — Dirty-check runs the transform, so every randomized encrypt marks the field dirty and rewrites it on `save()`. Equality available only via explicit index property, not transparent rewrites.

---

## Key Decision Points and Open Questions

These shape your thinking about changes. Items 1 and 2 are **provisionally decided under Gate 0a and still open** — ADR-0001 took option C (fresh envelope, AWS-aligned constructions); ADR-0002 deferred to the status quo without deciding. Both are reversible at Gate 0b, and the spec marks the affected sections `[PROVISIONAL]`. Items 3–6 remain untouched. Do not close any of these by engineering judgment, and do not treat a provisional decision as a settled one.

1. **Profile the AWS structured-encryption format or define fresh?** (§13.1) — Profiling buys interoperability and reduces novelty risk; defining fresh buys freedom from DynamoDB semantics. **Highest-leverage decision.**
2. **Which FIPS-approvable AEAD for suite 0x0001?** (§13.2) — AES-256-GCM + explicit commitment (current), AES-256-CBC-HMAC-SHA-512 (committing natively, more overhead), or wait for AES-GCM-SIV (not FIPS, best misuse resistance).
3. **Reserve space for NIST accordion modes?** (§13.3) — NIST announced accordion modes based on HCTR2 for SP 800-197x.
4. **Non-relational stores?** (§13.4) — Document databases and key-value stores have the same problem; deferred for v1.0.
5. **Vector/embedding encryption?** (§13.5) — RAG stores are becoming PII repositories; only IronCore ships distance-preserving vector encryption (paid).
6. **Deterministic AEAD suite?** (§13.6) — Would lift TypeORM constraints but strains the "one option, maybe two" commitment and requires pushing §7 controls into the suite.

---

## Engagement Path

When starting on this codebase:

1. **Understand the spec** — Read §1–§2 and your area of focus. Use §9 and §10 as reference as needed.
2. **Check the open questions** — Don't solve problems that are deferred.
3. **Verify your claim** — If you're correcting something, check `CONTRIBUTING.md` (citations required for normative changes).
4. **Test vectors** — Any normative change needs test vectors covering the change. See `vectors/README.md` for format.
5. **Cross-reference compliance** — If your change touches conformance, check the matrix in §10.1 and the per-ORM notes in §10.2.

**For issues on spec changes:** Label the PR/issue with the section it touches (e.g., "§7.4 truncation length"). If it modifies the registry, note which suite(s) and what breaks. If it touches conformance, update the matrix.

---

## Code and the Split Gate (Phase 0 → Phase 1)

This repository contains the specification, its documentation, the vector generator, two Phase 1 cores (`core/python`, `core/typescript`), two Phase 1 adapters (`adapters/django`, `adapters/prisma`) and the fieldseal.dev site; the remaining adapters, the tools in `tools/{leakage-estimator,backfill}`, the benchmark programme and the examples are not started. The Phase 0 exit gate is split (`docs/01-prd.md` §8): **Gate 0a** authorizes implementation and is closed; **Gate 0b** — independent cryptographic review — authorizes freezing and remains open. Phase 1 work may start. When implementations are written:

- Core libraries will be in `core/{python,typescript,java,dotnet,go}` and MUST pass the shared test vectors in CI.
- ORM adapters will be in `adapters/{django,sqlalchemy,...}` and MUST contain zero cryptographic code.
- Tools will live in `tools/{leakage-estimator,backfill}` and will be resumable, rate-limited, and idempotent.
- Benchmarks will be in `bench/` with honest measurement (not estimation) of latency, throughput, and storage.

The test-vector suite is the single source of truth for interoperability. If a value encrypted by Python cannot be decrypted by Go, the central claim is false.

---

## Building, Linting, Testing

**Python core** (`core/python`): `pip install -e "./core/python[argon2,dev]"`, `pytest core/python/tests -q`, report via `python core/python/tests/run_vectors.py` (see `.github/workflows/conformance.yml`).

**TypeScript core** (`core/typescript`, Node ≥ 24.7): `npm ci`, `npm test` (vitest: vector harness + gates + totality + primitives + providers), `npm run vectors` (emits the `docs/14` §4 conformance report), `npm run build`, `npm run typecheck`. Zero runtime dependencies.

**Django adapter** (`adapters/django`): install the core from this checkout, not an index — `pip install -e "./core/python[argon2]"` then `pip install -e "./adapters/django[dev]"`; `python -m pytest tests -q` from `adapters/django`, with `FIELDSEAL_TEST_DB=sqlite|postgres`. CI runs both backends (`docs/12` §8), plus `ruff check src tests` and `mypy --strict src/fieldseal_django`.

**Prisma adapter** (`adapters/prisma`): build the core first (`npm ci && npm run build` in `core/typescript`), then `npm ci`, `npm run build`, `node tests/fixture/build.ts && npx prisma generate && npx prisma db push`, `npm test`. `npm run report` emits the `docs/14` §4 report. CI runs SQLite and Postgres legs.

**AD-1 (spec §11.3):** an adapter contains no cryptographic code. CI greps `src/` for crypto imports in both adapters and fails the build on a hit. This is a conformance rule, not a style preference.

**Site** (`www/`): `python www/scripts/sync-docs.py` then `hugo server --source www`; before pushing, `hugo --source www --minify --gc` and `python www/scripts/check-links.py www/public`.

**Independence rule:** a second core is built without reading the first or the generator — `docs/17-m2-implementer-brief.md` is the protocol, `docs/18-m2-report.md` the first result. When working on `core/typescript`, do not consult `core/python/**` or `tools/vector-gen/**` to resolve a mismatch; record it.

**When implementations arrive:** Each language will have its own build and test setup (Makefile, pyproject.toml, package.json, etc.). Adapters will be integrated into the same test suite and MUST demonstrate coverage through a documented matrix (spec §10.2).

---

## Contact and References

- **Report security issues:** See `SECURITY.md`. Do not open public issues for suspected vulnerabilities.
- **Contributing:** See `CONTRIBUTING.md`. Specification changes go through issues first.
- **Governance and licensing:** Licensing is settled — specification and docs CC BY 4.0, test vectors CC0 1.0, code Apache 2.0. The path-by-path mapping is `LICENSES.md`; the rationale is in `GOVERNANCE.md`, where everything *except* licensing remains proposed.

**Normative references:** Spec §15 lists all NIST, RFC, and research citations. Informative references point to AWS structured encryption, Tink, Vault, Rails, CipherSweet, and key research papers (Naveed–Kamara–Wright, Grubbs et al., MongoDB QE analysis, etc.).

