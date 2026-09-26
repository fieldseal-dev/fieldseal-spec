[![Conformance](https://github.com/fieldseal-dev/fieldseal-spec/actions/workflows/conformance.yml/badge.svg)](https://github.com/fieldseal-dev/fieldseal-spec/actions/workflows/conformance.yml)
[![Build and deploy fieldseal.dev](https://github.com/fieldseal-dev/fieldseal-spec/actions/workflows/pages.yml/badge.svg)](https://github.com/fieldseal-dev/fieldseal-spec/actions/workflows/pages.yml)
[![PyPI: fieldseal](https://img.shields.io/pypi/v/fieldseal?label=pypi%20fieldseal)](https://pypi.org/project/fieldseal/)
[![PyPI: fieldseal-django](https://img.shields.io/pypi/v/fieldseal-django?label=pypi%20fieldseal-django)](https://pypi.org/project/fieldseal-django/)
[![npm: @fieldseal/core](https://img.shields.io/npm/v/%40fieldseal%2Fcore?label=npm%20%40fieldseal%2Fcore)](https://www.npmjs.com/package/@fieldseal/core)
[![npm: @fieldseal/prisma](https://img.shields.io/npm/v/%40fieldseal%2Fprisma?label=npm%20%40fieldseal%2Fprisma)](https://www.npmjs.com/package/@fieldseal/prisma)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="www/static/brand/fieldseal-mark-dark.svg">
  <img src="www/static/brand/fieldseal-mark.svg" alt="" width="72" height="72">
</picture>

# Fieldseal

**A portable format for field-level encryption at rest, with reference implementations that prove it in CI.**

A value encrypted by one implementation in one language is decrypted by another implementation in another language under the same key. That is the whole claim. It is checked by a pinned test-vector suite that every core runs, and by an N×N job in which every core and every adapter decrypts what every other one wrote.

> **Experimental release: not independently reviewed, not for production data.**
> The cryptographic design has not been reviewed by anyone outside the project. Every cipher suite in the registry is provisional (spec §4.2, §4.8), and every implementation refuses to encrypt until the operator explicitly arms provisional use. The stored format may change before 1.0, and data written now may have to be re-encrypted. The packages below are published for evaluation and feedback under the terms in [`docs/01-prd.md` §8](docs/01-prd.md).

Rendered docs: **[fieldseal.dev](https://fieldseal.dev)**. Specification: [`docs/02-spec-v0.1.md`](docs/02-spec-v0.1.md).

## Packages

All four are at the same version and release together from one tag (`tools/release/`). Each core is a complete implementation of the format; each adapter contains no cryptographic code and delegates everything to its core.

| Package | Registry | What it is |
|---|---|---|
| [`fieldseal`](https://pypi.org/project/fieldseal/) | PyPI | Python core: envelope, key hierarchy, blind indexes, key providers. Python ≥ 3.10. |
| [`fieldseal-django`](https://pypi.org/project/fieldseal-django/) | PyPI | Django adapter: `Encrypted(...)` model fields, `BlindIndex`, query rewriting and refusals. Python ≥ 3.12, Django ≥ 5.2. |
| [`@fieldseal/core`](https://www.npmjs.com/package/@fieldseal/core) | npm | TypeScript core, zero runtime dependencies, `node:crypto` only. Node ≥ 24.7, server-side. |
| [`@fieldseal/prisma`](https://www.npmjs.com/package/@fieldseal/prisma) | npm | Prisma Client extension plus a generator that reads `/// @fieldseal(...)` schema comments. Prisma ≥ 7.10, < 8. |

```sh
pip install "fieldseal[argon2]"        # Python core
pip install fieldseal-django           # Django adapter (pulls in the core)
npm install @fieldseal/core            # TypeScript core
npm install @fieldseal/prisma @fieldseal/core @prisma/client@7.10   # Prisma adapter
```

Each package README carries an install, a quickstart and the limitations: [`core/python/`](core/python/README.md), [`core/typescript/`](core/typescript/README.md), [`adapters/django/`](adapters/django/README.md), [`adapters/prisma/`](adapters/prisma/README.md).

A Java core is in progress under `core/java` (stage S4 of [`docs/27-core-java.md`](docs/27-core-java.md): codec, registry, crypto pipeline, key providers and client built; blind indexes next). Nothing is published for it yet.

## Sixty seconds of the API

The two cores expose the same operations with the same semantics; only the spelling differs.

```python
from fieldseal import Fieldseal, FieldContext, IndexDeclaration
from fieldseal.keyprovider import StaticKeyProvider

fs = Fieldseal(
    key_provider=StaticKeyProvider(key_id=..., tenant_dek=..., tenant_index_key=...),
    allowed_suites={0xFF01}, write_suite=0xFF01,
    indexes=[IndexDeclaration(table_uuid=USERS, column_uuid=EMAIL,
                              idf="argon2id", normalize="nfc-casefold-v1",
                              truncate_bits=15, projected_population=100_000)],
    arm_provisional_suites=True,          # refuses to write without this
)
ctx = FieldContext(table_uuid=USERS, column_uuid=EMAIL)

env = fs.encrypt(b"ada@example.com", ctx)          # 111 bytes of overhead + the value
fs.decrypt(env, ctx)                               # b'ada@example.com'
fs.is_ciphertext(env)                              # True, without decrypting
fs.blind_index("Ada@Example.com", ctx.for_index("exact"))   # 2 bytes, equal for "ada@example.com"
fs.rotate(env, ctx)                                # re-encrypted under the active key version
```

```ts
import { Fieldseal, DerivedKeyProvider } from "@fieldseal/core";

const fs = new Fieldseal(
  { keyProvider: new DerivedKeyProvider({ rootSecret }),
    allowedSuites: [0xff01], writeSuite: 0xff01,
    indexes: [{ tableUuid: USERS, columnUuid: EMAIL, idf: "argon2id",
                normalize: "nfc-casefold-v1", truncateBits: 15, projectedPopulation: 100_000 }] },
  { armProvisionalSuites: true },
);
const ctx = { tableUuid: USERS, columnUuid: EMAIL, purpose: "encrypt" };

const env = fs.encrypt(plaintext, ctx);
fs.decrypt(env, ctx);
await fs.blindIndexAsync("Ada@Example.com", { ...ctx, purpose: "index:exact" });
```

The adapters hide all of this behind the ORM: a Django `Encrypted(models.EmailField(), column_uuid=..., index=BlindIndex(...))` field, or a Prisma `/// @fieldseal(encrypted, column_uuid: "...")` comment. `filter(email=...)` and `findMany({ where: { email } })` keep working through the blind index, and every candidate row is decrypted and re-compared before it is returned.

## The format

One database cell holds one self-describing envelope (spec §3.1):

```
| fmt_ver | suite_id | key_id | msg_seed | nonce | ciphertext | tag  | commitment |
|   1 B   |   2 B    |  16 B  |   32 B   | 12 B  |    var     | 16 B |    32 B    |
```

- **`suite_id` names a complete, frozen suite** (AEAD, nonce policy, KDF, index construction). There are no per-algorithm header fields and no caller-settable `alg`. Registry in spec §4; the only suite today is `0xFF01`, AES-256-GCM with HKDF-SHA-512, provisional.
- **`msg_seed` is 32 fresh CSPRNG bytes on every write**, including UPDATEs. The record key is derived from the tenant DEK, `key_id`, `msg_seed` and the canonical context, so no derived key ever encrypts two values and the SP 800-38D invocation ceiling is unreachable by construction.
- **`nonce` is fresh on every write** and never derived from row identity, never a counter, never persisted anywhere but the envelope.
- **`commitment` is mandatory** for a non-committing AEAD. AES-GCM is not key-committing; this is the AWS-2025-032 class of partitioning-oracle attack.
- **Context binding.** A canonical, length-prefixed encoding of table UUID, column UUID, purpose and, when used, tenant and row ID (spec §6.2) is both the KDF `info` and part of the AEAD's AAD. A ciphertext moved to another column, tenant or row fails to decrypt.
- **Blind indexes** (spec §7) are keyed hashes under a separate index key, Argon2id or HMAC-SHA-512, truncated to a declared number of bits so the index is a filter and never an answer. Indexing is refused on low-cardinality or skewed columns without a recorded override.
- **Logical types** (spec §3.6) each have exactly one plaintext rendering, so a Django `DecimalField` and a Prisma `Decimal` produce identical plaintext and identical blind indexes.

The specification is written in RFC 2119 language with the justification for every decision inline, and it flags what is contested (§14) and what is still open (§13).

## What is proven, and how

| Claim | Where it is checked |
|---|---|
| Both cores agree with the pinned vectors | `vectors/`: 150 vectors, 182 results per core, hashed in `MANIFEST.json`. `python-core` and `typescript-core` jobs; the TypeScript core also runs every vector through its async companions (364 results). |
| Both cores produce identical result ids | `cross-core-result-ids` |
| Each core decrypts what the other core and both adapters wrote | `cross-produce` / `cross-consume`: every producer encrypts a shared 16-case corpus through its production path; every consumer decrypts every producer, self-pairs included (`docs/14` §3). |
| Adapters render logical types identically | `vectors/codec/`: 124 vectors, both directions, refusals included; run by both adapters against SQLite and PostgreSQL. |
| Adapters contain no cryptography | A CI grep of each adapter's `src/` for crypto imports fails the build on a hit (spec §11.3). |
| The vectors are reproducible | `vectors-reproducible` regenerates the suite from `tools/vector-gen` and diffs; `unicode-tables` regenerates the vendored UCD tables with `--check`. |
| A Django app and a Prisma app share one table | `examples/patient-directory`: a scripted seven-act scenario over one Postgres table, gated in CI ([`docs/20`](docs/20-demo-patient-directory.md)). |
| Releases meet the PRD §8 conditions | `release-readiness`: build, check and smoke-test all four packages on every run (`tools/release/`). |

The TypeScript core was built without reading the Python core or the generator, under the protocol in [`docs/17`](docs/17-m2-implementer-brief.md); the result and the twenty ambiguities it surfaced are in [`docs/18`](docs/18-m2-report.md). The Java core is built the same way.

## Repository layout

```
spec/                  normative specification (versioned releases move here)
vectors/               the pinned vector suite; MANIFEST.json hashes every family
core/
  python/  typescript/ the two released cores
  java/                the Phase 2 core, in progress (docs/27)
  dotnet/  go/         placeholders
adapters/
  django/  prisma/     the two released adapters
  sqlalchemy/  hibernate/  efcore/  gorm/  typeorm/   placeholders
tools/
  vector-gen/          emits the vector suite; imports neither core
  ucd-gen/             regenerates the vendored Unicode 17.0.0 tables
  release/             builds, checks and smoke-tests the four packages
  figures/             extracts the static SVGs in docs/figures/
  leakage-estimator/   backfill/        placeholders (docs/15)
examples/
  patient-directory/   Django + Prisma over one Postgres table (docs/20)
bench/                 placeholder
docs/                  design documents, below
www/                   fieldseal.dev: Hugo, no theme, no JavaScript; docs/ is synced in
```

## Building and testing

| Component | Commands |
|---|---|
| Python core | `pip install -e "./core/python[argon2,dev]"`, `pytest core/python/tests -q`, `python core/python/tests/run_vectors.py` |
| TypeScript core | `cd core/typescript && npm ci && npm test && npm run vectors && npm run build && npm run typecheck` |
| Java core | `cd core/java && ./gradlew build`, `./gradlew -q vectors`, `python scripts/bite_checks.py` |
| Django adapter | `pip install -e "./adapters/django[dev]"`, then `cd adapters/django && python -m pytest tests -q` with `FIELDSEAL_TEST_DB=sqlite\|postgres` |
| Prisma adapter | build the core first, then `cd adapters/prisma && npm ci && npm run build && node tests/fixture/build.ts && npx prisma generate && npx prisma db push && npm test` |
| Release artifacts | `python tools/release/build_dists.py --out dist-release`, `check_release_conditions.py dist-release`, `smoke.py dist-release` |
| Site | `python www/scripts/sync-docs.py && hugo server --source www` |

The full matrix, including the demo and the lint jobs, is [`.github/workflows/conformance.yml`](.github/workflows/conformance.yml). Publishing is [`release.yml`](.github/workflows/release.yml): a `v0.MINOR.PATCH` tag that matches all four package versions, trusted publishing with provenance on both registries, and a maintainer approval gate.

## Conformance levels

Independently claimable (spec §10). The matrix of which ORM can reach which level is spec §10.1.

| Level | Claim |
|---|---|
| L0 | Envelope format, suite registry, vectors |
| L1 | Transparent value mapping at the ORM layer |
| L2 | Indexed equality through blind indexes; L2(a) explicit index property, L2(b) transparent query rewriting |
| L3 | Context binding to tenant; L3-row binds the row ID |
| L4 | Async key acquisition in the value path |

The Django adapter is gated at L1 and L2 in CI; the Prisma adapter at L1, L2 and L4.

## Limitations

Normative, from the spec, and reproduced in every package README:

- **No protection against a compromised application process.** The keys are in that process.
- **Storage overhead is real.** Every value carries 111 bytes of envelope before base64. A 9-byte SSN becomes ~120 bytes binary; across a 20-column, 100M-row table that is ~220 GB before index bloat.
- **The key service is a hard dependency in the read path.** A KMS outage affects every query that touches an encrypted field.
- **Argon2id blind indexes cost 10–100 ms per query term.** That is a product constraint, not tuning. [`docs/19`](docs/19-what-encrypted-search-costs.md) measures it.
- **Query logs are sensitive artifacts.** The ETH Zurich analysis of MongoDB Queryable Encryption recovered 40–100% of field values from logs alone.
- **No range queries, ordering, `LIKE`, aggregates, unique constraints or foreign keys over ciphertext.** Order-preserving and order-revealing encryption are forbidden by the spec. The adapters raise on these rather than degrade.
- **Retrofitting onto a populated table voids crypto-shredding claims for pre-existing backups** (NIST SP 800-88r2 §3.2.2).

## Documents

Everything under `docs/` is published at [fieldseal.dev/docs](https://fieldseal.dev/docs/) from the same source.

| Document | What it is |
|---|---|
| [`02-spec-v0.1.md`](docs/02-spec-v0.1.md) | **The specification.** Normative. |
| [`08-test-vector-spec.md`](docs/08-test-vector-spec.md) | Vector file formats, schemas, harness contract, cross-implementation protocol. |
| [`09-core-architecture.md`](docs/09-core-architecture.md) | The language-agnostic core architecture every implementation follows. |
| [`10-core-python.md`](docs/10-core-python.md) · [`11-core-typescript.md`](docs/11-core-typescript.md) · [`27-core-java.md`](docs/27-core-java.md) | Per-language core bindings. |
| [`12-adapter-django.md`](docs/12-adapter-django.md) · [`13-adapter-prisma.md`](docs/13-adapter-prisma.md) | Adapter designs: throw lists and coverage matrices. |
| [`14-conformance-ci.md`](docs/14-conformance-ci.md) | How conformance is claimed and proven; the report format; the N×N job. |
| [`21-write-path.md`](docs/21-write-path.md) · [`22-read-path.md`](docs/22-read-path.md) · [`23-query-path.md`](docs/23-query-path.md) · [`24-key-lifecycle.md`](docs/24-key-lifecycle.md) | Sequence diagrams of one encrypted field through save, read and equality query, and of the key hierarchy. |
| [`04-orm-adapter-notes.md`](docs/04-orm-adapter-notes.md) | Per-ORM interception points and hard limits. |
| [`15-tooling.md`](docs/15-tooling.md) | Backfill tool and leakage estimator designs. |
| [`00-research-memo.md`](docs/00-research-memo.md) · [`01-prd.md`](docs/01-prd.md) · [`03-compliance-mapping.md`](docs/03-compliance-mapping.md) | Prior art, requirements and phasing, and what regulations do and do not require. |
| [`16-reviewer-brief.md`](docs/16-reviewer-brief.md) | The cryptographic-review brief: eight self-contained question cards. |
| [`17-m2-implementer-brief.md`](docs/17-m2-implementer-brief.md) · [`18-m2-report.md`](docs/18-m2-report.md) | Building a second core in isolation, and what came back. |
| [`19-what-encrypted-search-costs.md`](docs/19-what-encrypted-search-costs.md) | What blind-index search costs, measured. Written for non-specialists. |
| [`07-implementation-plan.md`](docs/07-implementation-plan.md) · [`25-phase-1-retro.md`](docs/25-phase-1-retro.md) · [`26-phase-2-plan.md`](docs/26-phase-2-plan.md) | Phase 1 plan and decision log, its retrospective, and the Phase 2 plan. |
| [`adr/`](docs/adr/) · [`issues/`](docs/issues/) | Decision records and the spec-gap issues. |

## Status

Phase 1 ("prove the format") is done: two cores, two adapters, one demo, all gated in CI. Phase 2 ("prove the breadth", [`docs/26`](docs/26-phase-2-plan.md)) is under way, Java core first, then Hibernate, SQLAlchemy, .NET, EF Core, Go and GORM.

**Gate 0b is open.** The format freezes only after review by at least two people with cryptographic credentials. Until then no suite identifier is final, no stable vector suite is published, nothing reaches 1.0, and no production adoption is invited. The five review-gated spec gaps ([#1](https://github.com/fieldseal-dev/fieldseal-spec/issues/1), [#2](https://github.com/fieldseal-dev/fieldseal-spec/issues/2), [#4](https://github.com/fieldseal-dev/fieldseal-spec/issues/4), [#5](https://github.com/fieldseal-dev/fieldseal-spec/issues/5), [#7](https://github.com/fieldseal-dev/fieldseal-spec/issues/7)) are provisionally adopted and marked `[PROVISIONAL]` in the spec.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Specification changes go through an issue first, and every normative change needs a citation and test vectors. Most wanted:

- **Cryptographic review.** [`docs/16`](docs/16-reviewer-brief.md) is built so that answering one question is a complete contribution; [Q4](docs/16-reviewer-brief.md#q4) takes about twenty minutes and needs no project context.
- **ORM internals.** Several claims in [`docs/04`](docs/04-orm-adapter-notes.md) were reasoned from documentation, not source.
- **Field experience.** If you have shipped field-level encryption and watched it break, that is what the design is missing.

Security issues: [`SECURITY.md`](SECURITY.md), not a public issue.

## License

Mapped by path in [`LICENSES.md`](LICENSES.md); rationale in [`GOVERNANCE.md`](GOVERNANCE.md).

| What | License |
|---|---|
| Specification and documentation | [CC BY 4.0](LICENSE-SPEC) |
| Test vectors | [CC0 1.0](LICENSE-VECTORS) |
| Code | [Apache 2.0](LICENSE) |
