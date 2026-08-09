# Governance

**Status:** proposed. Nothing here is settled.

## Why this exists early

The best options in this space are cautionary tales about maintainer concentration. `lockbox` and `blind_index` — arguably the most complete open-source field-encryption story on any platform — are single-maintainer projects. Cossack Labs' Acra, the closest existing thing to this concept, has not shipped a release since September 2024. CipherSweet's Java, .NET, Rust, and Python ports have been listed as "coming soon" for years.

A specification outlives any single implementation, which is the main structural defense. But the specification still needs a home that does not depend on one person continuing to care.

## Target: OpenSSF Sandbox

The [OpenSSF project lifecycle](https://github.com/ossf/tac/blob/main/process/project-lifecycle.md) requires, for Sandbox entry:

- **3+ maintainers from 2+ organizations**
- alignment with the OpenSSF mission
- **1 TAC or Working Group sponsor**
- documented security best practices

Application is by pull request to the `ossf/tac` repository.

**The binding constraint is the maintainer requirement, and it must be satisfied before applying.** This is treated as a useful forcing function rather than an obstacle: a project that cannot find three maintainers across two organizations probably should not be claiming to be a reference architecture.

Incubating adds a contributor guide, documented governance, multi-party adoption, and an OpenSSF Silver badge. Graduated adds 5 maintainers across 3+ organizations, a Gold badge, a third-party security audit, and production adoption. Projects dormant for 9+ months are archived.

## Decision-making (proposed)

- **Specification changes** require consensus among maintainers, with a public issue and a minimum comment window before merge. A single maintainer cannot land a normative change.
- **Cipher suite additions** require, in addition, review from someone with cryptographic credentials who is not a maintainer. The registry is deliberately capped at two suites for v1.0; the bar for a third is high.
- **Implementation changes** follow ordinary review.
- **Breaking changes to the envelope format** are permitted before v1.0 and forbidden after, except via the suite-retirement mechanism (spec §4.3, §5.9).

## Licensing (proposed, not final)

- **Specification and documentation:** CC BY 4.0 — so it can be quoted, profiled, and incorporated into other standards without friction. That is the point of writing a specification.
- **Code:** Apache 2.0 — permissive, with an explicit patent grant, and compatible with OpenSSF and CNCF expectations.

Open question: whether the test vectors should be CC0 rather than CC BY, to remove any attribution friction from a competing implementation running them. Leaning yes — the vectors' value comes from being run, not from being credited.

## What is deliberately not decided yet

- Trademark registration. The name `Fieldseal` was selected 2026-08-08 after collision vetting (npm and PyPI free; bare GitHub org squatted-but-empty → publish under `fieldseal-spec`; nearest trademark is "Field Seal" farm toolboxes, unrelated class). Remaining: claim npm `@fieldseal` scope and the PyPI name, check NuGet / Maven Central / crates.io, register `fieldseal.dev` or `.org`, and run USPTO TESS before any public release.
- Whether to pursue OASIS standardization later. That requires a funded Project Sponsor and only makes sense once a real multi-vendor interoperability story exists — the OASIS Standard track requires three Statements of Use from real implementations, which is a good long-term target and a bad near-term one.
- Whether the specification's long-term home is an IETF Independent Submission RFC. See [`docs/05-dissemination.md`](docs/05-dissemination.md) §5.
