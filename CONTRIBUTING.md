# Contributing

## What is most wanted right now

The specification is a working draft and has not been independently reviewed. The highest-value contributions, in order:

1. **Cryptographic review of [`docs/02-spec-v0.1.md`](docs/02-spec-v0.1.md)** — especially the open questions in §13 and the contested claims in §14. If a mandate is wrong, say so plainly; the spec is written to make its own reasoning attackable.
2. **Answers to the open questions.** §13.1 (profile the AWS structured-encryption format or define fresh?) and §13.2 (which FIPS-approvable AEAD?) are blocking Phase 1 and should be settled before code is written.
3. **Corrections to the ORM analysis** in [`docs/04-orm-adapter-notes.md`](docs/04-orm-adapter-notes.md). Several claims were verified against ORM source; some were not, and those are marked. If you maintain one of these ORMs and something is wrong, a correction is worth more than a feature.
4. **Corrections to the compliance mapping.** §8 of that document lists what could not be verified. Closing any of those items is a real contribution.

## Specification changes

Open an issue before a PR. Every normative change needs:

- **A justification with a citation** — a NIST publication, an IETF RFC, peer-reviewed literature, or shipping-product documentation. "This seems better" is not enough.
- **A statement of what it breaks.** Envelope format and suite registry changes are compatibility-breaking by definition until v1.0 is tagged.
- **Test vectors.** A normative change without vectors cannot be verified across implementations.

Changes that add a cipher suite are held to a higher bar than changes that clarify prose. The spec deliberately commits to "one option, maybe two"; proposals to add a third need to argue why the existing suites are inadequate, not merely why the new one is nice.

## Implementations

An implementation may claim a conformance level only if it passes every vector for that level in CI. **The cross-implementation vectors are the ones that matter** — ciphertext produced by implementation A decrypted by implementation B. That test is the entire point of the project; if it is failing, nothing else counts.

Adapters must:

- contain **zero cryptographic code** — their only permitted calls into the core are the five synchronous functions plus `warm`
- publish a coverage matrix stating exactly which write, read, and query paths they intercept
- **throw** rather than degrade on any path that would silently write plaintext or silently return wrong results (spec §10.2)

## Documentation

Two standing rules, and they are not negotiable:

**Every claim gets a citation or a flag.** The "not verified" list in the compliance document is a feature. Reviewers trust documents that say what they don't know.

**Do not overclaim.** This project's positioning depends on being the document that says SOC 2 does not require this, that CIS says storage-layer encryption meets the minimum, and that the "60% of small businesses close after a breach" statistic is fabricated. A single unsupported claim costs more credibility than ten supported ones earn.

## Code of conduct

Be straightforward and assume good faith. Technical disagreement is welcome and expected; a spec that nobody argues with has not been read.
