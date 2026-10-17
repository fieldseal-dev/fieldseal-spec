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

## Dependency updates

Dependabot is enabled for **security updates only**: there is no `dependabot.yml`, so there are no version-update PRs, and a dependency version otherwise moves only when a PR moves it.

A security-update PR arrives against the repository's **default branch**, `main`. This project merges it on the integration branch instead:

1. **Retarget it to `dev`** — `gh pr edit <n> --base dev`.
2. **Squash-merge** it once its checks are green — `gh pr merge <n> --squash --delete-branch`. A work PR into `dev` is merged as a merge commit, while a Dependabot PR has been squashed (#234, #258). GitHub does not delete the branch for us (`deleteBranchOnMerge` is off), so it is deleted by hand.
3. The change reaches `main` with the next `dev → main` promotion PR, which is itself merged as a merge commit.

**Do not add `target-branch: dev` to a `dependabot.yml` to avoid step 1.** `target-branch` is a version-updates option; GitHub documents that with it defined, "options defined for this `package-ecosystem` no longer apply to security updates because security updates always use the default branch for the repository" ([Dependabot options reference](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference#target-branch-)). It would leave security PRs on `main` anyway *and* stop the rest of that ecosystem's configuration from applying to them. Only changing the repository's default branch changes the branch Dependabot itself opens against. If the annoyance is the number of PRs rather than the base branch, the repository-level **Grouped security updates** setting (Settings → Advanced security) combines them without a config file, and likewise does not change the base branch.

An advisory is per manifest, so one vulnerable package reachable from two lockfiles is two alerts and up to one PR per directory (the `source-map-js` advisory of 2026-10-17 was open in `core/typescript/package-lock.json` and `adapters/prisma/package-lock.json`). Read the alert's **scope** before setting urgency: a `development`-scope alert lives in the toolchain rather than in an artifact this repository publishes — the TypeScript core declares no runtime dependencies — while an alert whose scope reaches a published package is a different question.

## Licensing of contributions

By contributing, you agree your contribution is licensed under whichever license governs the path you are touching, per [`LICENSES.md`](LICENSES.md): CC BY 4.0 for the specification and documentation, CC0 1.0 for the test vectors, Apache 2.0 for code. There is no CLA.

If that mapping is wrong for something you want to contribute — a tool that embeds vector data, say — raise it in the issue before opening the PR rather than after.

## Code of conduct

Be straightforward and assume good faith. Technical disagreement is welcome and expected; a spec that nobody argues with has not been read.
