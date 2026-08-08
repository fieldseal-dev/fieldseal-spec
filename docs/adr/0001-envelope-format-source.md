# ADR-0001: Profile the AWS structured-encryption format, or define the envelope fresh

**Status:** OPEN — spec §13.1 calls this "the highest-leverage unresolved decision"; it blocks all Phase 1 code · **Date opened:** 2026-08-08 · **Spec refs:** §3, §13.1 · **PRD refs:** §10 item 1 (a plain list — the PRD has no §10 subsections), risk "a vendor ships an equivalent open format first"

## Context

The v0.1 envelope (spec §3.1) is defined fresh. AWS maintains a normative, RFC-2119 structured-encryption specification (aws-database-encryption-sdk-dynamodb) written against generic "Structured Data" with Terminal fields, not DynamoDB types. Every artifact in this repo — vectors, cores, adapters — serializes the envelope, so changing this after code exists means rewriting everything; that is why it must close before Phase 1 starts (spec §13.1, CONTRIBUTING.md item 2).

## Options

### A. Profile the AWS format

Fieldseal envelopes become a documented profile (subset + fixed choices) of the AWS structured-encryption header/format.

- **Buys:** interoperability with a shipping, security-reviewed implementation; large novelty-risk reduction (PRD's top risk is "the spec is wrong in a way only a cryptographer would catch" — reusing a reviewed format shrinks the novel surface); a cooperative rather than competitive posture toward the most likely "vendor ships an equivalent format" scenario (PRD §9).
- **Costs:** inherits DynamoDB-item lineage and AWS KMS assumptions in the key-provider model (the spec's own reservation, §13.1); Fieldseal-specific commitments — per-write `msg_seed` (§3.1), sibling index keys (§5.2), the §6.2 canonical context — must be expressible inside it or as a profile extension, which may hollow out the interop benefit. **The clause-level mapping now exists: [Appendix A](0001-appendix-a-expressibility-mapping.md) (2026-08-08). Headline: §6.3 dual-layer binding is not expressible in the AWS format, §3.2/§4.4 survive only as reworded equivalent-protection arguments, and the per-cell embedding costs 1.4×–2.4× the fresh envelope at the §3.3 benchmark — evidence favoring option C, re-verified 2026-08-08 against the raw AWS spec text pinned at commit `a82094c` (Appendix A §8).**
- **Breaks:** the v0.1 envelope layout; all of `docs/08`/`docs/09` §4 as written.

### B. Define fresh (v0.1 status quo)

- **Buys:** exact fit to the design commitments (msg_seed, explicit commitment field, minimal fixed header); freedom from AWS semantics; a format whose every byte the spec justifies inline.
- **Costs:** full novelty risk on the format itself; the independent cryptographic review (Phase 0 exit gate) must cover envelope construction, not only suite choices; zero interop with existing ciphertext.
- **Breaks:** nothing now; forfeits option A permanently once ciphertext exists in the wild.

### C. Hybrid: fresh envelope, AWS-aligned constructions

Define the envelope fresh but deliberately align internal constructions (commitment derivation, key-derivation labels) with AWS ESDK v2 patterns so review can lean on their published analysis.

- **Buys:** most of B's fit with some of A's review-surface reduction. The spec already does this implicitly (msg_seed cites the ESDK v2 Message ID precedent, §3.1).
- **Costs:** "aligned" is weaker than "profiled" — no wire interop, and the alignment claim needs case-by-case citation to survive review.

## Decision criteria

1. Can every normative requirement of spec §3–§6 be expressed in the candidate format without weakening? (A fails if not; produce the clause-level mapping first.)
2. Does the choice reduce the surface the independent cryptographic review must treat as novel? (This is the PRD's highest-rated risk; weight accordingly.)
3. Envelope overhead delta at the 9-byte-SSN benchmark (§3.3) — the honesty math must be redone for A and stay defensible.
4. Does the choice survive AWS evolving their format unilaterally? (A needs a pinned-version profile statement; "tracks AWS main" is not a spec.)

## Evidence needed to close

- ~~The §3–§6 → AWS-format expressibility mapping~~ — **delivered as [Appendix A](0001-appendix-a-expressibility-mapping.md) (2026-08-08), verification closed the same day**: the AWS spec is pinned at commit `a82094c`, all eight `structured-encryption/` files were re-read as raw text, and the byte arithmetic re-verified — totals and the 1.4×–2.4× ratio unchanged (Appendix A §8). One flagged residual: the MaterialProviders submodule (tag length, suite parameters) was not retrieved; no verdict depends on it. The appendix may now be cited in the Decision.
- An opinion from at least one of the Phase 0 cryptographic reviewers specifically on envelope-format novelty risk (exit-gate reviewers are already required; add this question to their brief).
- Optional but valuable per PRD §9: early contact with the AWS ESDK team — they may generalize their format themselves, which changes the calculus toward A.

## Decision

*(open)*
