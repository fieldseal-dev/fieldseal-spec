# Spec-gap issue drafts (G1–G13)

**Date:** 2026-08-08 · **Status:** all thirteen posted to the GitHub tracker on 2026-08-08; issue numbers align with gap numbers (G*n* = issue #*n*). These files remain the canonical drafts; edits after posting belong in the tracker.

These are the specification gaps found while writing the Phase 1 tech-spec suite (G1–G11) and during its consistency review (G12–G13), consolidated in `docs/07-implementation-plan.md` §5. Per `CONTRIBUTING.md`, every specification change starts as an issue carrying: a justification with a citation, a statement of what it breaks, and test-vector obligations. Each file here is one complete issue body in that shape, titled and labeled per `CLAUDE.md` ("label the issue with the section it touches").

"Proposed direction" in each issue is a **starting point for discussion, not a decision** — the ones marked *needs cryptographic review* must not be closed by engineering judgment alone.

| # | Issue | File | Section | Blocks | Crypto review |
|---|---|---|---|---|---|
| G1 | [#1](https://github.com/fieldseal-dev/fieldseal-spec/issues/1) | [`G01-key-commitment-construction.md`](G01-key-commitment-construction.md) | §4.6, §3.1 | all envelope/commitment vectors; ADR-0002 | **Yes** |
| G2 | [#2](https://github.com/fieldseal-dev/fieldseal-spec/issues/2) | [`G02-argon2id-parameters.md`](G02-argon2id-parameters.md) | §7.3 | Argon2id blind-index vectors | **Yes** |
| G3 | [#3](https://github.com/fieldseal-dev/fieldseal-spec/issues/3) | [`G03-truncation-bit-semantics.md`](G03-truncation-bit-semantics.md) | §7.2, §7.4 | all blind-index vectors | No |
| G4 | [#4](https://github.com/fieldseal-dev/fieldseal-spec/issues/4) | [`G04-tenant-id-null-encoding.md`](G04-tenant-id-null-encoding.md) | §6.2 | context vectors; any absent-tenant envelope vector | **Yes** |
| G5 | [#5](https://github.com/fieldseal-dev/fieldseal-spec/issues/5) | [`G05-error-precedence.md`](G05-error-precedence.md) | §9, §3.4, §6.3 | most of `errors/crypto.json` | Partly |
| G6 | [#6](https://github.com/fieldseal-dev/fieldseal-spec/issues/6) | [`G06-readonly-mode-error.md`](G06-readonly-mode-error.md) | §9, §10.3 | `errors/policy.json` mode cases | No |
| G7 | [#7](https://github.com/fieldseal-dev/fieldseal-spec/issues/7) | [`G07-xchacha-normative-source.md`](G07-xchacha-normative-source.md) | §4.2 | suite 0x0002 vector confidence | Partly |
| G8 | [#8](https://github.com/fieldseal-dev/fieldseal-spec/issues/8) | [`G08-blind-index-stored-representation.md`](G08-blind-index-stored-representation.md) | §7 | blind-index storage assertions; adapter DDL | No |
| G9 | [#9](https://github.com/fieldseal-dev/fieldseal-spec/issues/9) | [`G09-async-blind-index.md`](G09-async-blind-index.md) | §11.1 | none (API surface; L4 ergonomics) | No |
| G10 | [#10](https://github.com/fieldseal-dev/fieldseal-spec/issues/10) | [`G10-plaintext-length-bound.md`](G10-plaintext-length-bound.md) | §3 | one boundary behavior | No |
| G11 | [#11](https://github.com/fieldseal-dev/fieldseal-spec/issues/11) | [`G11-purpose-grammar.md`](G11-purpose-grammar.md) | §6.1, §7.2 | context negative vectors | No |
| G12 | [#12](https://github.com/fieldseal-dev/fieldseal-spec/issues/12) | [`G12-unique-constraint-contradiction.md`](G12-unique-constraint-contradiction.md) | §7.10, §7.4 | adapter DDL guidance | No |
| G13 | [#13](https://github.com/fieldseal-dev/fieldseal-spec/issues/13) | [`G13-prisma-in-rewrite-vs-reject.md`](G13-prisma-in-rewrite-vs-reject.md) | §10.2, §7.10 | Prisma conformance wording | No |

## Closure log

| # | Resolved | Resolution |
|---|---|---|
| G3 | 2026-08-08 | Adopted as proposed: spec §7.2 pins `truncate` bit-exactly (leading `⌈b/8⌉` bytes, MSB-first bit numbering, trailing bits of the final byte zeroed); §7.4 cross-references it; §12 requires `b mod 8 ≠ 0` vectors. Unblocks `blind-index/hmac.json` fully; `argon2id.json` still waits on G2. Tracker [#3](https://github.com/fieldseal-dev/fieldseal-spec/issues/3) to close on push. |

When an issue closes, sweep the tech-spec suite for the corresponding `G<n>` markers (`grep -rn "G<n>" docs/07* docs/08* docs/09* docs/1[0-5]* docs/adr docs/issues`) and update every dependent section — that sweep is part of closing, per `docs/07-implementation-plan.md` §6. Namespace caveat: `docs/00-research-memo.md` uses G1–G6 for *market* gaps (and `docs/06-verification-log.md` cites them) — a bare repo-wide grep collides with that older namespace; the sweep scope above avoids it.
