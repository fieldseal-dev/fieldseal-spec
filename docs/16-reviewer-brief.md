# Cryptographic Reviewer Brief

**Date:** 2026-08-08 · **Status:** Draft 1 — the document sent to prospective Phase 0 reviewers · **Why this exists:** the Phase 0 exit gate (PRD §8) is *"at least two people with real cryptographic credentials have read the spec and their objections are addressed or documented."* Independent review is the project's top-listed risk mitigation, not a courtesy. This brief tells a reviewer exactly what is being asked, in what order to read, and which questions actually gate the project — so the review costs hours, not weeks.

---

## 1. What this is and what we are asking

Fieldseal is a draft specification for portable field-level encryption-at-rest at the data-access layer: a self-describing per-cell ciphertext envelope, a frozen two-suite registry, a three-tier key hierarchy with per-write derived keys, and a blind-index construction with a declared leakage budget. Cross-language test vectors are the conformance mechanism. There is **no code yet** — that is deliberate; code begins only after this review.

**The ask:** read roughly 25 pages along the path in §2, then answer the eight questions in §3. Each question points at a concrete proposal (a tracker issue or decision record), so you are reacting to specifics, not brainstorming. Estimated effort: **6–10 hours**. Objections do not need solutions attached — "this is wrong because X" is a complete, valuable answer.

**Not being asked:** implementation review (nothing to review), compliance-mapping review (`docs/03`), ORM-integration analysis (`docs/04`), or editorial feedback. If you notice such issues in passing, they are welcome, but they do not gate anything.

## 2. Reading path

| Step | What | Why | ~Time |
|---|---|---|---|
| 1 | [`README.md`](../README.md) | The problem, the design commitments, the honest-limitations list | 15 min |
| 2 | Spec [`docs/02-spec-v0.1.md`](02-spec-v0.1.md) §1–§2 | Scope and threat model — what the design does and does not defend against | 20 min |
| 3 | Spec §3–§6 | Envelope, suite registry, key hierarchy, context binding — the cryptographic core | 1.5–2 h |
| 4 | Spec §7 | Blind indexes — the highest-risk feature; §7.6/§7.10 state its limits | 1–1.5 h |
| 5 | Spec §9, §13, §14 | Error taxonomy; open questions; **§14 is a pre-built list of every claim we flagged as contested — it was written for you** | 45 min |
| 6 | The eight questions below, each with its linked proposal | The actual review targets | 2–4 h |

Skippable entirely: `docs/00` (market analysis), `docs/03`–`docs/05`, `docs/10`–`docs/15` (engineering bindings). They exist; none of them gate this review.

## 3. The questions that gate Phase 1

Each names the artifact holding the concrete proposal. "What closes it" states the answer type needed — endorsement, counterexample, or correction.

**Q1 — Is the per-write-key structure sufficient justification for AES-GCM in a database setting?** (spec §4.4, §5.3)
Databases break every nonce discipline SP 800-38D permits: UPDATEs re-encrypt different plaintext at the same identity, restored backups rewind counters, autoscaled tiers void device-ID uniqueness. The spec's answer is structural: every envelope carries a fresh random 32-byte `msg_seed`, so every derived key encrypts exactly one value; the random 96-bit nonce is defense in depth on top of key uniqueness. *What closes it:* explicit endorsement that this holds in the stated threat model (§2), or a counterexample. This question underpins Q8 — if the argument fails, option A of ADR-0002 fails with it.

**Q2 — The key-commitment construction.** ([issue #1](https://github.com/fieldseal-dev/fieldseal-spec/issues/1), spec §4.6/§3.1)
Proposal: `commitment = HKDF-SHA-512(ikm = record_key, salt = "", info = "fieldseal-commit-v1", length = 32)`, verified constant-time before AEAD open. *What closes it:* does this achieve the binding needed to stop partitioning oracles (CMT-1 in the Bellare–Hoang framing)? Is verify-before-decrypt with early exit on commitment success acceptable, given commitments are public envelope content?

**Q3 — The Argon2id invocation layout.** ([issue #2](https://github.com/fieldseal-dev/fieldseal-spec/issues/2), spec §7.3)
Proposal: password = normalized plaintext; salt = HKDF-derived from the index key (deterministic — determinism is the point of a blind index); index key via RFC 9106's secret parameter K. *What closes it:* is the deterministic salt sound for this keyed use, and is K the right place for the key?

**Q4 — Canonical-encoding injectivity.** ([issue #4](https://github.com/fieldseal-dev/fieldseal-spec/issues/4), spec §6.2; includes [#11](https://github.com/fieldseal-dev/fieldseal-spec/issues/11))
`canonical_context` is both KDF info and AAD; optional fields (`tenant_id`, `row_id`) currently have under-specified null encodings. Proposal: a presence bitmap. *What closes it:* confirmation the chosen encoding is injective over the current and future-extended field set, or a demonstrated aliasing.

**Q5 — Decrypt error precedence and oracle risk.** ([issue #5](https://github.com/fieldseal-dev/fieldseal-spec/issues/5), spec §9/§3.4/§6.3)
A pinned check-order state machine; under dual binding, context mismatch and key confusion are indistinguishable at decrypt time, and the issue proposes reporting `COMMITMENT_INVALID` with an optional *diagnostic* re-derivation under known-legitimate context variants. *What closes it:* sign-off on the timing posture (constant-time compares, early exit) and on whether the diagnostic re-derivation could be abused as an oracle.

**Q6 — XChaCha20-Poly1305's normative source.** ([issue #7](https://github.com/fieldseal-dev/fieldseal-spec/issues/7), spec §4.2)
No RFC exists; the draft expired. Proposal: name libsodium's construction as normative (the PASETO precedent), or drop suite 0x0002. *What closes it:* a position — is a libsodium-defined suite acceptable in a spec that demands citations, or is a one-suite registry the honest answer?

**Q7 — Envelope-format novelty risk.** ([ADR-0001](adr/0001-envelope-format-source.md) + [Appendix A](adr/0001-appendix-a-expressibility-mapping.md), spec §13.1)
The highest-leverage open decision: profile AWS's structured-encryption format, define fresh, or define fresh with AWS-aligned constructions. Appendix A's clause-level mapping found the strict profile fails (§6.3 dual binding is not expressible; per-cell embedding costs 1.4×–2.4×). *What closes it:* your read on whether the fresh envelope's novel surface is acceptable given the review it is now receiving, and whether option C's construction-borrowing (commitment shape, Message-ID derivation, footer model) captures the risk reduction that matters.

**Q8 — The mandatory suite's AEAD.** ([ADR-0002](adr/0002-suite-0x0001-aead.md), spec §13.2)
AES-256-GCM + explicit commitment vs AES-256-CBC-HMAC-SHA-512 (natively committing, composition-validation question) vs AES-GCM-SIV (best misuse resistance, not FIPS-approvable). The overhead argument is settled arithmetic (the ADR's "Overhead evidence" section — option B with the RFC 7518 truncated tag is actually *smaller* than A at the benchmark), so the decision rides on FIPS-validation reality and on your Q1 answer. One sub-question surfaced by that arithmetic: spec §4.5 forbids tag truncation — does that rule out B's RFC 7518-standard 32-byte truncated HMAC-SHA-512 tag, or does a 256-bit tag satisfy §4.5's intent (a floor aimed at short GCM tags)? *What closes it:* a recommendation with reasoning, plus a position on the §4.5 reading.

**Plus the standing sweep:** spec §14 lists every claim the authors flagged as contested, with the reason. Confirming or refuting entries there is exactly as valuable as the numbered questions.

## 4. Ground rules

- **Where to respond:** GitHub issues on [`fieldseal-dev/fieldseal-spec`](https://github.com/fieldseal-dev/fieldseal-spec/issues) (preferred — the review should be public), referencing the question number; or by email to the maintainer if you prefer private first contact.
- **What happens to objections:** each is recorded and either addressed with a spec change (issue → citation → breakage statement → vectors, per `CONTRIBUTING.md`) or documented as an accepted open risk. The gate is *addressed or documented* — you do not need to be agreed with for the gate to close honestly.
- **Everything is public, no NDA.** The specification is CC BY 4.0 and the test vectors are CC0 1.0 — settled 2026-08-09, not proposed (`LICENSES.md`).
- **Credit:** reviewers are named in the spec's acknowledgments with their permission; anonymous review is fine too.
- **Compensation:** none — this is an unfunded open-source review request, stated plainly so you can decline on that basis alone. What we offer instead: public acknowledgment (§ above), a review scope deliberately compressed to hours by the question format, and a design that took your time seriously enough to pre-flag its own contested claims (§14) before asking for it.
- **Timeline:** a **4-week window** from your acceptance. That covers the targeted read and written responses to the eight questions at a few hours per week; partial responses inside the window beat complete ones after it — an early answer to Q1 or Q7 alone unblocks more than a late answer to everything. The Phase 1 implementation clock (~12 weeks, PRD §8) starts only when this gate closes, so review latency is the project schedule.

## 5. One honest paragraph a reviewer should see before accepting

This specification was written by generalist engineers from the primary literature, not by cryptographers, and it says so. The two things most likely to be wrong are the things you are being asked hardest about: the per-write-key argument for GCM in a hostile-nonce environment (Q1), and the blind-index leakage stance built on AWS's engineering heuristics rather than peer-reviewed bounds (spec §7.4 flags this itself). The project's stated position is that a design this security-sensitive should not exist without exactly the review this brief requests — if your conclusion is "do not ship this," that is a successful review outcome, and the repository's history shows unfavorable findings get recorded, not buried (`docs/06-verification-log.md`).
