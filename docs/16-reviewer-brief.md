# Cryptographic Reviewer Brief

**Date:** 2026-08-08 · **Revised:** 2026-08-22 · **Status:** Draft 2 — the document sent to prospective reviewers

**Why this exists.** Fieldseal is a draft specification for portable field-level encryption-at-rest. It was written by generalist engineers from the primary literature, not by cryptographers. Eight specific claims in it need someone who knows this material to confirm or kill. **Answering exactly one of them is a complete and useful contribution** — §2 is built so each question stands alone, and you can stop after one.

---

## 1. The ask, in two sizes

**One question — 15 to 90 minutes.** Pick any card in §2. Each names the few pages to read, the concrete proposal, and the kind of answer that settles it. Nothing else in this repository is prerequisite. If you only ever answer [Q1](#q1) or [Q7](#q7), that alone unblocks more than a complete late response to all eight.

**The full brief — 5 to 7 hours.** All eight questions, plus the standing sweep in spec §14 (a pre-built list of every claim the authors flagged as contested — it was written for a reviewer, not for the record).

**Objections do not need solutions attached.** "This is wrong because X" is a complete answer. So is "this is fine." So is "I don't know, but here is who would."

**Not being asked:** implementation review, compliance-mapping review (`docs/03`), ORM-integration analysis (`docs/04`), or editorial feedback. Welcome in passing; gates nothing.

### What your answer changes

The project's Phase 0 exit gate was split on 2026-08-22 (`docs/01-prd.md` §8), and you should know this before deciding whether to spend time here.

- **Gate 0a — implementation.** The project closed this itself. The eight questions below were answered *provisionally*, in normative spec text, each marked **[PROVISIONAL]** and linked back to its tracker issue. Reference implementations are being built against those provisional answers.
- **Gate 0b — freeze.** This is still you, and it is unchanged. Until two credentialed reviewers have read the spec and their objections are addressed or documented, the project does not assign a real suite identifier, does not publish a stable vector suite, does not claim conformance to a frozen format, does not invite production adoption, and does not run its dissemination track.

Two honest consequences. First, this makes your answer *more* concrete, not less: it now corrects working code and a machine-checkable test-vector suite, not only a document. Second, it means the project has committed effort in a direction you may reject — and it has been structured so that rejecting it stays cheap. Every suite identifier is provisional (spec §4.8), implementations refuse to write under one without an explicit operator acknowledgment, and anything written that way is identifiable from stored bytes alone. **You are not being handed a fait accompli, and if it starts to read like one, say so.**

---

## 2. The questions

Each card is self-contained. Read the named sections, not the whole spec.

<a id="q1"></a>
### Q1 — Does the per-write-key structure justify AES-GCM in a database setting?

| | |
|---|---|
| **Read** | Spec §2 (threat model, 2 pp.) · §4.4 (nonce policy) · §5.3 (record-key derivation) |
| **Time** | ~45–60 min |
| **Provisional status** | Adopted; suite `0xFF01` is built on it |
| **Blocks** | [Q8](#q8) — if this argument fails, ADR-0002's option A fails with it |

Databases break every nonce discipline NIST SP 800-38D permits. UPDATEs re-encrypt different plaintext at the same row identity. Restored backups rewind counters. Autoscaled application tiers void device-ID uniqueness partitioning. There is no safe place to keep a counter.

The spec's answer is structural rather than operational: every envelope carries a fresh random 32-byte `msg_seed`, and the record key is derived from it, so **every derived key encrypts exactly one value**. The 96-bit random nonce is then defense in depth on top of key uniqueness rather than the thing being relied upon, and the 2³² invocation ceiling of SP 800-38D §8.3 is unreachable by construction rather than by scale assumption.

**What closes it:** an explicit endorsement that this argument holds within the stated threat model (§2) — or a counterexample. A counterexample is the more valuable outcome and the project would rather have it now.

<a id="q2"></a>
### Q2 — Is the key-commitment construction sound?

| | |
|---|---|
| **Read** | Spec §4.6 (key commitment) · §3.1 (envelope layout) · §5.3 |
| **Time** | ~30–45 min |
| **Proposal** | [issue #1](https://github.com/fieldseal-dev/fieldseal-spec/issues/1) |
| **Provisional status** | Adopted; spec §4.6 carries a `[PROVISIONAL]` marker |

Proposed: `commitment = HKDF-SHA-512(ikm = record_key, salt = "", info = "fieldseal-commit-v1", length = 32)`, compared in constant time before the AEAD open is attempted.

The motivation is not theoretical. AWS shipped [AWS-2025-032](https://aws.amazon.com/security/security-bulletins/AWS-2025-032/) in December 2025 — "Key Commitment Issues in S3 Encryption Clients," CVE-2025-14759 through -14764, across six language SDKs — with the note "There are no known workarounds."

**What closes it:** does this achieve the binding needed to stop partitioning oracles — CMT-1 in the Bellare–Hoang framing? And is verify-before-decrypt with early exit on commitment success acceptable, given that commitments are public envelope content?

<a id="q3"></a>
### Q3 — Is the Argon2id invocation layout sound for a keyed, deterministic use?

| | |
|---|---|
| **Read** | Spec §7.2–§7.3 (blind-index construction and IDF selection) · RFC 9106 §3.1 |
| **Time** | ~30–45 min |
| **Proposal** | [issue #2](https://github.com/fieldseal-dev/fieldseal-spec/issues/2) |
| **Provisional status** | Adopted and **narrowed 2026-08-22**; spec §7.3 now pins the full invocation and carries a `[PROVISIONAL]` marker |

Spec §7.3 pins this exactly:

```
salt = HKDF-SHA-512(ikm = index_key, salt = "", info = "fieldseal-argon2-salt-v1", length = 16)
raw  = Argon2id(password = normalize(plaintext), salt = salt,
                version = 0x13, t = 3, m = 32768 KiB, p = 1, output_len = 64)
```

The index key enters **only** through the salt. Argon2's optional secret parameter `K` and associated data `X` are forbidden.

That is not where this started. The original proposal put `index_key` in `K`, and the project withdrew it — not on cryptographic grounds but because `K` is unreachable in Python. libsodium's `crypto_pwhash` exposes no secret parameter at all; `argon2-cffi` exposes one only through an ultra-low-level call its own documentation warns against; Node's `node-argon2` does expose it. A construction one reference core can express and the other cannot is this project's central claim failing, so the option is dead regardless of its merits. Sources are in [issue #2](https://github.com/fieldseal-dev/fieldseal-spec/issues/2).

Two costs follow, and the specification states both. Keying now rests entirely on the salt, so the defense-in-depth argument for `K` is gone. And the salt is 16 bytes because libsodium requires exactly 16, so the keyed material at this step is 128 bits rather than 256.

The construction that remains is close to what CipherSweet ships — Argon2id "where the blind index key is the Argon2 salt" — with an HKDF step added so the raw key never reaches Argon2 directly.

**What closes it:** one question. Is salt-only keying, through a domain-separated HKDF step, sound for this deterministic keyed use? The salt is deterministic by design, since determinism is the point of a blind index. If your answer is that it is unsound, the live alternative is explicit domain-separated concatenation into the password — not a return to `K`, which is not available to us.

<a id="q4"></a>
### Q4 — Is the canonical context encoding injective?

| | |
|---|---|
| **Read** | Spec §6.1–§6.4 (context binding — 2 pp.) |
| **Time** | ~20–30 min |
| **Proposal** | [issue #4](https://github.com/fieldseal-dev/fieldseal-spec/issues/4), incl. [#11](https://github.com/fieldseal-dev/fieldseal-spec/issues/11) |
| **Provisional status** | Adopted; spec §6.2 carries a `[PROVISIONAL]` marker |

`canonical_context` is used twice — as the KDF `info` parameter and inside the AEAD's AAD — so an aliasing collision is a key-reuse bug and an authentication bug simultaneously. The optional fields are where it is weak: `row_id` is "omitted entirely if null" while `tenant_id` has no stated null encoding at all, so under the original positional encoding an absent `tenant_id` and a present-but-zero-length one produced identical bytes. The fix — a presence bitmap — is in §6.2 provisionally under Gate 0a and is what the cores and vectors now use; the question for you is whether it is the right fix.

**What closes it:** confirmation that the chosen encoding is injective over the current field set *and* over plausible future extensions — or a demonstrated aliasing. This is the cheapest question here and the one where a counterexample is most likely.

<a id="q5"></a>
### Q5 — Is the decrypt error precedence free of oracle risk?

| | |
|---|---|
| **Read** | Spec §9 (errors) · §3.4 (detection) · §6.3 (dual-layer binding) |
| **Time** | ~45 min |
| **Proposal** | [issue #5](https://github.com/fieldseal-dev/fieldseal-spec/issues/5) |
| **Provisional status** | Adopted; spec §9 carries a `[PROVISIONAL]` marker |

The spec refuses to collapse failures into a single "decryption failed," on the grounds that operators cannot debug migrations without distinguishable errors. That refusal is where the risk lives.

Under dual-layer binding (§6.3) a context mismatch and a key confusion are indistinguishable at decrypt time. The proposal pins a check-order state machine, reports `COMMITMENT_INVALID` in that case, and offers an optional *diagnostic* re-derivation under known-legitimate context variants.

**What closes it:** sign-off on the timing posture (constant-time comparisons, early exit) and on whether the diagnostic re-derivation is abusable as an oracle. If it is, saying so kills a feature, which is a fine outcome.

<a id="q6"></a>
### Q6 — What is XChaCha20-Poly1305's normative source?

| | |
|---|---|
| **Read** | Spec §4.2 (registry) — one page |
| **Time** | ~15 min |
| **Proposal** | [issue #7](https://github.com/fieldseal-dev/fieldseal-spec/issues/7) |
| **Provisional status** | Suite retained provisionally; the question itself is untouched |

No RFC exists. `draft-irtf-cfrg-xchacha` expired. libsodium's `crypto_aead_xchacha20poly1305_ietf_*` is the de-facto standard. A specification that demands a citation for every normative claim cannot name a suite it cannot cite.

**The precedent is weaker than it first looks** (verified 2026-08-22). PASETO **v2.local** does specify XChaCha20-Poly1305 "using an AEAD interface such as the one provided in libsodium," citing no RFC or draft — a real instance of the choice. But **v4.local** moved to XChaCha20 with a separate BLAKE2b-MAC, so it is not a second instance; and PASETO's author is also the author of the expired `draft-irtf-cfrg-xchacha`, so what reads as independent corroboration is one party's judgment. The draft's status is pinned: revision **-03, expired 2023-05-02, datatracker state "Dead IRTF Document."**

**What closes it:** a position, not an analysis. Is a libsodium-defined suite acceptable in a specification seeking independent review, or is a one-suite registry the honest answer? This is the fastest question in the set and it is genuinely blocked on someone else's judgment.

**Input received, 2026-08-23 (CFRG list, in reply to the 2026-08-22 post; not a review, recorded as what it is).** Three replies, two substantive:

- *Neil Madden*: not aware of any other stable specification for XChaCha20-Poly1305 — so no revival to wait for — and asks whether a general-purpose KDF deriving a subkey for standard ChaCha20-Poly1305 would not achieve the same end.
- *John Preuß Mattsson (Ericsson)*: (1) `draft-irtf-cfrg-xchacha-03` **is a stable, citable document** — "it will not change, and the IETF will keep the document available indefinitely" (`https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt`), which answers the citation question this brief thought was blocked; (2) "non-NIST" is the wrong design goal — *a different hardness assumption* is the sensible one, and this project's rationale wording should say that instead; (3) the recommended way to get random extended nonces with any AEAD is `K' = KDF(K, E); C = AEAD(K', N, P, A)` — which is **already §5.3**, with the 32-byte `msg_seed` as `E` — so the 192-bit nonce that motivated XChaCha is redundant here and plain RFC 8439 ChaCha20-Poly1305 under the derived key is the fully citable alternative; (4) NIST's SP 800-38D r1 second public draft is considering removing support for non-96-bit GCM IVs (`https://csrc.nist.gov/pubs/sp/800/38/d/r1/2prd`; his comments at `https://emanjon.github.io/NIST-comments/2026%20SP%20800-38D.pdf`), and long random GCM nonces are hashed to 128 bits and add a `q²/2^min(r,128)` term to both bounds — a citation §4.4 lacked.
- The third reply did not engage with the question and is not recorded further.

The list archive is `https://mailarchive.ietf.org/arch/browse/cfrg/` (thread subject as posted, 2026-08-22/23). Consequence for this question: it now has **three** answers rather than two — cite the archival draft, drop the suite, or re-base `0xFF02` on RFC 8439 ChaCha20-Poly1305 with §5.3 as the nonce extension — and the third is the one `docs/issues/G07` now proposes. The position a reviewer is asked for is unchanged in kind: which of the three.

<a id="q7"></a>
### Q7 — Is the fresh envelope's novelty risk acceptable?

| | |
|---|---|
| **Read** | [ADR-0001](adr/0001-envelope-format-source.md) · [Appendix A](adr/0001-appendix-a-expressibility-mapping.md) (clause-level mapping) |
| **Time** | ~1–1.5 h — the longest card here |
| **Provisional status** | **Provisionally decided: option C.** Reversible, and the most expensive to reverse |

Three options: profile AWS's structured-encryption format, define fresh, or define fresh with AWS-aligned internal constructions. Appendix A's clause-level mapping found the strict profile fails — spec §6.3's dual-layer binding is not expressible in the AWS format, and per-cell embedding costs 1.4×–2.4× the fresh envelope at the §3.3 benchmark. On that evidence the project provisionally took option C.

The remaining question is the one Appendix A cannot answer: option C reduces the *novel surface* by borrowing AWS's commitment shape, Message-ID derivation and footer model — but "aligned" is weaker than "profiled," and the alignment claim needs to survive someone checking it.

**What closes it:** your read on whether the fresh framing's novel surface is acceptable given the review it is now receiving, and whether option C's construction-borrowing captures the risk reduction that actually matters. This is the highest-leverage question in the set.

<a id="q8"></a>
### Q8 — Which AEAD should the mandatory suite use?

| | |
|---|---|
| **Read** | [ADR-0002](adr/0002-suite-0x0001-aead.md), including its "Overhead evidence" section |
| **Time** | ~45 min |
| **Depends on** | [Q1](#q1) |
| **Provisional status** | **Deferred, not decided** — the status quo is retained so that arithmetic exists to build against |

AES-256-GCM + explicit commitment, versus AES-256-CBC-HMAC-SHA-512 (natively committing, but its FIPS story is a composition argument rather than a CAVP listing), versus AES-GCM-SIV (best misuse resistance, not FIPS-approvable).

The overhead argument is settled arithmetic and it did not decide anything: option B with the RFC 7518 truncated tag is actually *smaller* than A at the benchmark (115 vs 120 bytes). What remains is FIPS-validation reality and your answer to Q1.

**One sub-question the arithmetic surfaced:** spec §4.5 forbids tag truncation. Read literally that rules out B's RFC 7518-standard 32-byte truncated HMAC-SHA-512 tag; read per §4.5's own justification (a ≥128-bit floor aimed at short GCM tags) a 256-bit tag qualifies. Which reading is right?

**What closes it:** a recommendation with reasoning, plus a position on the §4.5 reading.

### Plus the standing sweep

Spec §14 lists every claim the authors flagged as contested, with the reason each is contested. Confirming or refuting an entry there is exactly as valuable as answering a numbered question, and considerably faster.

---

## 3. Ground rules

- **Where to respond.** GitHub issues on [`fieldseal-dev/fieldseal-spec`](https://github.com/fieldseal-dev/fieldseal-spec/issues), referencing the question number — public review is preferred. Email to the maintainer is fine if you would rather start privately.
- **No deadline.** Draft 1 of this brief asked for a 4-week window. That was a mistake: it added pressure without adding speed, and a partial answer whenever it arrives is worth more than a complete one that never comes. Answer one question, or eight, or none, on whatever schedule you have.
- **What happens to objections.** Each is recorded and either addressed with a spec change (issue → citation → breakage statement → vectors, per `CONTRIBUTING.md`) or documented as an accepted open risk. The gate is *addressed or documented* — you do not need to be agreed with for it to close honestly. `docs/06-verification-log.md` is the precedent: it exists because 20 of this project's own claims were re-checked, 7 were wrong, and it says so in a table.
- **Everything is public, no NDA.** Specification and docs are CC BY 4.0; test vectors CC0 1.0 (`LICENSES.md`).
- **Credit.** Reviewers are named in the spec's acknowledgments with permission. Anonymous review is equally welcome.
- **Compensation: none.** This is an unfunded open-source request, stated plainly so you can decline on that basis alone. What is offered instead: a scope compressed to hours by the card format above, a design that pre-flagged its own contested claims (spec §14) before asking for your time, and a gate that your answer actually controls.

---

## 4. Outreach log

Kept in the open so that "we could not find reviewers" is a claim with evidence behind it, and so that nobody is asked twice by accident. Appended to rather than rewritten.

| Date | Venue or person | Question(s) put | Outcome |
|---|---|---|---|
| 2026-08-22 | IRTF CFRG list (`cfrg@irtf.org`) | [Q6](#q6) | **Answered 2026-08-23** — three replies; two substantive (Madden; Preuß Mattsson), recorded under [Q6](#q6) and in `issues/G07`. Not a review. **Replied 2026-08-23** (to the list): confirmed the recommended `K' = KDF(K, E)` shape is already §5.3, stated the option-3 re-base as the current proposal, adopted the hardness-assumption wording, and posed the narrowed question — under a single-use derived key, does HChaCha20's extension have any advantage over RFC 8439 ChaCha20-Poly1305 with a random 96-bit nonce, and is the retained random nonce redundant or harmless. Awaiting response |
| 2026-08-22 | Paragon Initiative (`security@paragonie.com`), for Scott Arciszewski | [Q3](#q3), [Q6](#q6) | **Sent.** Awaiting response. Chosen because one person authored both the CipherSweet blind-index construction Q3 diverges from and the expired `draft-irtf-cfrg-xchacha` behind Q6 |

Channels this brief is written to be usable in, roughly in order of expected yield:

1. **Construction authors, asked about their own construction.** Not "review our spec" but "does our use match your intent" — a question people answer. [Q3](#q3) is close to CipherSweet's pattern; [Q6](#q6) is a call libsodium and PASETO have already made; [Q7](#q7) is answerable in part by the AWS ESDK team, whom PRD §9 already lists engaging as a risk mitigation.
2. **IRTF CFRG.** [Q6](#q6) is squarely in CFRG's jurisdiction — an expired CFRG draft is the reason the question exists. A list post is a legitimate question on its own merits and puts the spec in front of the right readers without asking anyone for a favor.
3. **Applied-crypto academics.** Public acknowledgment is worth considerably more to a PhD student or postdoc than to a principal engineer at a vendor. The groups whose papers this spec already cites are the natural first ask — including the authors of the MongoDB QE analysis the threat model leans on (spec §2.3).
4. **Crypto Stack Exchange**, for [Q4](#q4) specifically. It is a self-contained encoding-injectivity question and needs no project context.
5. **Funded review.** OSTIF brokers audits for open-source projects at no cost to the project; their track record is implementations rather than specifications, so whether they would scope this needs checking before it is counted on. Failing that, a scoped spec review from a boutique firm turns this from a recruitment problem into a budget decision.

---

## 5. One honest paragraph before you accept

This specification was written by generalist engineers from the primary literature, and it says so wherever it matters. The two things most likely to be wrong are the two you are being asked hardest about: the per-write-key argument for GCM in a hostile-nonce environment ([Q1](#q1)), and a blind-index leakage stance built on AWS's engineering heuristics rather than peer-reviewed bounds — which spec §7.4 flags itself. The project's position is that a design this security-sensitive should not exist without exactly this review, and that has not changed now that implementation has started ahead of it: the freeze is still gated, and the provisional-suite machinery of spec §4.8 exists specifically so that "the reviewers said no" remains an affordable outcome. If your conclusion is *do not ship this*, that is a successful review, and this repository's history shows unfavorable findings get recorded rather than buried.
