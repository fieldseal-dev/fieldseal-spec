# G5 — §9/§3.4/§6.3: Decrypt error classification order is undefined

**Labels:** §9 · §3.4 · §6.3 · spec-gap · blocks-vectors · needs-crypto-review (partly)
**Blocks:** most of `errors/crypto.json`; the precedence cases in `errors/format.json`.

## Gap

§9 enumerates the error taxonomy (UNKNOWN_FORMAT_VERSION, SUITE_NOT_ALLOWED, KEY_UNAVAILABLE, AAD_MISMATCH, TAG_INVALID, COMMITMENT_INVALID, NOT_CIPHERTEXT) but not the **order of checks**, so an input failing two checks at once (e.g., unknown format version *and* truncated) can legally produce different errors from different implementations — making negative vectors unwritable, since each must pin one expected error.

Two sub-problems need normative answers:

1. **Precedence.** The order structural-parse → suite-policy → key-acquisition → commitment → AEAD must be pinned. A proposed order exists in `docs/09-core-architecture.md` §3.2, including the §3.4-mandated decoupling (unregistered suite → NOT_CIPHERTEXT during recognition; registered-but-not-allowed → SUITE_NOT_ALLOWED after).
2. **The dual-binding ambiguity.** Under §6.3, a context mismatch produces a *wrong derived key*, so at decrypt time it is cryptographically indistinguishable from key confusion: both surface as "no candidate key's commitment verifies." §9 wants AAD_MISMATCH (usually a data-migration bug) distinguished from COMMITMENT_INVALID (possible partitioning-oracle attempt) — but at that point in the state machine the implementation cannot know which occurred. As written, §9's distinction is unimplementable in the case where both bindings fail together, and the spec should say so honestly.

Also folded in: whether UNKNOWN_FORMAT_VERSION is *raisable at all*, since a future `fmt_ver` need not keep `suite_id` at the same offset, making an unrecognized version structurally indistinguishable from non-ciphertext (docs/09 §3.2 footnote).

## Proposed direction (starting point, not a decision)

Adopt the docs/09 §3.2 state machine normatively:

- Structural parse failures → NOT_CIPHERTEXT (strict) / pass-through (permissive), except a **reserved-known-future** version byte with plausible length → UNKNOWN_FORMAT_VERSION.
- **Decrypt-side context assembly is part of the pinned machine:** the context's `suite_id` member MUST be taken from the parsed, allow-listed header — never from the client's write suite. Mixed-suite reads (§4.3/§5.6), re-encryption sweeps (§5.9), and `rotate` all require decrypting envelopes whose suite differs from the write suite; a write-suite-sourced context derives the wrong key for every one of them. Tampering is caught because `suite_id` is bound in both the KDF info and the AAD (§6.2).
- Registered suite not on allow-list → SUITE_NOT_ALLOWED (after recognition, honoring §3.4).
- No candidate keys → KEY_UNAVAILABLE.
- Per candidate: commitment verify (constant-time) → on success, AEAD open; AEAD failure with verified commitment → TAG_INVALID (key and context proven right; remaining cause is ciphertext/tag corruption).
- No candidate's commitment verifies → **COMMITMENT_INVALID**, with an optional *diagnostic* (never control-path) re-derivation under known-legitimate context variants to annotate "context mismatch suspected." AAD_MISMATCH is then reserved for suites/paths where AAD verification is separable from key verification, and §9 gains a sentence acknowledging the collapse under dual binding.

## Justification

§3.4 already mandates half the ordering ("Recognition MUST be independent of the decrypt allow-list") with a spelled-out failure story (double-encryption corruption). The operational reason to keep COMMITMENT_INVALID distinct is the partitioning-oracle detection story behind §4.6 (Len–Grubbs–Ristenpart, USENIX Security '21): a commitment failure is a signal an operator should be able to alert on separately from migration bugs. Vectors cannot exist without a pinned order — `CONTRIBUTING.md`'s vector rule applies to error semantics exactly as to positive paths.

## What it breaks

Error-code behavior only; no envelope bytes change. Implementations written against a different informal order would misreport — which is the point of pinning before any exist.

## Vector obligations

- `errors/format.json`: multi-defect inputs pinning precedence (truncated + unknown version; unknown version + unregistered suite; etc.).
- `errors/crypto.json`: wrong-key → COMMITMENT_INVALID; wrong-context (row_id altered) → the pinned code; verified-commitment + flipped ciphertext bit → TAG_INVALID; verified-commitment + flipped tag bit → TAG_INVALID.
- Vectors pin **codes only**, never diagnostic annotations.

## Review flag

**Partly.** The precedence itself is engineering; a reviewer should sign off on (a) the timing posture (early exit on commitment success; constant-time compares) and (b) that the diagnostic re-derivation cannot be abused as an oracle.
