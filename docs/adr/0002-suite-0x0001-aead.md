# ADR-0002: Which FIPS-approvable AEAD for suite 0x0001

**Status:** OPEN — blocks suite freeze, envelope arithmetic, commitment design (gap G1), and all vector expected values · **Date opened:** 2026-08-08 · **Spec refs:** §4.2, §4.6, §13.2 · **PRD refs:** §10 item 2 (a plain list — the PRD has no §10 subsections)

## Context

Suite `0x0001` is the mandatory suite (spec §4.2) and the one the primary user's auditors will ask about, so "FIPS-approvable" is a product requirement, not a preference. The registry currently names AES-256-GCM + explicit 32-byte commitment, flagged **[OPEN]** in the spec itself. The candidates and their trade-offs are tabulated in spec §13.2; this ADR adds the decision mechanics.

## Options (from spec §13.2)

| | Expansion | Committing | FIPS path | Nonce misuse |
|---|---|---|---|---|
| A. AES-256-GCM + explicit commitment (status quo) | 28 B + 32 B | via commitment (construction undefined — gap G1) | **CAVP-testable** | Catastrophic — mitigated structurally by per-write keys (§4.4/§5.3), which is a design argument reviewers must accept |
| B. AES-256-CBC-HMAC-SHA-512 | 49–64 B | **natively** (encrypt-then-MAC over everything) | Composition of approved primitives — a validation-strategy argument, **not** a CAVP algorithm listing; spec §13.2 says confirm with a lab before asserting to a buyer | Reveals prefix equality only |
| C. AES-256-GCM-SIV | 28 B | No (still needs commitment) | **Not** FIPS-approvable today (not in SP 800-38 series) | Graceful — best engineering answer, wrong compliance answer |

Interaction to keep explicit: choosing A makes closing **gap G1** (commitment construction) a prerequisite for vectors; choosing B dissolves G1 for 0x0001 (natively committing ⇒ `commit_len = 0` in the registry, which docs/09 §6 already represents) but re-raises it for 0x0002, which also needs a commitment. G1 must be solved for 0x0002 regardless — so B does not actually remove the design work, only its presence in the mandatory suite.

## Decision criteria

1. **A CAVP/lab-validated story an auditor accepts** — for B specifically, a testing lab's written opinion on the composition claim (spec §13.2's own caveat). Without it, B's main advantage is unsubstantiated.
2. **Per-field overhead honesty** — redo the §3.3 arithmetic for the winner; counting the 32 B commitment that B drops, B with the RFC 7518 32 B tag runs from 11 B *smaller* to 4 B *larger* per field than A depending on plaintext length mod 16 — 5 B smaller at the §3.3 SSN benchmark (115 vs 120 B) — and only the untruncated-64 B-tag variant costs more across the board (+21 to +36 B); the corrected table is published below ([Overhead evidence](#overhead-evidence-criterion-2)).
3. **Reviewer acceptance of the per-write-key mitigation** — A's nonce-misuse catastrophe is mitigated by structure (`msg_seed`); at least one Phase 0 cryptographic reviewer must explicitly endorse that this mitigation is sufficient for a database setting (UPDATE-heavy, backup-restore-prone). If reviewers balk, B's misuse profile becomes decisive.
4. **CNSA 2.0 / FIPS 140-3 timeline fit** — verify the winner is assertable under the certificates that will be current at v1.0 (all FIPS 140-2 certs go Historical 2026-09-22; compliance mapping §6).

## Evidence needed to close

- Cryptographic reviewer positions (Phase 0 exit-gate reviewers; add to their brief).
- A lab conversation for option B's composition-validation claim (spec §13.2 instructs exactly this).
- ~~The corrected overhead table per option (engineering, can be produced now)~~ — **delivered as [Overhead evidence (criterion 2)](#overhead-evidence-criterion-2) below (2026-08-08)**.
- Confirmation of SP 800-38D revision trajectory relevance (spec §14.4 — second pre-draft comment period closed 2026-07-31; check whether the revision text changes GCM guidance material to this choice).

## Overhead evidence (criterion 2)

*Added 2026-08-08. Redoes the spec §3.3 arithmetic for all three options. Construction parameters were verified against the primary sources cited per assumption below; everything else is the v0.1 envelope as specified.*

### Assumptions

- **Header is 51 B under every option** — `fmt_ver` 1 + `suite_id` 2 + `key_id` 16 + `msg_seed` 32 (spec §3.1). The per-write `msg_seed` is retained in all cases: for A it is the structural nonce-misuse mitigation this ADR's criterion 3 depends on, and no option proposes removing it.
- **Commitment: 32 B for A and C, 0 B for B.** Per this ADR's own interaction paragraph (Context, above): choosing B dissolves G1 for `0x0001` — natively committing ⇒ `commit_len = 0` in the registry. A and C both carry the explicit 32 B commitment required by spec §4.6 (AES-GCM-SIV is not key-committing; RFC 8452 provides no commitment).
- **Option B's shape per [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) (JWA, `A256CBC-HS512`):** 16 B IV (§5.2.2.1: "a 128-bit value generated randomly or pseudorandomly"); PKCS #7 padding per RFC 5652 §6.3 (RFC 7518 §5.2), so the ciphertext is the plaintext padded to a full 16-byte block — padding adds 1–16 B, never 0; authentication tag = the *first 32 octets* of the HMAC-SHA-512 output (§5.2.5: "truncated to T_LEN=32 octets"; leftmost-octet truncation per §5.2.2.1).
- **B's tag length is itself an undecided sub-choice.** RFC 7518 mandates the 32 B truncated tag; a Fieldseal suite could instead specify the untruncated 64 B HMAC-SHA-512 output. There is a genuine tension with spec §4.5 ("Tag truncation MUST NOT be supported"): read literally it forces the 64 B row; read per its own justification (a ≥128-bit floor aimed at short GCM tags) the 256-bit RFC 7518 tag qualifies. Undecided — both rows are given. (Spec §13.2's "49–64 B" expansion figure for B is the 32 B-tag case: 16 IV + 1–16 pad + 32 tag; with the 64 B tag it would read 81–96 B.)
- **Option C per [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452):** 12 B nonce (§6: N_MIN = N_MAX = 12), 16 B tag, no padding — "the result of the encryption is the encrypted plaintext (truncated to the length of the plaintext), followed by the tag" (§4), i.e. ciphertext = plaintext + 16 B, identical in shape to A.
- **Option A** is the status-quo arithmetic of spec §3.3 (12 B nonce + 16 B tag + 32 B commitment = 111 B fixed), reproduced unchanged.
- Binary column storage throughout; base64 adds one third on top of every figure (spec §3.3).

### Corrected table

| Option | Fixed-overhead formula | Fixed overhead | 9 B SSN total (§3.3 benchmark) | 16 B plaintext total (worst padding for B) | Overhead vs A |
|---|---|---|---|---|---|
| A. AES-256-GCM + 32 B commitment (status quo) | 51 hdr + 12 nonce + 16 tag + 32 commit | 111 B | **120 B** | 127 B | baseline |
| B. AES-256-CBC-HMAC-SHA-512, 32 B tag (RFC 7518) | 51 hdr + 16 IV + pad(1–16) + 32 tag | 100–115 B | **115 B** (pad = 7) | 131 B (pad = 16) | **−11 to +4 B** |
| B′. AES-256-CBC-HMAC-SHA-512, 64 B untruncated tag | 51 hdr + 16 IV + pad(1–16) + 64 tag | 132–147 B | **147 B** (pad = 7) | 163 B (pad = 16) | +21 to +36 B |
| C. AES-256-GCM-SIV + 32 B commitment | 51 hdr + 12 nonce + 16 tag + 32 commit | 111 B | **120 B** | 127 B | ±0 B |

### What the numbers force

1. **At the §3.3 benchmark, B with the RFC 7518 tag is *smaller* than A: 115 vs 120 B.** Dropping the 32 B commitment (−32) more than pays for the wider IV (+4 vs A's nonce) and the padding (+7 at 9 B plaintext). This contradicts the casual reading of §13.2's "more overhead" framing, and it contradicted this ADR's original criterion 2 sentence ("B costs 20–36 B more per field than A"), which compared the suites' expansions — 49–64 B vs 28 B — while leaving A's commitment out of the comparison; that sentence has been corrected in place above. The commitment-inclusive comparison: B-32 ranges from 11 B smaller (plaintext ≡ 15 mod 16) to 4 B larger (plaintext a multiple of 16) than A.
2. **B loses when padding lands badly, and always loses with the untruncated tag.** At plaintext lengths that are multiples of 16, PKCS #7 adds a full extra block and B-32 costs 4 B more than A (131 vs 127 B at 16 B plaintext). The 64 B-tag variant costs 21–36 B more than A at every length.
3. **None of this decides the ADR.** The deltas are single bytes to tens of bytes per field — small against the 111 B either committing construction already carries. Criterion 1 (a lab-validated story an auditor accepts) and criterion 3 (reviewer acceptance of the per-write-key mitigation) dominate the choice; this section only removes the incorrect overhead argument from the scales.

Spec follow-up when this ADR closes (do not apply now): §13.2's overhead phrasing ("at 20–36 bytes more per field") makes the same expansion-only comparison and should be corrected to the commitment-inclusive figures above.

## Decision

*(open)*
