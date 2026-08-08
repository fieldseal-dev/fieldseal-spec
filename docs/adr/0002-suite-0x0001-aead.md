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
2. **Per-field overhead honesty** — redo the §3.3 arithmetic for the winner; B costs 20–36 B more per field than A *before* noting that B drops the 32 B commitment, which narrows the real gap; publish the corrected table either way.
3. **Reviewer acceptance of the per-write-key mitigation** — A's nonce-misuse catastrophe is mitigated by structure (`msg_seed`); at least one Phase 0 cryptographic reviewer must explicitly endorse that this mitigation is sufficient for a database setting (UPDATE-heavy, backup-restore-prone). If reviewers balk, B's misuse profile becomes decisive.
4. **CNSA 2.0 / FIPS 140-3 timeline fit** — verify the winner is assertable under the certificates that will be current at v1.0 (all FIPS 140-2 certs go Historical 2026-09-22; compliance mapping §6).

## Evidence needed to close

- Cryptographic reviewer positions (Phase 0 exit-gate reviewers; add to their brief).
- A lab conversation for option B's composition-validation claim (spec §13.2 instructs exactly this).
- The corrected overhead table per option (engineering, can be produced now).
- Confirmation of SP 800-38D revision trajectory relevance (spec §14.4 — second pre-draft comment period closed 2026-07-31; check whether the revision text changes GCM guidance material to this choice).

## Decision

*(open)*
