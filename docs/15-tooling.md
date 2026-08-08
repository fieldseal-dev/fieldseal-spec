# Operational Tooling Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** engineering design for `tools/backfill` and `tools/leakage-estimator`. The backfill tool is PRD requirement AD-6; the leakage estimator has no PRD requirement ID — it traces to spec §7.4's "Implementations SHOULD ship a tool that measures actual distribution skew" and the blind-index risk mitigation in PRD §9. This document exists now because their requirements constrain the core and adapters (resumability hooks, metrics, read modes), and those constraints must be known in Phase 1.

---

## 1. Backfill / re-encryption tool (`tools/backfill`)

One tool, two jobs with the same mechanics: **initial encryption backfill** (plaintext → ciphertext, the `docs/04` §11 five-step dual-write procedure) and **re-encryption sweep** (rotate under a new key/suite — spec §5.8's "full background re-encryption," the only mechanism permitting old-key destruction and therefore *the* crypto-agility mechanism per §5.9).

### 1.1 Requirements (from spec §5.8, PRD CL-8/AD-6)

Resumable · rate-limited · idempotent — each is a design constraint, not a feature flag:

| Property | Design |
|---|---|
| **Resumable** | Progress state in a `fieldseal_backfill_runs` table in the *target* database (run id, table, cursor value, counts, config hash). Keyset cursor over an immutable, indexed, monotonic column (PK or created-at + PK tiebreak). Restart resumes from the persisted cursor; no OFFSET pagination ever |
| **Idempotent** | Re-processing a row is safe by construction: initial backfill skips rows where `is_ciphertext(col_ct)` is already true; rotation sweeps skip envelopes whose header `key_id`/`suite_id` already match the target (header parse only — no decrypt needed to skip, which is most of a resumed run's work) |
| **Rate-limited** | Token-bucket on rows/sec and on batches in-flight (1 for v0 — serial batches); configurable batch size; adaptive backoff on DB error and on replication-lag signal where available (`pg_stat_replication` lag query for Postgres) **[flag: lag-source per database; v0 ships Postgres, others documented as manual-throttle]** |
| **Safe writes** | Batches go through the **encrypting path of the host language's data layer or the core directly** — never `UPDATE … SET col_ct = col` SQL. Verified-good paths per `docs/04` §11: Django `bulk_update`; SQLAlchemy `session.execute(update(User), [dicts])`. The Prisma path — per-row/`updateMany` through the extension — is *proposed*, not verified by `docs/04` (which only records that `prisma-field-encryption` ships a cursor-based generator); it carries a **[VERIFY]** in `docs/13` §6 and must be confirmed during WS-F. Each batch wrapped in a short transaction; long transactions are the classic backfill outage cause |
| **Verifiable** | A `verify` subcommand samples N rows per table, decrypts, and (for initial backfill during dual-write) compares against the legacy plaintext column; emits a report. Cutover to `strict` mode is gated on verify + the plaintext-read metric at zero (procedure step 4, `docs/04` §11) |

### 1.2 Shape

Phase 1 ships two thin frontends over one documented procedure, not a universal binary: a Django management command (`manage.py fieldseal_backfill`) using the Python core, and a Node CLI (`@fieldseal/backfill`) for Prisma projects using the TypeScript core — precedent being the only two shipped backfill tools in any surveyed library (Rails `db:encrypt:all`, `prisma-field-encryption`'s generator; `docs/04` §11). A shared `PROCEDURE.md` defines the state-table schema and cursor semantics so both frontends (and future Java/Go ones) are operationally identical.

### 1.3 Honesty requirements (must appear in tool output, not only docs)

- On first run against a populated table, print the crypto-shredding caveat verbatim: retrofit **permanently voids crypto-shredding claims for pre-existing backups** (NIST SP 800-88r2 §3.2.2 precondition; `docs/04` §11). Require `--acknowledge-preexisting-backups` to proceed.
- On rotation runs configured lazy/on-read anywhere: restate spec §5.8 — lazy convergence never completes for cold data and never permits old-key destruction on its own.
- Final report includes measured rows/sec and wall-clock, feeding PRD DO-5's migration cost model (measured, not estimated).

## 2. Leakage estimator (`tools/leakage-estimator`)

The tool spec §7.4 says implementations SHOULD ship: AWS's beacon-length band is an engineering heuristic that AWS itself hedges on ("the more unevenly distributed your dataset, the less effective beacon length is"), so the honest offer is *measurement of the operator's actual data*, pre-commitment, before §7.8 immutability makes the choice permanent.

### 2.1 Function

Input: read-only access to a plaintext column (pre-migration — the intended moment of use) or a plaintext export; a candidate truncation length `b` (or a range); optional declared `projected_population`.

Computed, all offline, nothing persisted, no values in the report (frequencies and hashes only):

1. **Distribution profile:** distinct count vs. declared `P`; top-k frequency mass; Shannon entropy vs. uniform; a skew classification (the §7.6 gate's "heavily skewed" needs a measurable definition — proposal: top-1 frequency > 1% of rows or top-10 mass > 10%, **flagged as a proposal** to be calibrated against real datasets and folded back into spec guidance).
2. **Collision simulation per candidate `b`:** bucket the real values through a keyed hash + truncation (throwaway key — this is simulation, not index construction), report actual collisions-per-value distribution against the AWS-band prediction `P × 2^(−b)`, and the actual "given a bucket, how identifying is it" distribution — the number the band only estimates.
3. **Verdicts:** `REFUSE` (under the §7.6 cardinality floor or skew-classified — mirrors the core's default-deny gate), `CAUTION` (band satisfied but skew makes tail buckets identifying; show the worst buckets by frequency rank, not value), `OK` (with the chosen `b` and measured expected over-fetch factor for §7.5 planning).
4. **Correlation check (v1.1):** given two candidate indexed columns, estimate pairwise identification lift, mechanizing the §7.7 correlated-columns prohibition. **[Deferred — metric choice (e.g. normalized mutual information) needs design; do not ship a half-calibrated number.]**

### 2.2 Shape

Python CLI in `tools/leakage-estimator` (imports nothing from `fieldseal` — it must be runnable before any encryption exists), DB access via SQLAlchemy-core read-only connection or CSV input, report as Markdown + JSON. The JSON report's `b`, `P`, and verdict fields are shaped to paste directly into an `IndexDeclaration` (docs/09 §7), closing the loop: spec §7.4 requires recording both; the tool is where the recorded numbers should come from.

### 2.3 Honesty requirements

The report header restates: the band is an AWS engineering heuristic, not a peer-reviewed leakage bound (spec §14.6); passing this tool is a *measurement against known attacks' preconditions*, not a proof of safety; and blind-index leakage is cumulative with query-log exposure (spec §2.3). The tool must never print plaintext values in any output mode — worst-bucket reporting is by rank and count only.

## 3. Shared constraints on core/adapters (why this doc exists in Phase 1)

- Core: envelope **header parse without decrypt** must be a public-enough API for the backfill skip-check (docs/09 §4 already provides `EnvelopeHeader`; keep it exported).
- Core: `readonly` mode is what `verify` runs under; `permissive` metrics must be countable per-table for the cutover gate.
- Adapters: each documents its backfill write path in its coverage matrix (`docs/12` §7 for Django, verified; `docs/13` §6 for Prisma, proposed with a [VERIFY] flag).
- The state-table schema in `PROCEDURE.md` is versioned from day one; Phase 2 languages implement against it unchanged.
