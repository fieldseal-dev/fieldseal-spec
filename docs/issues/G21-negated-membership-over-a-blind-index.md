# G21 — `docs/13` §4 grants `notIn:` an index rewrite that §10.2's scoping and §7.10's table never granted

**Labels:** §10.2 · §7.10 · §7.5 · docs/13 §4 · docs/12 §3.3 · spec-gap
**Blocks:** No stored byte, no derived value, no vector in any family. Prisma adapter L2: `notIn:` is on the §4 table as rewritable, and the adapter shipped the opposite behaviour pending this issue.
**Found:** 2026-08-27, writing the Prisma adapter's throw list (WS-F PR1) against `docs/13` §4.

**Status:** OPEN — filed, not decided. The adapter currently **refuses** `notIn:` and `.not`, which is the conservative reading; if this issue resolves the other way that refusal is lifted, and if it resolves as filed the `docs/13` §4 row changes to match.

## Gap

`docs/13` §4's throw table lists, as one row:

> | `in:` / `notIn:` with **no declared index** | Not rewritable — throw. With a declared index this upgrades to a rewrite (below) |

and the note beneath it describes the rewrite as `emailBidx: { in: [bidx(v1), bidx(v2), …] }`, citing G13's scoping of §10.2 as the authority.

**G13 scoped `in:` only.** §10.2's Prisma bullet, as amended:

> An adapter MUST reject `in:` over an encrypted field **unless** it rewrites the predicate to the field's declared blind index as §7.10 membership (the N index values, `OR`'d or as a single `IN`), subject to §7.5 re-verification of the candidates.

`notIn` appears nowhere in that clause. And **§7.10's table has no row for negated membership** — it has `Membership (IN) | **Yes** — N indexes OR'd`, and nothing else. So `docs/13` extends a permission to a shape the specification has never addressed, on the strength of a citation that does not cover it.

## Why the extension is not merely unstated but wrong

The asymmetry is the one `docs/12`:107 already states for Django's `exclude()`, and it transfers verbatim:

> A filter's false positives are recoverable; an exclusion's false negatives are not.

Concretely. §7.4 *mandates* collisions: the band `2 ≤ P × 2^(−b) < √P` guarantees that an index value corresponds to at least two distinct plaintexts. A positive `in:` therefore returns a **superset** of the answer, and §7.5's re-verification pass removes the extras — the mechanism works because the surplus rows are *present* and can be inspected.

A negated `notIn:` inverts that. `WHERE emailBidx NOT IN (bidx(v1), …)` excludes **every row in those buckets**, including rows whose plaintext is not any of `v1…vN` and which belong in the result. Those rows are excluded by the database and never reach the adapter, so §7.5 has nothing to put back. The query silently drops correct rows, in proportion to the collision rate the spec deliberately requires.

The same argument covers Prisma's scalar `.not` and any `NOT`-wrapped equality over an encrypted column. `docs/13` §2.1 currently lists `.not` (scalar form) among the where-shapes the visitor *rewrites*, which has the same defect.

## Proposed direction (starting point, not a decision)

1. **§7.10 gains a row**: negated membership and negated equality over a blind index — **No**, with the honest fallback (fetch the matches by index with `in:`/equality, re-verify, and exclude their primary keys in application code, or over-fetch and filter after decryption).
2. **§10.2's Prisma bullet stays scoped to `in:`** and gains a sentence stating that the permission does not extend to `notIn:`, so the next adapter does not read the silence the way `docs/13` did.
3. **`docs/13` §4's row splits**: `in:` rewritable with a declared index; `notIn:` an unconditional rejection. §2.1's `.not` entry moves from the rewrite list to the rejection list.
4. Consider whether `docs/12` should say the same thing explicitly rather than only in Django's `exclude()` message, since the rule is not Django's.

## Justification

Spec §7.4 (truncation band, collisions mandated) and §7.5 (the index is a filter, never an answer; candidates MUST be decrypted and re-verified) together make the positive case sound and the negated case unsound, without any new citation. The Naveed–Kamara–Wright and AWS material §7.6 already cites is not needed here: this is an internal-consistency defect, not a leakage question.

## What it breaks

Nothing stored, nothing derived. It removes a capability `docs/13` promised and no adapter has shipped — the Prisma adapter refuses it today, and the Django adapter already refuses the analogue. If any implementation has built the rewrite, its results were wrong in proportion to `P × 2^(−b)`.

## Vector obligations

**None.** The rule is an adapter obligation over already-decrypted plaintext and query shapes, downstream of every cryptographic operation — the same shape as G19's comparison rule, which `docs/07` §7 records as held by per-adapter tests rather than by the suite. Per-adapter refusal tests are the executable form.

## Review flag

**No cryptographic review.** No construction, no derivation, no stored byte, no error code. It resolves an internal contradiction between `docs/13` §4 and §10.2/§7.10, and no Gate 0b question depends on it.
