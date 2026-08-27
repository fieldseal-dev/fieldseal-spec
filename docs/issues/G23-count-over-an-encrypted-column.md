# G23 — plain `COUNT` over an encrypted column: §10.2's aggregate clause refuses a shape that is exact, and the two adapters now disagree

**Labels:** §10.2 · §7.10 · docs/12 §3/§6 · docs/13 §4 · spec-gap
**Blocks:** No stored byte, no derived value, no vector in any family. A live behavioural divergence between the two shipped adapters: the Prisma adapter **serves** `_count: { field: true }` over an encrypted column (PR [#86](https://github.com/fieldseal-dev/fieldseal-spec/pull/86), merged 2026-08-27, with a test measuring exactness), while the Django adapter **refuses** `Count("email")` with a message claiming it "computes on envelope bytes" — which is false for this shape. Whichever way this resolves, one adapter changes.
**Found:** 2026-08-27, in the PR #86 review round (Reviewer 1 flagged the false justification on the Prisma side; Reviewer 4 ruled serve), recognized as a cross-adapter divergence against §10.2's letter after the merge.

**Status:** ✅ **CLOSED 2026-08-27** — resolved to **serve**, with the review panel's three adjustments (three tracker reviews, unanimous; the recorded consensus on [#89](https://github.com/fieldseal-dev/fieldseal-spec/issues/89) is what was ratified): §10.2's discriminator reworded to *reads envelope bytes*, a conditional permission plus a refusal-honesty prohibition, and the NULL-preservation invariant stated normatively — it was enforced and tested in both adapters and written down nowhere. §7.10 gains the non-null-count row; the Django adapter serves the bare shape with mirrored exactness tests; `COUNT(DISTINCT col)` stays refused everywhere. The divergence is ended: both shipped adapters serve. Closure record: `docs/07` §7 (2026-08-27 entry) and `docs/issues/README.md`.

## Gap

Spec §10.2's **All ORMs** bullet, added by G20 ([#80](https://github.com/fieldseal-dev/fieldseal-spec/issues/80)):

> ordering, grouping, `DISTINCT`, or aggregate/function expressions over a ciphertext column. […] an aggregate computes on bytes, and the failure can be *silent and plausible* — `MIN()` over a ciphertext column returns whichever envelope sorts first […] An adapter MUST throw where its interception surface reaches the shape

The justification — *an aggregate computes on bytes* — is true of `MIN`, `MAX`, `SUM`, `AVG`, and every function expression G20 measured, and **false of plain `COUNT(col)`**, which computes on null-ness alone: the database never reads the envelope, only whether the column is NULL. Under the invariant every conformant write path already keeps — NULL is stored as NULL and a value as an envelope, so a column is NULL exactly when the value is absent — `COUNT(col)` over envelopes equals `COUNT(col)` over the plaintexts, exactly, with no collision class and nothing for §7.5 to re-verify. It is the one member of the family with nothing to refuse.

The two adapters read the clause opposite ways:

- **Prisma** (`adapters/prisma`, PR #86): `_count` was split out of the refused aggregate set, with a runtime test asserting exact counts (`_count: { email: true, nickname: true }` over one NULL and two non-NULL rows returns 2 and 1). The README matrix carries the row and the reasoning.
- **Django** (`adapters/django`): `Count("email")` is refused inside the G20 family (`test_ordering.py::TestAggregates`, message asserting "envelope bytes"), and the docs/12 G20 table's own rationale column advises the workaround for exactly this shape: *"A non-null count is `filter(f__isnull=False).count()`"* — a `WHERE`-clause spelling of the same `COUNT`, served two lines away from where the direct spelling is refused.

`COUNT(DISTINCT col)` is different and is not part of this gap: a randomized suite makes every envelope distinct, so it counts **rows**, not values — a silent wrong answer squarely inside G20's family. It stays refused under every resolution of this issue. The line between the two is not "COUNT is special" but "which SQL reads envelope bytes": `COUNT(col)` reads none; `COUNT(DISTINCT col)` compares them.

## Proposed direction

Starting point for discussion, not a decision:

1. **§10.2's All-ORMs bullet gains the carve-out**: plain `COUNT(col)` (non-null count) over an encrypted column MAY be served, because it computes on null-ness rather than bytes and is exact under the NULL-preservation invariant, which the clause names; `COUNT(DISTINCT col)` remains in the refusal family with its reason stated (counts envelopes, i.e. rows).
2. **§7.10's table gains a row**: *Non-null count* → **Yes** (ciphertext column), with the invariant as the condition.
3. **docs/12's G20 table row splits** accordingly, and the Django adapter serves `Count(field)` while keeping `Count(field, distinct=True)` refused, with tests measuring exactness the way the Prisma adapter's do.
4. The refusal message for the shapes that stay refused stops claiming `COUNT` computes on bytes anywhere it still does.

If the issue resolves the other way — refuse uniformly for surface-simplicity — the Prisma adapter reverts `_count` to the refused set and its README row and test change; the Django adapter is already conformant to that reading.

## What breaks

Nothing stored, nothing derived, no envelope byte, no error code in spec §9. Adapter behaviour over query shapes only, plus the three document sites above. Same shape as G19/G20/G21: per-adapter tests carry the obligation.

## Vector obligations

None. The shape is not expressible in the vector families (no core operation is involved — the database computes the count), and per the G20 precedent, adapter query-shape behaviour is held by per-adapter tests rather than vectors.

## Cryptographic review

**No — no bearing on any Gate 0b question.** The decision concerns which SQL reads envelope bytes, which is answerable from SQL semantics and the NULL-preservation invariant; no construction, derivation, or stored byte changes.
