# G24 — the two bucket-semantics escape hatches disagree about negation, and each adapter's error message asserts its own answer

**Labels:** §10.2 · §7.10 · §7.5 · docs/12 §3.3 · docs/13 §2.2 · spec-gap
**Blocks:** No stored byte, no derived value, no vector in any family. One shipped adapter changes whichever way it resolves.
**Found:** 2026-08-31, closing G21 ([#87](https://github.com/fieldseal-dev/fieldseal-spec/issues/87)) — writing the §10.2 negation bullet required deciding whether the escape hatches lift it, and the two adapters already answer differently.

**Status:** OPEN — filed, not decided. Tracker [#100](https://github.com/fieldseal-dev/fieldseal-spec/issues/100). G21 closed without deciding this, and spec §10.2 says so explicitly rather than picking a side by omission.

## Gap

G21 settled that negated membership and negated equality over a blind index are refused: the exclusion is computed in the database over §7.4 buckets, so rows that belong in the answer never reach the client and §7.5 has nothing to put back.

Both adapters also offer a documented opt-out to bucket semantics — Django's `.candidates()`, Prisma's `candidateScope()` — under which §7.5 becomes the caller's responsibility. **They disagree about whether that opt-out reaches negation, and each one's error message states its own answer as though it were the rule.**

- **Django lifts it.** `adapters/django/src/fieldseal_django/query.py:_encrypted_predicates` returns `[]` immediately when `_fieldseal_verify` is false, so the negation refusal below it is never reached. `docs/12` §3.3 states this deliberately: "`.candidates()` lifts every refusal in that table — including the filter-time ones (`exclude`, `Q` under `OR`), since the SQL semantics they refuse are exactly what it hands over. An escape hatch that refuses the same things is not one." The refusal message itself ends: "…or use `.candidates()` and accept the semantics."
- **Prisma does not.** `adapters/prisma/src/visitor/reject.ts:388` throws unconditionally, outside the `verify` gate, and the message says so in as many words: "(G21, [#87]; `candidateScope()` does not lift it.)"

A caller who reads one adapter's error text and moves to the other gets the opposite behaviour, with no clause in the specification to appeal to.

## Why this is a real question and not a tidy-up

The argument is genuinely two-sided, which is why this is filed rather than decided.

**For Django's reading.** The hatch's contract is "I take §7.5 and I accept bucket semantics." For an exclusion, the bucket semantics are well defined — the whole bucket is excluded — and the caller asked for exactly that. A hatch that keeps refusing the shapes it exists to hand over is not a hatch, which is the sentence `docs/12` §3.3 already makes.

**For Prisma's reading.** §7.5 is a *filter* obligation, and handing it over transfers something the caller can actually discharge: decrypt the superset, drop the surplus. Negation transfers something they cannot. No operation on the returned rows restores a row the database removed, so the caller ends up holding a responsibility that is not dischargeable from what they were given. The recoverable/irrecoverable asymmetry that motivates the refusal in the first place does not disappear when the caller opts in — it is a property of the SQL, not of who is on the hook.

The sharpest form: under `filter().candidates()` the caller has *more* rows than the answer and can get to the answer. Under `exclude().candidates()` they have *fewer* and cannot. A caller can reconstruct by separately fetching the bucket positively and re-adding — but not from the exclusion's own result, and nothing in the API says so.

There is also an ergonomic asymmetry worth weighing: Django's refusal message *recommends* the hatch, so a caller following the error text lands on the irrecoverable semantics without being told they differ in kind from the filter case.

## Proposed directions (starting points, not a decision)

1. **Adopt Prisma's reading.** Neither hatch lifts negation. `_encrypted_predicates` gains a negation carve-out ahead of its early return, the Django message stops recommending `.candidates()` for this shape, and `docs/12` §3.3's "lifts every refusal" sentence gains its exception. Cost: removes a capability Django documents and has shipped since L2.
2. **Adopt Django's reading.** The hatch lifts everything it can express. Prisma's unconditional `notIn` refusal becomes scope-gated, and `docs/13` §2.2 and §4 change. Cost: a caller can obtain a silently short answer through an opt-in whose asymmetry nothing states.
3. **Split it.** The hatch lifts negation only through a distinct, separately-named opt-in, so the call site names what it costs rather than inheriting it from a hatch taken for a different reason. Cost: a third surface on a package that has kept its API small on purpose.

Directions 1 and 3 are the ones that survive the "what can the caller actually do with what they were handed" test; that is an observation, not a ruling.

## Justification

Spec §7.4 mandates collisions and §7.5 makes the index a filter and never an answer. G21 derived the refusal from those two clauses without any new citation. This issue asks whether an explicit caller opt-in changes the derivation — and neither clause mentions opt-outs, which is precisely the silence that let two adapters read it two ways.

## What it breaks

Nothing stored, nothing derived, no envelope, no index value. One adapter's query surface changes whichever way it goes. Django's is the surface at risk under direction 1; Prisma's under direction 2.

## Vector obligations

**None.** The rule is an adapter obligation over query shapes and already-decrypted plaintext, downstream of every cryptographic operation — the same shape as G19, G20, G21 and G23, which `docs/07` §7 records as held by per-adapter tests rather than by the suite. Per-adapter tests are the executable form.

## Review flag

**No cryptographic review**, and no bearing on any Gate 0b question. No construction, no derivation, no stored byte, no error code. It decides which query shapes an adapter's documented escape hatch may serve.
