# G13 — §10.2/§7.10: Prisma's `in:` — unconditional MUST-reject vs supported membership rewrite

**Labels:** §10.2 · §7.10 · spec-gap
**Blocks:** the Prisma adapter's conformance claim wording (docs/13 §4); no vectors.

## Gap

Spec §10.2's Prisma bullet requires rejection unconditionally: `where.field.in: [...]` (with `contains:` and `startsWith:`) "MUST reject … over encrypted fields." But §7.10's support table says membership is **supported**: "Membership (`IN`) | Yes — N indexes OR'd." For an adapter that *can* correctly rewrite `in: [v1, v2]` to `bidx: { in: [blind_index(v1), blind_index(v2)] }` with §7.5 re-verification — which the docs/13 schema-driven visitor can — the two clauses give contradictory instructions. `contains:`/`startsWith:` are not affected (§7.1 genuinely forbids them, except §7.9 prefix indexes).

## Proposed direction (starting point, not a decision)

Scope §10.2's MUST to the failure mode it was written against. Proposed wording:

> An adapter MUST reject `in:` over an encrypted field **unless** it rewrites the predicate to the declared blind index as §7.10 membership (N index values, OR'd/`IN`), subject to §7.5 re-verification. An adapter that cannot guarantee the rewrite (no declared index, or a filter path its interception surface does not cover) MUST reject rather than pass the shape through.

Rationale for the original MUST, preserved: the surveyed failure was path-surgery implementations *encrypting the filter values* and silently returning zero rows. The MUST should target "never silently mis-serve the query," not "never serve it correctly."

## Justification

§7.10 is the honest-capability table the rest of the spec defers to for what blind indexes support; membership is listed as supported with no adapter carve-out. The contradiction is internal; the adapter analysis it traces to is `docs/04-orm-adapter-notes.md` §3 (the `prisma-field-encryption` failure catalog), which documents the mis-encryption failure mode — not an impossibility of correct rewriting.

## What it breaks

Conformance wording only. Until this closes, docs/13 §4 flags its `in:` rewrite as a documented deviation from §10.2's letter, claimed under §7.10's semantics.

## Vector obligations

None at the vector-suite level (adapter behavior, not core). The docs/13 test plan already carries the adapter-level obligations: the rewrite test, the no-index throw test, and the collision re-verification test.

## Review flag

None — conformance-language consistency, not cryptography.
