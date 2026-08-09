# G12 — §7.10/§7.4: The unique-constraint row contradicts the mandated collision band

**Labels:** §7.10 · §7.4 · spec-gap
**Blocks:** adapter DDL guidance (docs/12 checks E002/E005, docs/13 schema shape); no vector expected values.

## Gap

§7.10's honest-support table says unique constraints are supported "**On the index column only** | Never on randomized ciphertext." But §7.4 *mandates collisions*: `2 ≤ P × 2^(−b)` means every index value is expected to correspond to at least two distinct plaintexts by design — that is the privacy mechanism. A UNIQUE constraint on a truncated blind-index column therefore rejects legitimate, distinct plaintext values whenever they collide at `b` bits, with probability approaching certainty as the table fills toward `P`. The two sections cannot both be followed: a database-enforced uniqueness guarantee on the index column is incompatible with an index construction that is required to be non-injective.

Found while writing the adapter specs: the Prisma example naturally reached for `@unique` on the sibling column (uniqueness of email is a real application requirement) and the design review caught that it would make legitimate inserts fail.

## Proposed direction (starting point, not a decision)

Change §7.10's row to:

| Operation | Supported | Honest fallback |
|---|---|---|
| Unique constraints | **No** — not on randomized ciphertext, and not on a truncated blind index (§7.4 mandates collisions) | Enforce uniqueness in application logic: index-filtered candidate fetch → decrypt → compare, inside a transaction with an appropriate isolation level or advisory lock. Document the race honestly: without database enforcement, uniqueness is best-effort under concurrency unless serialized. |

If a future revision wants database-enforced uniqueness over an encrypted column, that is the §13.6 deterministic-AEAD discussion (a deterministic suite's full-length index *is* injective per key) — it should not be smuggled in via §7.10.

## Justification

Internal consistency: §7.4's lower bound (`P × 2^(−b) ≥ 2`) is normative and deliberate — AWS's beacon-length guidance, §7.4's cited source, exists precisely to force ambiguity into the index. A constraint whose correctness requires injectivity cannot sit on a value whose construction forbids it. No external citation needed beyond what §7.4 already cites.

## What it breaks

Documentation and adapter DDL only; no envelope or index bytes change. Deployments that (hypothetically) built UNIQUE index columns would need a migration dropping the constraint — none exist.

## Vector obligations

None (no computable expected value changes). The adapter test suites gain the enforcement tests: docs/12's E002/E005 checks and docs/13's construction-time rejection of a unique sibling.

## Review flag

None — design consistency, not cryptography. (A reviewer glancing at the application-level fallback's race-condition honesty would be welcome.)
