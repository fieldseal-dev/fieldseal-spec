# G20 — §10.2 names the ordering throw for one ORM only; ORDER BY, GROUP BY and DISTINCT over a ciphertext column return confidently wrong answers everywhere else

**Labels:** §10.2 · §7.10 · docs/12 §3, §5, §6 · docs/04 §1 · docs/13 §5 · spec-gap
**Blocks:** No stored byte, no derived value, no vector in any family. Django adapter correctness: the surface has shipped silent since L1 (#73) and through L2 (#79).
**Found:** 2026-08-26, in the PR #79 review round — the sweep asked "what does the database answer from bytes the adapter never showed it?" of every `LIMIT` path; this is the same question asked of `ORDER BY`, `GROUP BY` and `DISTINCT`, recorded then as a follow-up.

**Status:** CLOSED 2026-08-26, the day it was filed — tracker [#80](https://github.com/fieldseal-dev/fieldseal-spec/issues/80). Closed as filed plus one addition: aggregate and function expressions over a ciphertext column joined the refusal set after `aggregate(Min("age"))` over `{30, 40}` was measured returning `40` — the byte-wise minimum *envelope* decrypts cleanly to an arbitrary row's value, presented as the minimum, with nothing raised. See the closure note in `docs/issues/README.md` and the `docs/07` §7 log entry.

## Gap

The specification already answers this at the level of principle. §7.10's normative table:

> | Range, `<`, `>`, `ORDER BY` | **No** | A deliberately coarse plaintext bucket column […] |

and §10.2's general clause:

> Where a path is not intercepted and would silently write plaintext or silently return wrong results, the adapter **MUST throw**, not degrade silently.

But §10.2's *known-cases* list names the ordering throw for exactly one ORM, in one sentence written against one surveyed library's failure mode (deleting the clause with a `console.error`):

> **Prisma:** […] `orderBy` on an encrypted field MUST throw rather than being silently dropped.

No other ORM's ordering shape is named, and the general clause needs an interpretive step for ordering that it does not need for values: the *rows* are right, only the *arrangement* is meaningless. The two shipped adapter designs read that silence in opposite directions — `docs/13` §5 throws, citing "spec §10.2 names this case" (true only for Prisma), while `docs/12` says nothing and the Django adapter serves the shape silently.

**Measured against the shipped adapter** (Django 6.1, SQLite; four rows created in order `m@x.com, a@x.com, z@x.com, a@x.com`):

| Query | Returns | Correct answer |
|---|---|---|
| `.order_by("email")` | `z, a, a, m` — envelope-byte order, stable-looking, deterministic per row | `a, a, m, z` |
| `.values("email").annotate(n=Count("pk"))` | **4 groups, every `n=1` — two groups printing the identical key** `a@x.com` | 3 groups, one `n=2` |
| `.earliest("email")` | `z@x.com` | `a@x.com` |

The middle row is why this is a gap and not a documentation nit. `GROUP BY` over the ciphertext column returns wrong **numbers** — no reading of "wrong results" excuses it — and §7.10's table does not reach it: the `GROUP BY`/`DISTINCT` row says "Yes, with the caveat that it groups by index," which is about the **blind-index sibling**; grouping on the ciphertext column itself, which is what every ORM compiles from the natural spelling of the query, appears in no row. PostgreSQL's `DISTINCT ON (ciphertext)` fails the same way by the same mechanism — every randomized envelope is distinct, so it deduplicates nothing. (Stated from the construction; the verification above ran on SQLite, where Django refuses `distinct(*fields)` itself. On the ordering and grouping rows the wrong output was executed, not reasoned.)

Ordering also arrives through doors that never spell `order_by`: `earliest()`/`latest()` compile `add_ordering` directly; `Meta.ordering` and `Meta.get_latest_by` are declared once and applied to every query silently; the admin's sortable column headers emit `order_by` on click.

## Proposed direction (starting point, not a decision)

1. **§10.2's known-cases list gains an "All ORMs" bullet**; the Prisma sentence stays as the named instance:

   > **All ORMs:** ordering, grouping, or `DISTINCT` over a ciphertext column. `ORDER BY` sorts envelope bytes — a meaningless but stable-looking order; `GROUP BY` and `DISTINCT ON` treat every randomized envelope as distinct, returning wrong counts and deduplicating nothing. An adapter MUST throw where its interception surface reaches the shape, and MUST document the shapes it cannot reach (raw SQL is already documented as such for every ORM).

2. **§7.10's `GROUP BY`/`DISTINCT` row splits in two**: on the *index sibling* — Yes, with the existing collision caveat, unchanged; on the *ciphertext column* — **No**, honest fallback: materialize → decrypt → sort/group in application code, or the coarse plaintext bucket column the Range row already names.

3. **`docs/12` gains the Django design.** Refuse `order_by()`, `earliest()`/`latest()`, `distinct(*fields)` and `values(...).annotate(...)` grouping when they name an encrypted column — on **every** `FieldsealQuerySet`, obligations or none, since a meaningless order needs no filter to be wrong (the PR #79 refusals key on `_verifying`; these must not). A system check (suggest **E009**) for `Meta.ordering`/`Meta.get_latest_by` naming an encrypted column, and an admin-facing check beside W001 (suggest **W005**) for sortable changelist columns. `.candidates()` does **not** lift these: bucket semantics are a meaningful thing to accept for a filter; ciphertext order has no semantics to accept. Ordering by the index *sibling* stays available — deterministic, documented as meaningless, and occasionally useful as a stable tiebreaker (the L2 tests use it for exactly that).

4. **`docs/04` §1 records the interception honesty.** Django resolves ordering names to a plain `Col` with no field hook in the path (`find_ordering_name`), so the refusal is queryset-level plus checks — which means a *plain-manager* model ordering through a relation onto another model's encrypted column is not reachable, unlike the equality traversal, which PR #79 closed at the lookup layer. That residue is documented as a limitation in the same class as raw SQL, not silently owned.

## Justification

- §7.10 already rules `ORDER BY` out and §10.2 already contains both the rule and the exact sentence — for one ORM. This is the G13/G19 shape: a rule stated once where it is needed everywhere, with the divergence already shipped in project documents (`docs/13` §5 throws; `adapters/django` does not).
- The measured `GROUP BY` case is a §10.2 "confidently wrong answer" with no interpretive step: `COUNT` of 1 for every group where the truth is 2, under group keys that print identically.
- Project precedent: the PR #79 review round closed the same class for `LIMIT` — `get()`'s 21-candidate window, `qs[i]`, `earliest()`/`latest()` on verifying querysets. This issue extends the same audit question from `LIMIT` to `ORDER BY`/`GROUP BY`/`DISTINCT`, and from verifying querysets to all of them.

## What it breaks

Nothing stored and nothing cryptographic. No envelope byte, no derived value, no index value, no error code, no registry entry, no `pinned_decisions` key, no vector.

- §10.2 gains the All-ORMs bullet; §7.10's table splits one row.
- `docs/12` §3 gains the refusal design, §5 the two check ids, §6 the coverage rows.
- `docs/13` §5 is already conformant; it gains only the cross-reference to the generalized bullet.
- **Behavioral break by intent:** application code currently depending on `order_by()` over an encrypted column starts raising. What it was depending on was a random-but-stable arrangement, which is the failure mode this project exists to refuse.

## Vector obligations

None — adapter query-surface behavior, not byte-expressible, the same class as G18. Each adapter's coverage matrix carries rows naming the tests that hold the refusals; the zero-silent-failure regression list in `docs/13` §7 already carries the Prisma one.

## Review flag

**No cryptographic review required.** Everything here is downstream of decryption or refuses a query shape outright; it changes no key, nonce, derivation, encoding or stored byte, and it has no bearing on any Gate 0b question (Q1–Q8 untouched). Closable by engineering judgment under the rule that closed G3, G6, G8–G13 and G16–G18.
