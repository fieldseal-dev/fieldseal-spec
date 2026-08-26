# G19 — §7.5: re-verification says "compare the actual values" without saying under what equality, and on a normalized column the two readings return different rows

**Labels:** §7.5 · §7.2 · §7.1 · docs/09 §7, §7.2 · docs/12 §3.2, §3.3 · docs/13 · spec-gap
**Blocks:** Django L2 and Prisma L2 — the adapter cannot implement §7.5 without choosing, and the choice is user-visible in the result set. No stored byte, no derived value, no vector in any family.
**Found:** 2026-08-26, implementing `docs/12` §3.2's re-verification filter for the Django adapter's L2 path.

**Status:** OPEN — tracker [#78](https://github.com/fieldseal-dev/fieldseal-spec/issues/78), posted 2026-08-26.

## Gap

Spec §7.5 is three sentences, and the operative one is:

> After retrieving candidate rows by index, the implementation MUST decrypt and compare **the actual values** before returning results to the caller.

`normalize` is declared per column (§7.2) and is applied to derive the index. **§7.5 does not say whether the comparison is against the plaintext or against its normalization**, and on any column declaring `nfc-casefold-v1` the two answers return different rows.

Concretely, a column declaring `nfc-casefold-v1`, holding a row whose stored plaintext is `Ada@Example.com`, queried as `filter(email="ada@example.com")`:

| Reading | Index lookup | Verification | Result |
|---|---|---|---|
| **A — byte-exact** | hits (both fold to the same value) | `b"Ada@Example.com" != b"ada@example.com"` | **0 rows** |
| **B — normalized-equal** | hits | `normalize(stored) == normalize(queried)` | **1 row** |

Both are defensible readings of "the actual values". Only one can be right, and an adapter cannot ship §7.5 without picking.

### Two project documents already point in opposite directions

**`docs/12` §3.3 implies B.** It refuses `iexact` on an encrypted column with the parenthetical rationale:

> `iexact` (case folding belongs to the normalizer, not the query)

That sentence only makes sense under B. It tells a user who wants caseless matching to declare a caseless normalizer instead of asking for `iexact` — which is a promise that `exact` on such a column *is* the caseless query. Under A the user gets neither: `iexact` is refused, and `exact` is case-sensitive, so **the caseless lookup the normalizer exists to enable is unreachable from the ORM**.

**`docs/09` §7.2 reads as A**, in the sentence that closes G16's bucket design:

> a query for an unindexable value derives the marker, matches the bucketed rows, and spec §7.5 re-verification […] decrypts the candidates and keeps **the ones that actually match**.

That reasoning works under either reading for the bucket case specifically — an unindexable value's stored plaintext and queried plaintext are the same string — so it does not decide the question, but its phrasing assumes a plaintext comparison without qualification.

### Under reading A, declaring a folding normalizer is close to strictly harmful

This is the argument that makes the gap more than a wording nit. Under A, `nfc-casefold-v1` on a column:

- **enlarges the candidate set** — every case variant of every value now collides into one bucket, so §7.5 decrypts more rows per query;
- **buys no query capability** — every extra candidate it surfaces is then discarded by the byte comparison;
- **leaks slightly more** — a bucket that merges case variants is a coarser equivalence class than one that does not.

So under A a deployment is better off declaring `identity` on exactly the columns §7.3's domain classes point at `nfc-casefold-v1`. A normalizer that is worse than not declaring it, on the columns it was designed for, is a sign the reading is wrong rather than a cost to be documented.

**Reading A is not simply wrong, though**, and the counter-argument should be recorded rather than skipped: `exact` meaning *exact* is what the word says in every ORM, and B makes `filter(email=X)` return rows whose `email` is visibly not `X` when printed. That is surprising in a different direction, and it is surprising in a way the user cannot see from the query.

### A third case the wording does not reach at all

Even setting case aside, `nfc-casefold-v1` normalizes to NFC. Two byte-different, **canonically equivalent** spellings of the same string — precomposed `é` (U+00E9) versus `e` + U+0301 — fold to one index value and are, to every user and every rendering engine, the same text. Under A they do not match each other. There is no reading of "the actual values" under which that is a useful answer, and no ORM-level escape hatch for it: unlike case, Django has no `inormalized` lookup to refuse people towards.

## Proposed direction (starting point, not a decision)

**§7.5 states the equality it means, and it is the column's own.**

> Re-verification MUST compare `normalize(stored_plaintext)` against `normalize(queried_value)`, using the normalizer declared for the index that produced the candidates. The comparison is on the normalizer's output bytes.
>
> A consequence adapters MUST document: on a column whose normalizer is not `identity`, an equality lookup is equality **under that normalizer**, not byte equality of the plaintext. An adapter MUST NOT offer a separate case-insensitive lookup over such a column, because the column has only one equality.

Three reasons for B over A:

1. **It is the only reading under which `normalize` is a feature.** Under A the transformation costs candidates and leakage and returns nothing; §7.3's domain classes recommend `nfc-casefold-v1` for email-like text, which under A would be advice to make the column worse.
2. **It matches what an index *is* here.** §7.2 defines the index over `normalize(plaintext)`; the index's equivalence classes are normalization classes. Verification exists to remove the *collisions* truncation introduces (§7.4), not to reintroduce a distinction the normalizer deliberately erased. Under A, verification is doing two jobs and one of them is undoing §7.2.
3. **It is the only reading that handles canonical equivalence sanely**, which is not a preference question — NFC exists precisely so that canonically equivalent spellings compare equal.

**The cost is stated rather than mitigated away.** Under B, `filter(email="ada@example.com")` can return a row that renders as `Ada@Example.com`. That is correct and it will surprise someone. It is the same surprise a `utf8mb4_unicode_ci` column produces in MySQL, and the honest mitigation is documentation plus `identity` for columns that want byte equality — not a second lookup, which the rule above forbids for a specific reason: two equalities on one column means two ways to ask the same question with different answers, and the index can only serve one of them.

Recorded alternatives:

- **A — byte-exact, and document that `normalize` is an index-shaping tool only.** Rejected on reason 1: it makes the recommended normalizer harmful on the columns it is recommended for. Worth keeping on the record because `exact`-means-exact is a real expectation.
- **Make it per-column** (`verify: normalized | exact`). Rejected as the worst of both: it doubles the semantics an adapter must implement and test, and a column declared `nfc-casefold-v1 + verify=exact` is the harmful configuration above, now spelled out and blessed.
- **Refuse folding normalizers on indexed columns entirely.** Rejected: it removes the capability rather than defining it, and `digits-only-v1` — which has exactly the same question, since `555-0100` and `5550100` fold together — is not optional for phone-like columns.

**No `pinned_decisions` key.** This decides a rule about stored-value comparison that is identical in every core and every adapter; it is not a per-implementation choice. Unlike G17's buffer lifetime it is directly testable, and unlike G18's accessor it is testable *by a vector*, which is where it belongs — see below.

## Justification

- §7.2 makes `normalize` part of what the index **is**: `raw = IDF(index_key, normalize(plaintext))`. A verification step that compares un-normalized values is comparing under a different equality than the one the index implements, which is the definition of a filter and its check disagreeing.
- §7.1 restricts a blind index to equality and membership. "Equality" is the whole semantic surface of the feature and the specification does not define it.
- Unicode Standard Annex #15 defines canonical equivalence precisely so that canonically equivalent sequences are treated as identical; §7.2's own `nfc-casefold-v1` normalizes to NFC for that reason. A comparison that then distinguishes them contradicts the normalizer it just applied.
- Precedent: this is the same class as G16 part B — a choice left implicit that only becomes visible when an adapter has to write the code, where both options are defensible and silence produces divergence between adapters rather than a bug in either.

## What it breaks

Nothing stored, and no cryptographic behaviour. No envelope byte, no derived value, no index value, no error code, no registry entry, no `pinned_decisions` key. **Every blind index already written stays valid** — this decides what happens to candidates after they come back, not what is written.

- §7.5 gains the comparison rule and the adapter documentation obligation.
- `docs/09` §7 gains a cross-reference; §7.2's bucket paragraph gains the qualifier that keeps it accurate under the rule.
- `docs/12` §3.2 gains the rule for its `_fetch_all` filter, and §3.3's `iexact` refusal gains the reason it currently only implies.
- `docs/13` §3 gains the same for the Prisma extension.
- Cores are **unaffected**: neither exposes a comparison helper today, and re-verification is the adapter's step. If a core later ships one, it is bound by the same rule.

## Vector obligations

**Unlike G17 and G18, this one is expressible**, and it should be pinned rather than left to per-adapter tests, because two adapters resolving it differently is exactly the cross-implementation failure the suite exists to catch:

- `blind-index/` gains a vector asserting that a case-variant pair and a canonical-equivalence pair (`U+00E9` versus `e` + `U+0301`) under `nfc-casefold-v1` produce the **same** index value. The first is likely already implied by existing vectors; the second pins the NFC half explicitly.
- The comparison rule itself is an **adapter** obligation, so `docs/14` §4 is untouched and each adapter's coverage matrix carries a row naming the test that holds it.

## Review flag

**No cryptographic review required.** This defines an equality relation over already-decrypted plaintext, downstream of every cryptographic operation; it changes no key, nonce, derivation, encoding or stored byte, and it cannot make an index match more rows than it already matches — verification only ever removes candidates under either reading. Closable by engineering judgment under the rule that closed G3, G6, G8–G13 and G16–G18, and it has **no bearing on any Gate 0b question** (Q1–Q8 are untouched).
