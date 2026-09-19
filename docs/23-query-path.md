# The Equality Query — finding a row by an encrypted value

**Date:** 2026-09-19 · **Status:** Draft 1 · **Purpose:** a picture of what the specification requires to happen when an application looks a row up by the value of an encrypted field — `Patient.objects.filter(ssn=…)` — drawn from the Python core and the Django adapter as they stand at 0.1.3. It is a reading aid for the specification, not a part of it. Its companions are [the write path](21-write-path.md) and [the read path](22-read-path.md).

**This document is informative.** Every step below cites the section of [`docs/02-spec-v0.1.md`](02-spec-v0.1.md) that requires it. **Where this document and the specification disagree, the specification is right and this one is wrong.** The specification has not been independently reviewed, every registered suite is provisional (§4.8), and nothing here is an invitation to adopt it. For what searching costs in plain terms, see [`docs/19-what-encrypted-search-costs.md`](19-what-encrypted-search-costs.md).

![Sequence diagram: the Django app filters on the encrypted field; fieldseal_django asks the core for the query value's blind index, which the core derives under the index key; the adapter selects the rows whose index matches, receives one bucket of candidates, has each decrypted and normalized by the core, and returns only the rows that match.](figures/query-path.svg)

[Open the diagram at full size.](figures/query-path.svg)

---

## 1. The steps

The ciphertext is randomized — the same value never encrypts to the same bytes twice — so the database cannot compare it with anything. Equality goes through the blind index instead, and the blind index can only narrow the search, never settle it.

### Index the query — `EncryptedExact`

1. **The lookup is rewritten.** `filter(ssn=…)` on an encrypted field compiles onto its index column. `in` works the same way; `filter(ssn=None)` becomes `IS NULL`, which is exact — a NULL value is stored as NULL, never as an envelope — and needs none of what follows.
2. **The query value is indexed like a stored one.** The core derives the blind index of the query value exactly as the write path did: the tenant index key, never the DEK ([§5.2](02-spec-v0.1.md#52-tenant-dek-granularity-normative), [§7.2](02-spec-v0.1.md#72-construction-normative)), the column's normalizer, its index function and its truncation ([§7.3](02-spec-v0.1.md#73-index-derivation-function-selection-normative), [§7.4](02-spec-v0.1.md#74-truncation-length-normative)). For an enumerable domain the index function is Argon2id, roughly 10–100 ms per query term — a ceiling on query rate, not a tuning detail. A value the normalizer refuses is a validation error, never an empty result — unless the column declares a bucket for such values, which is then searched like any other.

### Fetch candidates

3. **The database matches index values, and only index values.** Equality and membership are the only lookups a blind index supports ([§7.1](02-spec-v0.1.md#71-purpose-and-hard-limits-normative)).
4. **What comes back is a bucket, not an answer.** The index is truncated on purpose so that unrelated values collide ([§7.4](02-spec-v0.1.md#74-truncation-length-normative)); that is what keeps an index value from identifying a plaintext. The rows returned are a superset of the rows asked for — a small multiple of them, by the truncation rule.

### Re-verify — `_fetch_all`

5. **Every candidate is decrypted and compared.** Each row goes through [the read path](22-read-path.md), and its plaintext is normalized under the index's own normalizer and compared with the normalized query value ([§7.5](02-spec-v0.1.md#75-application-side-re-verification-normative)). On a column that folds case, a row stored as `Ada@Example.com` matches a query for `ada@example.com`, because the index already treated them as one.
6. **Only matches are returned.** Rows that merely shared a bucket are dropped before Django hands anything to the application. This is the default; `.candidates()` opts out explicitly and hands the obligation to the caller.

## 2. What the diagram leaves out

- **Methods that answer from SQL.** Re-verification happens after the database has already applied `COUNT`, `LIMIT` and `OFFSET`. So `count()` materializes and verifies rather than counting the bucket, and `get()` fetches the whole bucket rather than Django's first 21 rows, where the true match might not be.
- **What is refused.** An encrypted term inside `exclude()`, a negated `Q` or an XOR is refused: a superset can be narrowed to the answer, but an exclusion computed on a superset cannot be widened back ([§10.2](02-spec-v0.1.md#102-mandatory-adapter-carve-outs-normative)). So are ordering, `DISTINCT`, grouping and aggregates over the envelope — except a plain `Count`, which only counts NULLs — and every lookup no blind index can answer: substrings, ranges, date parts, case-insensitive matching outside the normalizer ([§7.10](02-spec-v0.1.md#710-honest-statement-of-what-is-not-supported-normative)). The adapter raises instead of returning a wrong or empty result.
- **Which columns may be indexed at all.** Low-cardinality columns are refused an index by default ([§7.6](02-spec-v0.1.md#76-default-deny-cardinality-gate-normative)); a hot value in a skewed column is the case that makes a bucket large.

## 3. How the figure is made

As for [the write path](21-write-path.md#3-how-the-figure-is-made): drawn with [Archify](https://github.com/tt-a1i/archify) from [`figures/query-path.sequence.json`](figures/query-path.sequence.json), extracted to a static SVG by [`tools/figures/svg_from_archify.py`](../tools/figures/svg_from_archify.py). Commands are in [`tools/figures/README.md`](../tools/figures/README.md). Do not edit the SVG by hand.
