# G8 — §7: The blind index's *stored* representation is undefined

**Labels:** §7 · spec-gap · blocks-vectors
**Blocks:** storage assertions in `blind-index/` vectors; adapter DDL in docs/12/13 (both carry an interim recommendation flagged as pending this issue).

## Gap

§7 fully defines how the index value is *computed* but never what is *written to the database*. Raw bytes vs hex vs base64, column type, and width are unstated. The central claim requires two implementations sharing one database to produce byte-identical stored values — a Python-written index a Node process cannot match on is a silent, total failure of L2 interop that no envelope vector would catch.

## Proposed direction (starting point, not a decision)

- Stored form = the raw truncated bytes, length exactly `ceil(b/8)` (G3's output), in a binary column (`BYTEA`/`VARBINARY(ceil(b/8))`/`BLOB`).
- For text-only storage paths, a per-column declared alternative: lowercase hex, no prefix. The choice is part of the index declaration and immutable after first write (§7.8 applies).
- Equality semantics: exact byte (or exact string, for hex) match — never a collation-sensitive comparison. Adapters MUST create the column with a binary/`C`-collation to prevent case-insensitive collations from matching differently than the core would.

This mirrors §3.3's rule for envelopes (binary MUST, base64 MAY with documented overhead) so the two storage stories are symmetric.

## Justification

Same interoperability argument as §3.3, applied to the index column; the collation point is standard SQL behavior (a case-insensitive collation over hex text would equate `AB` and `ab` — two values the core treats as distinct). No cryptographic content.

## What it breaks

Every stored index value's byte layout — frozen per column after first write (§7.8). Nothing exists yet.

## Vector obligations

- `blind-index/` vectors gain a `stored` field: exact bytes (and the hex alternative) an implementation must write, alongside the computed value.
- One cross-suite assertion: `cross/` scenarios that query by index must match on the stored form.

## Review flag

None.
