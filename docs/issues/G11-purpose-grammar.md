# G11 — §6.1/§7.2: The `purpose` / `index-id` grammar is unconstrained

**Labels:** §6.1 · §7.2 · spec-gap
**Blocks:** `context/` negative vectors.

**Status:** RESOLVED in spec 2026-08-09, adopted as proposed — docs/02 §6.1 carries the ABNF (`index-id = 1*32( %x61-7A / %x30-39 / "-" )`), rejection is a declaration-time configuration error, and §7.2 echoes the constraint at the point the identifier enters the derivation. **Partial close, deliberately:** this settles the *grammar* only. G4 (issue #4) still owns whether `canonical_context` is injective over its whole field set — the absent-`tenant_id` encoding above all — and §6.1 says so in as many words rather than letting the grammar's closure imply the encoding is settled. The reviewer brief's Q4 bundles this issue into that question; that bundling stands, with the grammar now a fixed input to it rather than an open variable. Marker sweep: docs/08 §4.3 (four negative declarations: uppercase, non-ASCII, empty, 33-byte), docs/09 §7, docs/02 §12. Close tracker issue [#11](https://github.com/fieldseal-dev/fieldseal-spec/issues/11) when this lands, noting the G4 carve-out in the closing comment.

## Gap

§6.1 types `purpose` as `"encrypt" | "index:<index-id>"` but constrains `<index-id>` no further — charset, length, and case are open. Because `purpose` is a component of `canonical_context` (KDF info and AAD), unconstrained identifiers interact with G4's aliasing concern: an identifier containing bytes that resemble encoding structure widens the surface the injectivity argument must cover, and identifiers differing only by case or Unicode representation would silently derive different keys for what an operator believes is one index.

## Proposed direction (starting point, not a decision)

Constrain in §6.1 (and echo in §7.2):

```
purpose   = "encrypt" / ("index:" index-id)
index-id  = 1*32( %x61-7A / %x30-39 / "-" )   ; [a-z0-9-], 1–32 bytes, ASCII
```

- Exact-match, case-sensitive by specification, but uppercase is unrepresentable — removing the case-drift hazard rather than adjudicating it.
- Rejection is a configuration error at declaration time (fail closed), not a runtime error class.

## Justification

Restricting identifiers embedded in cryptographic derivation strings to a minimal ASCII alphabet is standard practice for exactly the ambiguity reasons above (cf. the fixed ASCII labels the spec already uses: `"fieldseal-index-v1"` §7.2). This narrows, and never widens, what G4's injectivity review must consider. Interop: 32 bytes of `[a-z0-9-]` is comfortably expressive for index naming (`exact`, `prefix3`, `email-domain`).

## What it breaks

Any hypothetical index declared with an out-of-grammar identifier (none exists). Additive constraint; identifiers already within the grammar are unaffected.

## Vector obligations

- `context/`: positive vectors with `purpose = "encrypt"` and `purpose = "index:exact"`; negative declarations — `index:Exact`, `index:é`, `index:` (empty), 33-byte identifier — each expected to be refused at declaration time (vector pins the refusal, not an error-code, since this is configuration validation).

## Review flag

None on its own; reviewed as part of G4's injectivity question.
