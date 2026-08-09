# G4 — §6.2: `tenant_id = null` encoding in `canonical_context` is unspecified

**Labels:** §6.2 · spec-gap · blocks-vectors · needs-crypto-review
**Blocks:** the `context/` vector family; every envelope vector for a deployment without a tenancy value.

## Gap

§6.1 declares `tenant_id : bytes | null`, but §6.2's canonical encoding defines omission behavior only for `row_id` ("omitted entirely if null"). For `tenant_id` there are three candidate encodings — omit the field entirely, encode `u64be(0)` with an empty value, or forbid null — and the spec chooses none. Worse, "omitted entirely" as a general strategy creates an **aliasing question**: if optional fields can be silently absent, can a crafted set of present-field values serialize to the same byte string as a different context with a field omitted? The length-prefixing in §6.2 exists precisely to prevent cross-field-boundary forgery (its own justification cites RFC 7518 §5.2 and Tink); optional-field omission reopens a variant of the same problem at the field-*count* level.

This is not cosmetic: `canonical_context` is both the KDF `info` (§5.3) and part of the AAD (§6.3). Two implementations disagreeing on the null encoding derive different keys from identical inputs; an aliasing ambiguity is a forgery surface.

## Proposed direction (starting point, not a decision)

Make field presence explicit rather than positional-and-optional. Candidates for the issue discussion:

1. **Presence bitmap:** prefix `canonical_context` with one byte whose bits declare which optional fields follow. Unambiguous, cheap, but a format change to §6.2.
2. **Field count prefix:** prefix with `u8(count)`; fields keep a fixed order. Simpler, but does not say *which* fields are present unless order+count is injective (it is, for the current two optionals — fragile under future extension).
3. **Encode null as a distinguished length:** e.g., `u64be(0xFFFFFFFFFFFFFFFF)` for null vs `u64be(0)` for present-but-empty. No layout change, but overloads the length field.

Option 1 is proposed. Whatever is chosen, `tenant_id = null` and `tenant_id = b""` (present, zero-length) MUST encode differently or zero-length MUST be forbidden — the issue must pick one and say so.

## Justification

The same argument §6.2 already makes for length-prefixing: "Unlength-prefixed concatenation is forgeable across field boundaries" (spec §6.2, citing RFC 7518 §5.2 and Tink's AES-CTR-HMAC encoding). An encoding in which two distinct `FieldContext` values can produce one byte string violates the injectivity that canonical encodings exist to provide.

## What it breaks

Compatibility-breaking for every derived key and every AAD (all ciphertext, all indexes). Nothing exists yet. If option 1 or 2 is adopted, §6.2's layout changes and `row_id`'s existing "omitted entirely" rule is subsumed by the same mechanism — the issue must restate §6.2 in full, not patch it.

## Vector obligations

- `context/`: canonical encodings for — all fields present; `tenant_id` null; `row_id` null; both null; `tenant_id` zero-length (expected: distinct encoding or a defined rejection).
- Negative vectors: byte strings exhibiting the aliasing attempt (a present-field encoding equal to an omitted-field encoding) with the expected rejection/impossibility documented.
- `kdf/` vectors deriving keys from null-tenant contexts.

## Review flag

**Needs cryptographic review** — this is canonical-encoding injectivity, a known forgery surface; a reviewer should confirm the chosen encoding is injective over the full (including future-extended) field set.
