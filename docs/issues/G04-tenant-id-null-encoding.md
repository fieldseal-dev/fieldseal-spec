# G4 — §6.2: `tenant_id = null` encoding in `canonical_context` is unspecified

**Labels:** §6.2 · spec-gap · blocks-vectors · needs-crypto-review
**Blocks:** the `context/` vector family; every envelope vector for a deployment without a tenancy value.

**Status:** OPEN — tracker [#4](https://github.com/fieldseal-dev/fieldseal-spec/issues/4); the presence bitmap is provisionally adopted under Gate 0a (spec §6.2 carries `[PROVISIONAL — G4]`) and is what both cores and all pinned vectors implement. **Crypto Stack Exchange input received 2026-08-26 and 2026-08-28** — the injectivity argument confirmed as stated, the extension half answered conditionally with a static version byte recommended. See the options added below and `docs/16` [Q4](../16-reviewer-brief.md#q4).

## Gap

§6.1 declares `tenant_id : bytes | null`, but §6.2's canonical encoding defines omission behavior only for `row_id` ("omitted entirely if null"). For `tenant_id` there are three candidate encodings — omit the field entirely, encode `u64be(0)` with an empty value, or forbid null — and the spec chooses none. Worse, "omitted entirely" as a general strategy creates an **aliasing question**: if optional fields can be silently absent, can a crafted set of present-field values serialize to the same byte string as a different context with a field omitted? The length-prefixing in §6.2 exists precisely to prevent cross-field-boundary forgery (its own justification cites RFC 7518 §5.2 and Tink); optional-field omission reopens a variant of the same problem at the field-*count* level.

This is not cosmetic: `canonical_context` is both the KDF `info` (§5.3) and part of the AAD (§6.3). Two implementations disagreeing on the null encoding derive different keys from identical inputs; an aliasing ambiguity is a forgery surface.

## Proposed direction (starting point, not a decision)

Make field presence explicit rather than positional-and-optional. Candidates for the issue discussion:

1. **Presence bitmap:** prefix `canonical_context` with one byte whose bits declare which optional fields follow. Unambiguous, cheap, but a format change to §6.2.
2. **Field count prefix:** prefix with `u8(count)`; fields keep a fixed order. Simpler, but does not say *which* fields are present unless order+count is injective (it is, for the current two optionals — fragile under future extension).
3. **Encode null as a distinguished length:** e.g., `u64be(0xFFFFFFFFFFFFFFFF)` for null vs `u64be(0)` for present-but-empty. No layout change, but overloads the length field.

Option 1 is proposed. Whatever is chosen, `tenant_id = null` and `tenant_id = b""` (present, zero-length) MUST encode differently or zero-length MUST be forbidden — the issue must pick one and say so.

### The second half: injectivity *across versions*

Options 1–3 answer the null-encoding question, and option 1 is what §6.2 now carries provisionally. What the Gate 0a adoption did not settle is the extension half of the same question: whether "a new optional field takes the next free presence bit" is enough to keep the encoding injective across format versions, and what happens once bit 7 is consumed and a second presence byte would shift every field after it.

*Added 2026-08-28 from Crypto Stack Exchange ([q. 119892](https://crypto.stackexchange.com/questions/119892), answered by Maarten Bodewes; full record in `docs/16` Q4).* Put the encode-only form of the question directly — there is no decoder, ever; the bytes only feed a KDF and an AEAD's AAD and are recomputed on both ends — the reply was: "I would strongly advice a single byte version in there, so that this kind of thing doesn't even come up. However, you could argue that the absence of a field is enough for you. But this is kind of the same thing as assigning meaning to a `null` value, if you know what I mean. Cryptographically it can be secure if semantically it means the same thing, basically." No counterexample was produced in either round. The recommendation is hygiene — its stated benefit is that it "lets you skip that discussion" — not a repair of a demonstrated flaw.

4. **A static version byte in `canonical_context`** — `u8(ctx_enc_ver) ‖ u8(presence) ‖ …`. This splits into two options that are routinely conflated and do not buy the same thing:

   - **4a — encoder-pinned.** The value is the version the *running implementation* encodes at. This separates versions unconditionally, and for exactly that reason a v2 reader can never reproduce v1 bytes — which is the same statement as "a v2 reader cannot read v1 data." That is a migration policy (a format bump requires re-encrypting everything), not an encoding fix, and it contradicts §3.4, which builds `permissive` mode for mixed-version deployments and calls them "the case to watch."
   - **4b — envelope-dispatched.** The value is taken from the envelope's `fmt_ver`. This preserves mixed-version reads and **does not close the aliasing case**: on decrypt, `fmt_ver` is read *from the envelope*, so a v2 reader handed a relocated v1 envelope dispatches to the v1 encoder and reproduces precisely the bytes said to collide. 4b buys tidiness, not separation.

   Cost, common to both: `canonical_context` is a derivation input that is never stored and never on the wire, so the runtime cost is one byte of KDF `info` and nothing else. The real cost is that it introduces a **second version number alongside §3.1's `fmt_ver`** — redundant under 4b, independently variable under 4a, and in either case a new invariant, a new way for two version fields to disagree, and a new error case. Design commitment 1 ("one suite, maybe two"; the PASETO model, not JOSE) exists to refuse this kind of multiplication.

5. **No new field; a normative extension rule.** Three sentences in §6.2, none of which changes a byte any current implementation emits:

   - **Bit 7 of `presence` is reserved as a continuation flag**, set iff a second presence byte follows. Every encoding this specification defines has bit 7 clear, so a one-byte bitmap can never alias a two-byte one and the bitmap can grow without shifting any field.
   - **A presence bit's meaning is immutable once assigned.** A new optional field MUST take the next free bit; no version may reassign or redefine an existing one.
   - **An absent optional field means "not bound", in every version.** No version may give an unset bit a default value or any other reading. *This is the sentence that answers the answer:* the conditional in "cryptographically it can be secure if semantically it means the same thing" becomes a normative requirement rather than an assumption about the discipline of future editors.

   Optionally a fourth, which costs nothing and separates versions with no new field at all: **any change to the §6.2 layout MUST take a new `fmt_ver` and MUST NOT reuse a `suite_id`.** `suite_id` is already the first length-prefixed field *inside* `canonical_context`, so a fresh identifier separates two encodings' derivation inputs everywhere `canonical_context` is used — including §7.2's index derivation, which has no envelope and therefore no `fmt_ver` at all.

**Option 5 is proposed.** 4a is the fallback if the project decides a `fmt_ver` bump requires full re-encryption regardless, in which case 4a is nearly free and option 5's third sentence becomes unnecessary — but that is a PRD question about mixed-version deployments, not an encoding one, and §3.4 currently answers it the other way. 4b is not proposed: it costs a format change and buys no separation.

Two things about option 5, stated against itself. It leaves the guarantee resting on editorial discipline rather than on the bytes — which is the objection the version-byte recommendation was making. The answer is that the discipline becomes RFC 2119 text with a rationale instead of a clause inside a *Justification* paragraph; it is still discipline. And it has **no negative vector** — see *Vector obligations*.

## Justification

The same argument §6.2 already makes for length-prefixing: "Unlength-prefixed concatenation is forgeable across field boundaries" (spec §6.2, citing RFC 7518 §5.2 and Tink's AES-CTR-HMAC encoding). An encoding in which two distinct `FieldContext` values can produce one byte string violates the injectivity that canonical encodings exist to provide.

## What it breaks

Compatibility-breaking for every derived key and every AAD (all ciphertext, all indexes). Nothing exists yet. If option 1 or 2 is adopted, §6.2's layout changes and `row_id`'s existing "omitted entirely" rule is subsumed by the same mechanism — the issue must restate §6.2 in full, not patch it.

**Options 4a and 4b** break compatibility the same way option 1 did, and now there is something to break: every derived key, every AAD, every blind index, and **all 145 pinned vectors** — all nine `MANIFEST.json` families depend on `canonical_context` directly or through a derived key. The break is cheap *now* (every suite identifier is still in the reserved `0xFF00–0xFFFF` provisional range per §4.8, and the manifest already warns that expected values may change at Gate 0b) and becomes a `fmt_ver 0x02` exercise after a freeze — so if the byte is ever going to be adopted, before Gate 0b closes is the moment. The code is small and localized: `canonical_context` is one function per core (`core/python/src/fieldseal/context.py`, `core/typescript/src/context.ts`) plus `tools/vector-gen`.

**Option 5 breaks nothing.** No current encoding changes, no vector is regenerated, and both cores already emit bit 7 clear.

## Vector obligations

- `context/`: canonical encodings for — all fields present; `tenant_id` null; `row_id` null; both null; `tenant_id` zero-length (expected: distinct encoding or a defined rejection).
- Negative vectors: byte strings exhibiting the aliasing attempt (a present-field encoding equal to an omitted-field encoding) with the expected rejection/impossibility documented.
- `kdf/` vectors deriving keys from null-tenant contexts.

**Option 5's vector cost is zero, and that is also its weakness.** The presence byte is computed by the encoder from which fields are set, so no implementation can construct a context with bits 2–7 set; there is nothing for a negative vector to reject, and `canonical_context` has no decoder to reject it with (§6.2: produced and recomputed, never parsed). The continuation-flag and bit-immutability rules are therefore producer obligations verifiable by review of a future revision, not by the suite — an honest cost of choosing a rule over a field.

## Review flag

**Needs cryptographic review** — this is canonical-encoding injectivity, a known forgery surface. The first half of the question (injectivity over the current field set) now has one round of external confirmation and no counterexample; the live half is extension. Put to a reviewer in the form option 5 gives it: with no decoder anywhere in the design, is "a presence bit's meaning is immutable, an absent field always means not-bound, and bit 7 continues the bitmap" sufficient for cross-version injectivity — or does the encoding need a version field of its own despite the `fmt_ver` and `suite_id` it already carries? A reviewer who wants the byte should say **which variant** they mean: 4a and 4b differ, and only 4a separates anything.
