# G7 — §4.2: Suite 0xFF02's XChaCha20-Poly1305 has no named normative definition

**Labels:** §4.2 · spec-gap · needs-crypto-review (partly)
**Blocks:** confidence in `envelope/ff02.json` (mechanics are unambiguous in practice; provenance is not).

**Status:** OPEN — tracker [#7](https://github.com/fieldseal-dev/fieldseal-spec/issues/7); provisionally retained under Gate 0a (spec §4.2). **CFRG list input received 2026-08-23** — see the option added below and `docs/16` Q6.

## Gap

The registry names `FLE-XCHACHA20POLY1305-HKDF-SHA512` for suite 0xFF02, but XChaCha20-Poly1305 has no IETF RFC: [`draft-irtf-cfrg-xchacha`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/) expired without publication — last revision **-03, expired 2023-05-02**, datatracker state **Expired / Dead IRTF Document**, author Scott Arciszewski (verified 2026-08-22). §15 (normative references) therefore has nothing to point at, violating the spec's own every-claim-cited standard for a registered suite. ChaCha20-Poly1305 itself is defined by **RFC 8439** (which obsoleted RFC 7539); only the X (extended-nonce, HChaCha20) construction lacks a standards-track definition.

## Proposed direction (starting point, not a decision)

Two options, in preference order:

1. **Name libsodium's construction as normative.** The libsodium documentation defines XChaCha20-Poly1305 (HChaCha20 subkey derivation + RFC 8439 ChaCha20-Poly1305-IETF with the derived subkey and 8-byte nonce remainder) and is the de-facto interoperability anchor every implementation tests against; the expired `draft-irtf-cfrg-xchacha-03` can be cited informatively as the written-up analysis. **Precedent, and its two limits** (corrected 2026-08-22 — this entry previously read "PASETO v2/v4 normatively depend on the same libsodium-defined construction," which is wrong about v4): [PASETO v2.local](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md) specifies XChaCha20-Poly1305 "using an AEAD interface such as the one provided in libsodium" and cites no RFC or draft — a real instance of the choice this option proposes. But [v4.local](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md) moved to XChaCha20 with a separate BLAKE2b-MAC, so it is **not** a second instance; and PASETO's author is also the author of the expired CFRG draft, so the precedent is one party's judgment rather than two independent ones. Stated because a precedent that collapses to a single author is weaker than it looks, and a reviewer would find this anyway.
2. **Drop 0xFF02 entirely.** The registry principle is "one option, maybe two" (§4.1); if the second option cannot be cited to the project's own standard, deleting it is coherent. Cost: no non-FIPS/mobile-friendly suite, and the registry's extension story goes unexercised.

3. **Re-base `0xFF02` on RFC 8439 ChaCha20-Poly1305, and let §5.3 be the nonce extension.** *Added 2026-08-23 from CFRG list replies (Neil Madden; John Preuß Mattsson, Ericsson — `https://mailarchive.ietf.org/arch/browse/cfrg/`, thread of 2026-08-22).* Both replies make the same point independently: the standard way to get a random extended nonce with any AEAD is `K' = KDF(K, E); C = AEAD(K', N, P, A)`, and XChaCha's HChaCha20 step is one instance of it. This specification already does exactly that — §5.3 derives a single-use `record_key` from the tenant key with the 32-byte `msg_seed` as `E` — so the 192-bit nonce that motivated choosing XChaCha over ChaCha20-Poly1305 buys nothing here that `msg_seed` has not already bought. Under this option the suite is `FLE-CHACHA20POLY1305-HKDF-SHA512`, 96-bit random nonce, RFC 8439 as the normative reference, and every word of §4.2's provenance problem disappears. What the suite is *for* is restated the way Mattsson put it: not "non-NIST", but **a different hardness assumption from AES** — which is a sensible goal and the one the PRD's SP-2 "non-FIPS alternative" was reaching for. Cost: a new provisional identifier (`0xFF02` retires unused, per §4.8's no-promotion-in-place rule, and a fresh one — say `0xFF03` — is registered), regenerated `ff02`-family vectors, and the loss of the one property XChaCha has that this design does not use (safe random nonces *without* a per-message key, which §4.4 forbids relying on anyway).

Two further facts from the same thread bear on options 1 and 2. Mattsson states that `draft-irtf-cfrg-xchacha-03` *is* a stable, citable document — "it will not change, and the IETF will keep the document available indefinitely" (`https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt`) — which weakens the premise that option 1 must lean on libsodium's documentation: an expired I-D is archival, not gone. And Madden is "not aware of any other stable specification for it", which answers the revival question: there is nothing to wait for.

**Option 3 is now proposed**, option 1 (citing the archival draft rather than libsodium) is the fallback, and option 2 remains the honest floor. Before 2026-08-23 this read: "Option 1 is proposed; the suite exists for a reason (192-bit nonce margin, non-NIST diversity)." Both halves of that reason are now answered — the margin is already provided by §5.3, and "non-NIST" was the wrong name for the goal.

## Justification

`CONTRIBUTING.md`: "a justification with a citation — NIST publication, IETF RFC, peer-reviewed literature, **or shipping-product documentation**." Libsodium's documentation is shipping-product documentation with a decade of cross-implementation agreement; the draft's expiry is verified above against the IETF datatracker.

## What it breaks

Nothing byte-level if option 1 (the construction everyone implements is what gets named). Option 2 removes a registry row — compatibility-breaking for hypothetical 0xFF02 ciphertext (none exists).

## Vector obligations

- Option 1: `envelope/ff02.json` round trips including an HChaCha20 intermediate-subkey vector (so implementations composing from ChaCha20-Poly1305 primitives can check the extension step in isolation).
- Option 2: remove 0xFF02 vector obligations; add a negative vector — envelope bearing 0xFF02 → NOT_CIPHERTEXT (unregistered).
- Option 3: `0xFF02` retires and its vector family with it; the replacement suite gets the full `envelope/`, `kdf/` and `commitment/` families of `0xFF01`, plus RFC 8439 §2.8.2's AEAD test vector as the primitive known-answer check (the one thing `0xFF02` could never have).

## Review flag

**Partly** — a reviewer should confirm treating libsodium's definition as normative is acceptable for a spec targeting independent review, or push the project to option 2. *2026-08-23:* under option 3 the question a reviewer is asked changes to a narrower one — is §5.3's derivation an adequate substitute for XChaCha's HChaCha20 extension, given that both are `K' = KDF(K, E)` — and the two CFRG replies already answer it in the affirmative, though a list reply is input, not a review.
