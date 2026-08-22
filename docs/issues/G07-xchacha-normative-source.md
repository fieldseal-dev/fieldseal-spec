# G7 — §4.2: Suite 0xFF02's XChaCha20-Poly1305 has no named normative definition

**Labels:** §4.2 · spec-gap · needs-crypto-review (partly)
**Blocks:** confidence in `envelope/ff02.json` (mechanics are unambiguous in practice; provenance is not).

## Gap

The registry names `FLE-XCHACHA20POLY1305-HKDF-SHA512` for suite 0xFF02, but XChaCha20-Poly1305 has no IETF RFC: [`draft-irtf-cfrg-xchacha`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/) expired without publication — last revision **-03, expired 2023-05-02**, datatracker state **Expired / Dead IRTF Document**, author Scott Arciszewski (verified 2026-08-22). §15 (normative references) therefore has nothing to point at, violating the spec's own every-claim-cited standard for a registered suite. ChaCha20-Poly1305 itself is defined by **RFC 8439** (which obsoleted RFC 7539); only the X (extended-nonce, HChaCha20) construction lacks a standards-track definition.

## Proposed direction (starting point, not a decision)

Two options, in preference order:

1. **Name libsodium's construction as normative.** The libsodium documentation defines XChaCha20-Poly1305 (HChaCha20 subkey derivation + RFC 8439 ChaCha20-Poly1305-IETF with the derived subkey and 8-byte nonce remainder) and is the de-facto interoperability anchor every implementation tests against; the expired `draft-irtf-cfrg-xchacha-03` can be cited informatively as the written-up analysis. **Precedent, and its two limits** (corrected 2026-08-22 — this entry previously read "PASETO v2/v4 normatively depend on the same libsodium-defined construction," which is wrong about v4): [PASETO v2.local](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md) specifies XChaCha20-Poly1305 "using an AEAD interface such as the one provided in libsodium" and cites no RFC or draft — a real instance of the choice this option proposes. But [v4.local](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md) moved to XChaCha20 with a separate BLAKE2b-MAC, so it is **not** a second instance; and PASETO's author is also the author of the expired CFRG draft, so the precedent is one party's judgment rather than two independent ones. Stated because a precedent that collapses to a single author is weaker than it looks, and a reviewer would find this anyway.
2. **Drop 0xFF02 entirely.** The registry principle is "one option, maybe two" (§4.1); if the second option cannot be cited to the project's own standard, deleting it is coherent. Cost: no non-FIPS/mobile-friendly suite, and the registry's extension story goes unexercised.

Option 1 is proposed; the suite exists for a reason (192-bit nonce margin, non-NIST diversity).

## Justification

`CONTRIBUTING.md`: "a justification with a citation — NIST publication, IETF RFC, peer-reviewed literature, **or shipping-product documentation**." Libsodium's documentation is shipping-product documentation with a decade of cross-implementation agreement; the draft's expiry is verified above against the IETF datatracker.

## What it breaks

Nothing byte-level if option 1 (the construction everyone implements is what gets named). Option 2 removes a registry row — compatibility-breaking for hypothetical 0xFF02 ciphertext (none exists).

## Vector obligations

- Option 1: `envelope/ff02.json` round trips including an HChaCha20 intermediate-subkey vector (so implementations composing from ChaCha20-Poly1305 primitives can check the extension step in isolation).
- Option 2: remove 0xFF02 vector obligations; add a negative vector — envelope bearing 0xFF02 → NOT_CIPHERTEXT (unregistered).

## Review flag

**Partly** — a reviewer should confirm treating libsodium's definition as normative is acceptable for a spec targeting independent review, or push the project to option 2.
