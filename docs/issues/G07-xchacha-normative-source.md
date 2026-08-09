# G7 — §4.2: Suite 0x0002's XChaCha20-Poly1305 has no named normative definition

**Labels:** §4.2 · spec-gap · needs-crypto-review (partly)
**Blocks:** confidence in `envelope/0002.json` (mechanics are unambiguous in practice; provenance is not).

## Gap

The registry names `FLE-XCHACHA20POLY1305-HKDF-SHA512` for suite 0x0002, but XChaCha20-Poly1305 has no IETF RFC: `draft-irtf-cfrg-xchacha` expired without publication. §15 (normative references) therefore has nothing to point at, violating the spec's own every-claim-cited standard for a registered suite. ChaCha20-Poly1305 itself is RFC 8539's predecessor RFC 8439; only the X (extended-nonce, HChaCha20) construction lacks standards-track definition.

## Proposed direction (starting point, not a decision)

Two options, in preference order:

1. **Name libsodium's construction as normative.** The libsodium documentation defines XChaCha20-Poly1305 (HChaCha20 subkey derivation + RFC 8439 ChaCha20-Poly1305-IETF with the derived subkey and 8-byte nonce remainder) and is the de-facto interoperability anchor every implementation tests against; the expired `draft-irtf-cfrg-xchacha-03` can be cited informatively as the written-up analysis. Precedent: PASETO v2/v4 normatively depend on the same libsodium-defined construction.
2. **Drop 0x0002 entirely.** The registry principle is "one option, maybe two" (§4.1); if the second option cannot be cited to the project's own standard, deleting it is coherent. Cost: no non-FIPS/mobile-friendly suite, and the registry's extension story goes unexercised.

Option 1 is proposed; the suite exists for a reason (192-bit nonce margin, non-NIST diversity).

## Justification

`CONTRIBUTING.md`: "a justification with a citation — NIST publication, IETF RFC, peer-reviewed literature, **or shipping-product documentation**." Libsodium's documentation is shipping-product documentation with a decade of cross-implementation agreement; the draft's expiry is checkable at the IETF datatracker (draft-irtf-cfrg-xchacha, last revision -03).

## What it breaks

Nothing byte-level if option 1 (the construction everyone implements is what gets named). Option 2 removes a registry row — compatibility-breaking for hypothetical 0x0002 ciphertext (none exists).

## Vector obligations

- Option 1: `envelope/0002.json` round trips including an HChaCha20 intermediate-subkey vector (so implementations composing from ChaCha20-Poly1305 primitives can check the extension step in isolation).
- Option 2: remove 0x0002 vector obligations; add a negative vector — envelope bearing 0x0002 → NOT_CIPHERTEXT (unregistered).

## Review flag

**Partly** — a reviewer should confirm treating libsodium's definition as normative is acceptable for a spec targeting independent review, or push the project to option 2.
