# G1 — §4.6/§3.1: The key-commitment construction is undefined

**Labels:** §4.6 · §3.1 · spec-gap · blocks-vectors · needs-crypto-review
**Blocks:** every `commitment/` and `envelope/` expected value; the invisible-salamander negative vectors in `errors/crypto.json`; ADR-0002 option A's arithmetic.

## Gap

§4.6 makes key commitment mandatory ("Every suite MUST provide key commitment, either by using a committing AEAD or by emitting an explicit 32-byte commitment value derived from the key") and §3.1 reserves the 32-byte `commitment` field — but no construction is defined anywhere in the spec. There is no formula from which an implementation can compute the value, so no envelope test vector can carry an expected output and no two implementations can interoperate on suites 0x0001/0x0002.

## Proposed direction (starting point, not a decision)

Derive the commitment from the record key via the suite's KDF under a dedicated, fixed label, e.g.:

```
commitment = HKDF-SHA-512(ikm = record_key, salt = "", info = "fieldseal-commit-v1", length = 32)
```

verified with a constant-time compare **before** AEAD open (the check order is G5's subject). Properties wanted: (a) computable by the decryptor from candidate key material alone, before touching ciphertext; (b) collision-binding on the key so a ciphertext cannot verify under two different keys; (c) domain-separated from record-key derivation (§5.3) and index-key derivation (§7.2) by label.

Precedent worth profiling regardless of ADR-0001's outcome: the AWS Database Encryption SDK's header commitment is "a 32-byte HMAC-SHA384 truncation calculated over the partial header using a commitment key derived via HKDF from the data key and message ID" (structured-encryption/header.md, retrieved 2026-08-08 — see `docs/adr/0001-appendix-a-expressibility-mapping.md`, finding F7). Adopting their derivation shape lets the Phase 0 review lean on a shipped, reviewed construction instead of a novel one.

**Interaction with ADR-0002:** choosing AES-256-CBC-HMAC-SHA-512 (option B) makes 0x0001 natively committing and dissolves this gap for the mandatory suite — but 0x0002 (XChaCha20-Poly1305) still needs it, so the construction must be defined regardless (ADR-0002 records this explicitly).

## Justification

AES-GCM and (X)ChaCha20-Poly1305 are not key-committing; in a multi-key system this enables invisible-salamander ciphertexts and partitioning-oracle attacks (Len–Grubbs–Ristenpart, *Partitioning Oracle Attacks*, USENIX Security '21; Albertini et al., *How to Abuse and Fix Authenticated Encryption Without Key Commitment*, USENIX Security '22 — the generic "commit to the key with an independent PRF output" fix is the shape proposed above). AWS remediated exactly this class in production via [AWS-2025-032](https://aws.amazon.com/security/security-bulletins/AWS-2025-032/) (CVE-2025-14759 through -14764) by introducing key commitment. The spec already mandates the property (§4.6); this issue only pins the formula.

## What it breaks

Compatibility-breaking for the envelope semantics of both registered suites (the reserved 32 bytes acquire a normative value). No conformant ciphertext exists yet, so the break is theoretical — which is precisely why this must close before Phase 1 code.

## Vector obligations

- `commitment/`: (key material, context) → expected 32-byte commitment, per suite.
- `envelope/`: every round-trip vector's expected envelope includes the commitment bytes.
- `errors/crypto.json`: COMMITMENT_INVALID cases — wrong key with correct structure; and a two-key vector demonstrating that a ciphertext verifying under key A fails commitment under key B (the salamander case).

## Review flag

**Needs cryptographic review.** The reviewer question: does the proposed KDF-based commitment achieve the binding notion needed to stop partitioning oracles (CMT-1 in the Bellare–Hoang framing), and is verify-before-decrypt with early loop exit acceptable (see docs/09 §3.2 timing note)?
