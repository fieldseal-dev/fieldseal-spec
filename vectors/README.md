# Test Vectors

**The cross-implementation vectors are the point of this project.** If a value encrypted by the Python core cannot be decrypted by the Go core, the central claim — that this is a portable format and not another library — is false, and nothing else in the repository matters.

Every implementation MUST run every vector for every conformance level it claims, in CI, and CI MUST fail on any divergence.

## Layout (planned)

```
vectors/
  envelope/          encrypt/decrypt round trips per suite, fixed key + seed + nonce + context
  kdf/               tenant DEK + key_id + msg_seed + context → expected record key;
                     tenant index key + context → expected per-index key
  context/           byte-exact canonical_context encoding, row_id present and absent
  blind-index/       key + plaintext + normalization + truncation → expected index
                     (both Argon2id and HMAC index derivation functions)
  commitment/        key-commitment values
  errors/            every error case in spec §9, including malformed envelopes
  cross/             manifest of values produced by each implementation,
                     to be decrypted by every other implementation
```

## Format (planned)

JSON, one file per vector group. Every binary value hex-encoded. Every vector carries a stable `id`, the full input state (no implicit defaults), the expected output, and a `spec_ref` pointing at the section it exercises.

```json
{
  "id": "envelope/ff01/basic-roundtrip",
  "spec_ref": "§3.1, §4.2",
  "suite_id": "0xFF01",
  "tenant_dek": "hex...",
  "key_id": "hex...",
  "msg_seed": "hex...",
  "nonce": "hex...",
  "context": {
    "table_uuid": "hex...",
    "column_uuid": "hex...",
    "tenant_id": "hex...",
    "row_id": null,
    "purpose": "encrypt"
  },
  "plaintext": "hex...",
  "expected_ciphertext": "hex...",
  "expected_canonical_context": "hex..."
}
```

Nonces and derivation seeds are fixed in vectors so outputs are deterministic and comparable. **This is a testing affordance only.** Spec §3.1 and §4.4 require a fresh CSPRNG seed and nonce on every real encryption, including UPDATEs; an implementation that accepts a caller-supplied nonce or seed outside of vector-test mode is non-conformant.

## Negative vectors matter as much as positive ones

Include, at minimum: unknown `fmt_ver`; a `suite_id` not on the allow-list; a truncated envelope; a valid envelope with one AAD component altered; a valid envelope with a flipped ciphertext bit; a valid envelope with a flipped tag bit; a ciphertext crafted to decrypt under two keys (the key-commitment case); and plaintext presented to a core in `strict` read mode.

Each must produce the specific error type from spec §9 — not a generic failure. An implementation that collapses `AAD_MISMATCH` and `TAG_INVALID` into one error is non-conformant, because operators need to distinguish a data-migration bug from tampering.

## Licensing

**CC0 1.0** ([`../LICENSE-VECTORS`](../LICENSE-VECTORS)), so that a competing or independent implementation can run these with zero attribution friction. Their value comes from being run, not from being credited. This file, being documentation about the vectors rather than a vector, is CC BY 4.0 like the rest of the docs — see [`../LICENSES.md`](../LICENSES.md).
