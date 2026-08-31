# Test Vectors

**The cross-implementation vectors are the point of this project.** If a value encrypted by the Python core cannot be decrypted by the Go core, the central claim — that this is a portable format and not another library — is false, and nothing else in the repository matters.

Every implementation MUST run every vector for every conformance level it claims, in CI, and CI MUST fail on any divergence.

## Layout

*Status 2026-08-31, suite `0.5.0-provisional`.* `envelope/`, `kdf/`, `context/`, `blind-index/`, `commitment/` and `errors/` (`format.json`, `policy.json`, `crypto.json`) are emitted by `tools/vector-gen` and pinned by hash in `MANIFEST.json` — 125 vectors, which both cores run as 145 results (`envelope/` vectors carry a `#decrypt` direction and some `blind-index/` vectors a `#pipeline` run, per `docs/14` §4); `blind-index/argon2id.json` is held out (see the manifest's `held_out` and `docs/07` §7). `keys/test-keys.json` is the shared public key material for `cross/`, and `cross/corpus.json` is the 16-case input corpus every cross producer encrypts — both under `MANIFEST.support`, never run by a harness. The *dynamic* cross exchange runs in CI (`docs/14` §3: each core produces through its production path, every core decrypts every producer, self-pairs included); `cross/static/` — per-release checked-in envelopes — waits for a first release to pin. `schema/` is empty; each harness records that in its report's `harness_notes`. Vectors whose expected value depends on an open gap carry `provisional_on` (docs/08 §3).


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

## Format

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

## Held-out families

A family may be generated, reviewable, and deliberately **not part of the
suite**. `MANIFEST.json` lists these under `held_out` rather than omitting them
— a missing file reads as an oversight, a listed one with a reason reads as a
decision — and each such file carries `"status": "held-out"` itself, so a
harness that loads the file directly still sees it.

A conformance run MUST iterate `MANIFEST.files` and MUST NOT iterate
`held_out`. An implementation MAY exercise a held-out family in its own
development and MUST NOT count it toward any conformance claim.

Currently held out: **`blind-index/argon2id.json`**. The Argon2id primitive has
never been checked against an external known-answer source, and the source
`docs/08-test-vector-spec.md` §7 named for that — RFC 9106 §5.3's test vector —
cannot serve, because it supplies a nonzero secret (`K`) and associated data
(`X`), both forbidden by spec §7.3 and unsuppliable from Python. Without an
external check, two implementations would inherit the same unverified
assumption from one generator, agree with each other, and prove nothing.

## Licensing

**CC0 1.0** ([`../LICENSE-VECTORS`](../LICENSE-VECTORS)), so that a competing or independent implementation can run these with zero attribution friction. Their value comes from being run, not from being credited. This file, being documentation about the vectors rather than a vector, is CC BY 4.0 like the rest of the docs — see [`../LICENSES.md`](../LICENSES.md).
