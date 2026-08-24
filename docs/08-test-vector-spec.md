# Test Vector Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the engineering specification for authoring, validating, and consuming the machine-readable test vectors described in spec §12 and `vectors/README.md`. Written for whoever builds the vector suite and the per-language conformance harnesses.

**Depends on:** `docs/02-spec-v0.1.md` (normative), `docs/07-implementation-plan.md` (decision gates). **Blocked in part by:** the spec gaps listed in §9 of this document — several vector families cannot be given expected values until those are resolved by spec issues.

---

## 1. Principles

1. **Vectors are the conformance oracle.** An implementation claims a conformance level (spec §10) only by passing every vector for that level in CI. The vectors, not any implementation, are the source of truth. If a vector and an implementation disagree, the vector wins unless a spec issue proves the vector wrong.
2. **Vectors are append-only after release.** Once a vector file ships in a tagged release, its vectors' `id`s and expected values MUST never change. Corrections retire an `id` (moved to a `retired` list with a reason and a spec-issue link) and add a new `id`. This is what lets independent implementations pin a vector-suite version.
3. **No implicit defaults.** Every input an implementation needs to reproduce the expected output is present in the vector. A vector that depends on an implementation's default configuration is a bug.
4. **Negative vectors are first-class.** Spec §9 requires distinguishable error types; `vectors/README.md` makes collapsing `AAD_MISMATCH` and `TAG_INVALID` non-conformant. Every error case therefore has vectors, and each names the exact expected error code.
5. **Fixed randomness is a testing affordance only.** Vectors fix `msg_seed` and `nonce` for determinism. Spec §3.1/§4.4 require fresh CSPRNG values on every real encryption. The injection mechanism (§6 below) MUST NOT be reachable from an implementation's public production API — and because Python/npm packages cannot prevent a determined `import` of a shipped module, §6 defines what unreachable means in practice: a separated namespace that the main entry never re-exports, **plus** a runtime arming gate.

---

## 2. Directory layout

Extends the planned layout in `vectors/README.md` with schema and shared-key files:

```
vectors/
  MANIFEST.json            suite-wide metadata: vector-suite version, file list, sha256 per file
  schema/                  JSON Schema (draft 2020-12), one per family (extracted from §4 of this doc)
    common.schema.json
    envelope.schema.json
    kdf.schema.json
    context.schema.json
    blind-index.schema.json
    commitment.schema.json
    errors.schema.json
    cross.schema.json
  keys/
    test-keys.json         shared, PUBLIC test key material referenced by key_ref (never real keys);
                           emitted by the generator, listed in MANIFEST.support, never run
  cross/
    corpus.json            the shared producer-input corpus (MANIFEST.support): key refs,
                           contexts, plaintexts -- no envelopes, no expected values
  envelope/
    ff01.json              suite 0xFF01 round trips
    ff02.json              suite 0xFF02 round trips (consumed only by implementations claiming 0xFF02)
  kdf/
    record-key.json
    index-key.json
  context/
    canonical.json
  blind-index/
    hmac-sha512.json
    argon2id.json          HELD OUT of the suite — see §9; listed in MANIFEST.held_out
  commitment/
    ff01.json
    ff02.json
  errors/
    format.json            structural failures: truncation, unknown fmt_ver, unregistered suite
    policy.json            allow-list, read-mode cases
    crypto.json            tag flips, AAD alteration, commitment mismatch, salamander case
  cross/
    keys → ../keys/test-keys.json (by reference, not symlink — see §4.7's key_ref rule)
    static/
      python/ff01.json     envelopes produced by each released implementation
      typescript/ff01.json
```

`MANIFEST.json` carries a semver `vector_suite_version`. Implementations record the version they were validated against in their conformance claim (see `docs/14-conformance-ci.md`).

---

## 3. Encoding conventions (normative for vector files)

| Value | Encoding | Rationale |
|---|---|---|
| All binary values (keys, seeds, nonces, ciphertexts, contexts, UUID surrogates) | Lowercase hex, no `0x` prefix, even length | Matches `vectors/README.md`; unambiguous, diff-friendly |
| `suite_id` | String `"0xFF01"` (`0x` prefix, four **uppercase** hex digits) | Matches the existing README example; visually distinct from binary blobs. Case is pinned because provisional identifiers (spec §4.8) contain letters and harnesses compare this field as a string |
| `fmt_ver` | String `"0x01"` | Same convention as `suite_id` |
| Absent optional value (`row_id`, `tenant_id`) | JSON `null` | Distinct from empty: `""` (hex) means *present with zero length*. Distinct on the wire since the §6.2 presence bitmap was adopted provisionally under Gate 0a (G4, 2026-08-22); `context/canonical.json` pins both (`tenant-zero-length`, `absent-differs-from-zero-length`) and regenerates if Gate 0b changes the bit assignment. |
| Text values (`purpose`, normalization names, error codes) | JSON string, ASCII | `purpose` is a protocol string, not user text |
| Sizes/lengths | JSON integer, bytes unless the field name says `_bits` | Truncation length `b` is in bits per spec §7.4 |

Vector files are UTF-8, LF line endings (repo `.gitattributes` pins LF), 2-space indent, keys in the order given by the schema — so that regenerated files diff cleanly.

---

**Two fields common to every family since suite 0.2.0 (2026-08-23):**

- `provisional_on` — a list of gap identifiers (`"G5"`, `"G14"`, `"G15"`) or, for a pin not yet owned by an issue, the `docs/18` divergence id (`"D-11"`). Present on every vector whose expected value would change if that gap closed the other way; absent otherwise. A harness does not act on it — it is the reader's map from an expected value to the decision that produced it, and the regeneration list when a gap closes.
- `assertion` vectors (`"distinct"` / `"equal"`) carry an `inputs` object holding both sides' inputs, so an implementation reproduces each side and then checks the relation. Earlier suites carried only the literal expected values (docs/18 D-08); a harness that merely compares the literals is no longer checking anything.

## 4. Vector file format per family

Every file shares a common wrapper:

```json
{
  "schema": "fieldseal-vectors/<family>/v1",
  "vector_suite_version": "0.1.0",
  "group": "<family>",
  "spec_version": "0.1-draft",
  "vectors": [ ... ],
  "retired": [ { "id": "...", "reason": "...", "spec_issue": "..." } ]
}
```

Every vector object carries:

- `id` — stable string, grammar: `<family>/<file-stem>/<slug>` where `slug` matches `[a-z0-9-]{1,64}`. Example: `envelope/ff01/basic-roundtrip`. Never reused, even after retirement.
- `description` — one sentence, for failure messages.
- `spec_ref` — the section(s) the vector exercises, e.g. `"§3.1, §4.2"`.

### 4.1 `envelope/` — encrypt/decrypt round trips

Input state is complete: no key provider, no cache, no modes — this family tests the cryptographic core in isolation.

```json
{
  "id": "envelope/ff01/basic-roundtrip",
  "description": "9-byte plaintext, tenant context, row_id absent",
  "spec_ref": "§3.1, §4.2, §5.3, §6.2, §6.3",
  "suite_id": "0xFF01",
  "tenant_dek": "…64 hex chars (32 B)…",
  "key_id": "…32 hex chars (16 B)…",
  "msg_seed": "…64 hex chars (32 B)…",
  "nonce": "…24 hex chars (12 B for 0xFF01)…",
  "context": {
    "table_uuid": "…32 hex…",
    "column_uuid": "…32 hex…",
    "tenant_id": "…hex…",
    "row_id": null,
    "purpose": "encrypt"
  },
  "plaintext": "…hex…",
  "expected": {
    "envelope": "…hex, the full concatenated envelope of spec §3.1…",
    "canonical_context": "…hex…",
    "aad": "…hex…"
  },
  "intermediates": {
    "record_key": "…hex…",
    "commitment": "…hex…"
  }
}
```

- `expected.envelope` is the normative assertion, byte-exact. `expected.canonical_context` and `expected.aad` are also normative (they double as `context/` coverage in situ).
- `intermediates` is **non-normative debugging aid** — harnesses SHOULD check it when their core exposes the values, and MUST NOT fail conformance on it alone.
- Each envelope vector is exercised in **both directions**: encrypt(inputs) → `expected.envelope`, and decrypt(`expected.envelope`) → `plaintext`. The harness contract (§5) requires both.
- `suite_id` sits at the vector's top level, outside the `context` object, deliberately: the context's `suite_id` member is filled by the **core**, never by the caller — from the write suite on encrypt and from the parsed header on decrypt (docs/09 §3.2 step 4). A vector that carried it inside `context` would imply the caller supplies it.

Minimum case coverage per suite: empty plaintext (0 B) · 1 B · a 9-byte SSN-shaped value · a 1 KiB value · a value crossing an AEAD block boundary · `row_id` present · `row_id` absent · `tenant_id` present · `tenant_id` absent · multi-byte UTF-8 plaintext (as raw bytes — the core is bytes-in/bytes-out).

**Correction 2026-08-22 — "maximum-length `purpose` string" was removed from that list.** It is not expressible in this family: spec §5.3 constrains record-key derivation to `purpose = "encrypt"`, so an envelope vector cannot carry an index purpose at all. A generator that substituted an encrypt context to satisfy the requirement would emit a byte-identical duplicate of the basic round trip under a name claiming otherwise — which is worse than no coverage, because it reports as a passing case. The maximum-length `index-id` is covered where it is actually reachable, in `context/canonical.json`.

### 4.2 `kdf/` — key derivation

```json
{
  "id": "kdf/record-key/row-id-absent",
  "spec_ref": "§5.3",
  "suite_id": "0xFF01",
  "tenant_dek": "…hex…",
  "key_id": "…hex…",
  "msg_seed": "…hex…",
  "context": { ... },
  "expected": { "record_key": "…hex…" }
}
```

`kdf/index-key.json` mirrors it with `tenant_index_key` as input, `context.purpose` of the form `"index:<index-id>"`, `row_id` null (spec §7.2), and `expected.index_key`; a top-level `index_id` repeats the identifier for readability only. (Until suite 0.2.0 the context carried `purpose = "encrypt"` and a harness had to construct the index purpose itself — docs/18 D-06.) The file carries two vectors differing **only** in the index identifier (`email-eq` vs `ssn-eq`) to pin the §7.2 distinctness rule, two differing only in `column_uuid` to pin per-column separation, one whose caller context carried a `row_id` (marked `same_as` the row-less vector, since §7.2 drops it), and one at the maximum index-path context (G14).

### 4.3 `context/` — canonical encoding

Byte-exact `canonical_context` and `AAD` outputs for representative contexts. This family exists so an implementation can debug encoding independently of any cryptography.

Required cases: all fields present · `row_id` null (omitted entirely per §6.2) · `tenant_id` at boundary lengths (1 B, 16 B, 64 B) · `purpose` = `"encrypt"` and an index purpose · a context whose fields contain bytes that would be misparsed under naive concatenation (a `tenant_id` ending in bytes that look like a `u64be` length prefix followed by eight bytes) — this is the anti-forgery case that justifies §6.2. Every vector carries a top-level `suite_id`, since `canonical_context` embeds one (docs/18 D-05; emitted since suite 0.2.0, as are the boundary and forgery cases, which 0.1.0 lacked).

**G14 lengths (suite 0.2.0, `provisional_on: ["G14"]`):** `tenant_id` and `row_id` at 255 bytes each (the bound G14 proposes), at 2000 bytes each (above the 1024-byte HKDF `info` cap of `node:crypto` — the length that split the two cores on 2026-08-22 with no vector noticing), and the longest index-path context (2000-byte `tenant_id`, 32-character index-id). The same maximum context appears in `envelope/ff01.json` and both `kdf/` files. If G14 adopts a bound below 2000, those vectors retire and a refusal vector replaces them.

**Grammar refusals (G11, issue #11, resolved 2026-08-09):** spec §6.1 now constrains `index-id` to `[a-z0-9-]{1,32}`, so this family also carries negative *declarations* — `index:Exact` (uppercase), `index:é` (non-ASCII), `index:` (empty), and a 33-byte identifier. These pin a refusal at index-declaration time, not an error code: configuration validation sits outside the §9 taxonomy, so the vector asserts that the declaration is rejected and deliberately does not name a code (each core maps it to its own `ConfigurationError`, docs/09 §9). They belong here rather than in `errors/` for that reason.

**Formerly blocked case, now authored:** `tenant_id` null vs zero-length was blocked on G4 until 2026-08-22; the provisional §6.2 presence bitmap made it authorable and the family carries `tenant-zero-length` plus the `absent-differs-from-zero-length` assertion. G4 itself stays open for the reviewers (Q4); a changed bit assignment regenerates these vectors.

### 4.4 `blind-index/`

```json
{
  "id": "blind-index/hmac-sha512/email-15bit",
  "spec_ref": "§7.2, §7.3, §7.4, §7.11",
  "suite_id": "0xFF01",
  "idf": "hmac-sha512",
  "idf_params": {},
  "index_key": "…hex (32 B)…",
  "tenant_index_key": "…hex (32 B)…",
  "index_id": "email-eq",
  "context": { "…the §7.2 derivation context: purpose index:<id>, row_id null…" },
  "normalize": "nfc-casefold-v1",
  "plaintext": "…hex of the ALREADY-NORMALIZED value…",
  "plaintext_preimage": "USER@Example.COM",
  "truncate_bits": 15,
  "expected": {
    "raw": "…hex (full IDF output)…",
    "index": "…hex (truncated)…",
    "stored": { "binary": "…hex of the exact column bytes…", "hex": "…lowercase-hex column text…", "octets": 2 }
  }
}
```

- `plaintext` is the post-normalization byte string and is the normative input; `plaintext_preimage` documents where it came from and lets an implementation that ships the named normalizer test it too. Normalizer identifiers (`nfc-casefold-v1`, …) are declared in `docs/09-core-architecture.md` §7; the vector suite only ever references declared identifiers (suite 0.1.0 wrote `nfc-casefold`; corrected in 0.2.0, docs/18 D-07).
- `index_key` is the normative key input. `tenant_index_key`, `index_id` and `context` are its provenance under spec §7.2, carried so a harness can run the public `blind_index` operation end to end from the vector alone (reported as `<id>#pipeline`, docs/14 §4) without recovering the tenant key from `kdf/`.
- Seven vectors pin `nfc-casefold-v1`'s definition (docs/09 §7.1), settled by G15 part D on 2026-08-24 and no longer `provisional_on`. Three pin *bytes*: `fold-nfc-stable` (U+01F0, whose fold output recomposes under the second NFC), `folding-added-in-17` (U+A7D2, which gained its folding in Unicode 17.0.0), and `assigned-in-17` / `nfc-reordering-17` (a Beria Erfe capital and a U+1AD9 reordering case, which a core pinned to 16.0.0 would refuse). Four are `assertion: equal` and pin *collision*, which is the property the normalizer exists for and which byte-pinning does not reach: `normalizer-collapses-case`, `-fold-nfc` (U+0390 against its uppercase spelling `U+03AA U+0301`), `-fold-nfc-upsilon`, `-precomposed` and `-sharp-s`. The Greek pairs are the ones that fail without the post-fold NFC.
- `expected.stored` asserts the spec §7.11 storage contract (G8, issue #8). `stored.binary` MUST equal `expected.index` byte for byte and `stored.octets` MUST equal `⌈b/8⌉`; the redundancy is deliberate, because it converts an assumption every implementation would otherwise make silently into a test that fails when one of them pads, length-prefixes, or base64s the column. `stored.hex` is the lowercase text-column form for implementations supporting that alternative — a harness whose implementation is binary-only skips `stored.hex` and reports it skipped, but MUST assert `stored.binary` and `stored.octets`.
- Argon2id vectors carry full `idf_params`: `{"version": 19, "time_cost": 3, "memory_kib": 32768, "parallelism": 1, "output_len": 64, "salt": "…hex…"}` — exactly spec §7.3's single pinned invocation. (This document previously allowed "reduced parameters" for CI speed; §7.3 pins one tuple and the cost is ~40 ms per vector, so there is nothing to reduce.) `salt` is the HKDF-derived value of §7.3, asserted separately so an HKDF-step bug and an Argon2-step bug are distinguishable.
- The bit-level truncation rule is pinned (spec §7.2, G3 resolved 2026-08-08: leading `⌈b/8⌉` bytes, trailing bits of the final byte zeroed, MSB-first). Per spec §12, each file carries at least three `b mod 8 ≠ 0` vectors plus one multiple-of-8 control; suite 0.2.0 ships b = 12, 15, 21, 30 and the control at 16. The Argon2id invocation is pinned provisionally (G2, narrowed 2026-08-22); `blind-index/argon2id.json` is generated and **held out** — see §9.

### 4.5 `commitment/`

`record_key` → expected 32-byte commitment, with `expected.salt` (empty), `expected.info` (the §4.6 label) and `expected.length` stated. Authored against the §4.6 provisional construction (G1; `provisional_on: ["G1"]`). The file's assertion vector carries two record keys differing in exactly one bit (bit 0 of the last byte) and their distinct commitments — suite 0.1.0's description claimed one bit while its inputs differed in 32.

### 4.6 `errors/`

```json
{
  "id": "errors/crypto/tag-bit-flip",
  "spec_ref": "§9, §4.6",
  "suite_id": "0xFF01",
  "operation": "decrypt",
  "config": {
    "allowed_suites": ["0xFF01"],
    "write_suite": "0xFF01",
    "read_mode": "strict",
    "registered_suites": ["0xFF01", "0xFF02"],
    "arm_provisional_suites": true
  },
  "key_id": "…hex…",
  "tenant_dek": "…hex…",
  "context": { ... },
  "input": "…hex, the (possibly malformed) envelope bytes…",
  "derived_from": "envelope/ff01/basic-roundtrip",
  "mutation": "flip bit 0 of tag byte 0",
  "expected": { "error": "TAG_INVALID" }
}
```

- `input` is always literal bytes — `derived_from`/`mutation` are documentation, not instructions; harnesses never compute mutations.
- `operation` is one of `decrypt` (the default), `encrypt`, `rotate`, `is_ciphertext`, `blind_index`; `input` is the operand (an envelope, a plaintext, a value to index). A `blind_index` vector also carries `tenant_index_key` and an `index_declaration` (`index_id`, `idf`, `normalize`, `truncate_bits`).
- `config` makes policy explicit because several errors are policy-dependent (`SUITE_NOT_ALLOWED` requires a suite that is registered but not allow-listed; `NOT_CIPHERTEXT` in `strict` vs the pass-through expectation in `permissive`; the §4.8 gate depends on `arm_provisional_suites`). `key_id`/`tenant_dek` are the one key the provider resolves; a header naming any other `key_id` is `KEY_UNAVAILABLE`.
- `expected` carries exactly one of: `error` (a §9 code), `value` (the literal input back — §10.3 pass-through), `plaintext`, `is_ciphertext` (a boolean), or `index` (a positive control through `blind_index`).
- Each file carries `pinned_order` (the decrypt-path order its outcomes assume — docs/09 §3.2 as declared by both shipped cores) and a `withheld` list naming cases deliberately not authored because two readings of the text are both defensible today, with the gap that decides them. Vectors whose outcome depends on an open gap carry `provisional_on`.

Required error coverage (each case = one or more vectors):

| Case | Expected error | Notes |
|---|---|---|
| Envelope shorter than minimum length; empty input; truncation at every field boundary (mid-`key_id`, mid-`msg_seed`, mid-nonce, mid-tag, mid-commitment) | `NOT_CIPHERTEXT` | Per spec §3.4 recognition rules |
| ASCII plaintext presented in `strict` mode | `NOT_CIPHERTEXT` | The migration-accident case |
| Same input in `permissive` mode | pass-through value | With the §10.3 warning requirement noted |
| `fmt_ver` = `0x00`, `0x03`, `0xff` on an otherwise valid envelope | `NOT_CIPHERTEXT` (strict) / pass-through (permissive) | Spec §3.4: not a recognized version |
| `fmt_ver` = `0x02` at ≥ 111 bytes; at 110 bytes | `UNKNOWN_FORMAT_VERSION` in every mode; `NOT_CIPHERTEXT` | The reserved-known-future set `{0x02}` and the plausibility floor are G15 part A (`provisional_on`); `is_ciphertext` stays false for it |
| A long envelope shortened by one byte | `COMMITMENT_INVALID` | Still ≥ 111 bytes with a registered suite, so recognition passes; the damage surfaces at the commitment check. Recognition cannot detect truncation beyond the minimum, and the vector says so |
| `suite_id` = `0xFF02` on a 115-byte blob | `NOT_CIPHERTEXT` | Per-suite minimum (123 for a 24-byte nonce), docs/18 D-11 (`provisional_on`) |
| `suite_id` unregistered (e.g. `0x00ff`) | `NOT_CIPHERTEXT` | Recognition, not authorization — §3.4 |
| `suite_id` registered but not on allow-list | `SUITE_NOT_ALLOWED` | The §3.4 decoupling case: recognition must succeed |
| `key_id` unknown to the provider | `KEY_UNAVAILABLE` | |
| Each context field altered on decrypt (wrong tenant, column, table; `row_id` added; `row_id` dropped) | `COMMITMENT_INVALID` (`provisional_on: ["G5"]`) | Under §6.3 dual binding a context mismatch derives the wrong record key and fails at the commitment check, indistinguishably from key confusion; `AAD_MISMATCH` is not raisable on 0xFF01 and is listed as withheld. A wrong *purpose* is an API-boundary argument error (§5.3), also withheld |
| `nonce` bit flipped | `TAG_INVALID` | The nonce is not in the AAD; the record key and commitment are untouched |
| Single bit flips in ciphertext; in tag | `TAG_INVALID` | |
| Commitment bytes altered | `COMMITMENT_INVALID` | |
| A ciphertext valid under two keys (invisible salamander) | `COMMITMENT_INVALID` | Constructed by `tools/vector-gen/fieldseal_vectorgen/gcm.py` following Len–Grubbs–Ristenpart (USENIX '21): GCM's tag is linear in the ciphertext under GHASH, so one free block solves a linear equation in GF(2^128). The vector carries both record keys and the bytes the AEAD *would* have returned under the second key; a positive control decrypts the same envelope under the committed key. This is the vector that proves §4.6 does its job |
| `msg_seed` altered | `COMMITMENT_INVALID` (`provisional_on: ["G5"]`) | Self-authenticating per §3.2: the derived record key changes, so its commitment no longer matches under the pinned order |
| `encrypt()`/`rotate()` without §4.8 arming; `decrypt()`/`blind_index()` without arming | `SUITE_PROVISIONAL`; success | The gate and its deliberate absence on reads. `encrypt()` on a client both `readonly` and unarmed is `MODE_VIOLATION` (docs/18 D-04, `provisional_on`) |
| `rotate()` on non-envelope input in `permissive` | **withheld** | G15 part B: both cores encrypt it; the issue proposes `NOT_CIPHERTEXT`. Authored when it settles |
| `encrypt()` called in `readonly` mode | `MODE_VIOLATION` | Spec §9 and §10.3, pinned by G6 (issue #6). `rotate()` under `readonly` is the same case and MUST also be covered |
| Reads in `readonly` mode (valid envelope; non-envelope input) | Plaintext; pass-through | Spec §10.3, pinned by G6: `readonly` takes `permissive`'s non-envelope behavior. Both are positive controls bounding the row above — they prove the mode refuses *writes*, not reads |
| `blind_index()` called in `readonly` mode | Success | Spec §10.3, pinned by G6: computing an index for a WHERE clause is not a write. Positive control — a regression here silently makes read-only clients unable to query |
| Plaintext longer than 2³¹−1 bytes | `LENGTH_EXCEEDED` | **No vector.** Spec §3.5/§12 (G10, issue #10) exempt this case from the literal-bytes rule — a 2-GiB file is not a thing to put in git. Verified by an implementation-level test asserting the exact threshold, declared in the conformance report per docs/14 §4 |

### 4.7 `cross/` — the central claim

Two mechanisms, one file format:

```json
{
  "schema": "fieldseal-vectors/cross/v1",
  "producer": { "implementation": "python", "version": "0.1.0", "commit": "…", "produced_at": "…" },
  "suite_id": "0xFF01",
  "cases": [
    {
      "id": "cross/python/0001/case-001",
      "key_ref": "tenant-a-dek-v1",
      "context": { ... },
      "plaintext": "…hex…",
      "envelope": "…hex…"
    }
  ]
}
```

- `key_ref` resolves into `vectors/keys/test-keys.json` so producers and consumers share key material without embedding it per file. **Everything in `keys/` is public test material by construction** — the file carries a banner field stating so, and no value in it may ever be used outside tests. The file's shape (emitted by the generator since suite 0.2.0): `{"schema": "fieldseal-vectors/keys/v1", "banner": …, "keys": {"<key_ref>": {"label", "suite_id", "key_id", "tenant_dek", "tenant_index_key"}}, "context_defaults": {"table_uuid", "column_uuid", "tenant_id"}}`. Two refs ship: `tenant-a-dek-v1` (the tenant every pinned vector uses) and `tenant-b-dek-v1`. It is listed in `MANIFEST.support`, hashed like every family and never iterated by a harness.
- **Static cross vectors** (`cross/static/<impl>/`): regenerated by each implementation at each release using its *real production path* — runtime CSPRNG for `msg_seed` and nonce, no injection. Checked in. Every other implementation decrypts every case and compares plaintext. This is the offline, versioned form of the claim. *No release exists yet, so none are checked in; the dynamic exchange (below) runs in CI since 2026-08-23, from the shared `cross/corpus.json` inputs.*
- **Dynamic cross validation**: in CI, each implementation produces a fresh cross file as a build artifact; every other implementation consumes all of them (full N×N including self). Defined in `docs/14-conformance-ci.md`. CI MUST fail on any divergence (spec §12).
- Case set per producer: minimum 16 cases per supported suite spanning the same size/shape coverage as §4.1, plus at least one case per context shape (row_id present/absent, tenant present/absent).

---

## 5. Harness contract (per implementation)

Each language core ships a conformance harness (in its own test framework) that MUST:

1. Load `MANIFEST.json`, verify file hashes, and record `vector_suite_version`.
2. Validate every vector file against `vectors/schema/` before use (a malformed vector suite must fail loudly, not skip silently).
3. Run every vector for every family the implementation claims (0xFF02 families only if the suite is implemented).
4. For `envelope/`: assert both directions (§4.1).
5. For `errors/`: assert the **exact** error code — a mapping table from vector error strings to the language's exception/error types is part of each core's tech spec (`docs/10-…`, `docs/11-…`).
6. Report results in the machine-readable format defined in `docs/14-conformance-ci.md` §4, so the conformance report is assembled identically across languages.
7. Skip nothing silently: a skipped vector (unsupported suite) appears in the report as `skipped` with a reason.
8. Assert the spec §3.5 plaintext length bound out-of-band, since it has no vector (G10): a test MUST show that 2³¹ bytes is refused with `LENGTH_EXCEEDED`, and the harness MUST record the assertion in the report's `out_of_band` block (docs/14 §4). A harness that cannot allocate the input on its runtime records the reason there rather than passing silently — the point of the block is that an unverified bound is visible in the report instead of absent from it.
9. Where the implementation exposes the optional asynchronous companions of spec §11.1 (G9), run the entire suite a second time through them and assert identical bytes and identical error codes. Both passes appear in `results`, the async pass suffixed `#async`, so a divergence names which path failed.

## 6. Determinism injection (testing affordance)

To reproduce `envelope/` vectors, an implementation needs to encrypt with a caller-supplied `msg_seed` and `nonce`. Spec constraint (`vectors/README.md`): *"an implementation that accepts a caller-supplied nonce or seed outside of vector-test mode is non-conformant."*

Contract, binding on all core tech specs:

- The injection entry point is `encrypt_with_materials(plaintext, ctx, msg_seed, nonce) -> envelope`.
- It lives in a clearly separated testing namespace, **not** exported from the main module: Python `fieldseal.testing`, TypeScript subpath `@fieldseal/core/testing` (see the per-language specs).
- **Arming gate:** the testing namespace MUST be inert unless the environment variable `FIELDSEAL_TEST_MODE=1` is set — every function raises otherwise. A shipped module can always be imported; the gate makes accidental or lazy production use a loud failure instead of a silent non-conformance. Each per-language spec carries a negative test for the unarmed state.
- It performs the full production pipeline except CSPRNG generation — same KDF, same AAD, same commitment path — so vectors exercise the real code, not a parallel test path.
- The production `encrypt()` MUST NOT accept seed/nonce parameters in any form (no kwargs, no config hook, no environment variable).
- Documentation for the testing namespace states the non-conformance consequence verbatim.

## 7. Authoring and generation

- Vectors are **generated, reviewed, then frozen** — never hand-computed. A generator tool (`tools/vector-gen/`, Python, because Phase 1 builds the Python core first) produces every file from a single source of inputs.
- **Independent verification before freeze:** expected values MUST be confirmed by a second, independently-written computation before a vector file is tagged. Phase 1 provides this naturally: the TypeScript core is written against the frozen *inputs* and must reproduce the expected values without consulting the generator. Divergence at this step means either an implementation bug or a spec ambiguity — both are exactly what the suite exists to catch. The generator is not an oracle; agreement of two independent implementations is.
- Where an external, already-published vector exists for a primitive, the generator's primitive layer MUST be checked against it first. **Status of each source, re-verified 2026-08-22 (this bullet previously carried a flag saying they had not been):**
  - **HKDF-SHA-512** — RFC 5869's test vectors are SHA-256 and SHA-1 only, so only the structure is reusable, not the values. Unchanged from the original assessment.
  - **AES-256-GCM** — NIST CAVP GCM vectors apply directly. Not wired into the generator's primitive layer, which takes AES-GCM from `cryptography`; the generator's own GHASH/tag implementation (`gcm.py`, used only to build the salamander vector) is checked against `cryptography`'s tags at generation time, which is a consistency check, not a CAVP one. **[VERIFY]** a CAVP vector in the primitive layer remains open.
  - **XChaCha20-Poly1305** — no RFC vectors exist because the construction has no RFC (gap G7); libsodium's test suite is the de-facto source.
  - **Argon2id** — RFC 9106 §5.3's vector supplies a nonzero secret (`Secret[8]: 03 03 …`) and associated data (`Associated data[12]: 04 04 …`), both forbidden by spec §7.3 and unsuppliable from Python, so it cannot be the primitive check on this stack (the 2026-08-22 finding). **Substitute found and wired 2026-08-23:** libsodium's `test/default/pwhash_argon2id.c` `tv()` table with its `.exp` answers — seven Argon2id 1.3 cases through `crypto_pwhash`, which can supply neither `K` nor `X`, 16-byte salts, `p = 1`. `tools/vector-gen/fieldseal_vectorgen/kat_argon2id.py` vendors them and the generator checks its primitive against all seven on every run, refusing to emit if one fails. Separately, the TypeScript core's `node:crypto.argon2Sync` backend reproduces RFC 9106 §5.3 *with* `K`/`X` and all four held-out vectors (docs/18 D-15). The hold-out's stated unblocking condition is therefore met; whether to count the family is a project decision (§9).
- The Windows caveat: the repo pins LF via `.gitattributes` — the generator writes bytes, not platform-dependent text.

## 8. What is deliberately out of scope for the vector suite

- **Key-provider behavior** (caching, TTL, zeroization, KMS interaction) — not byte-reproducible; covered by per-language unit tests against the contracts in `docs/09-core-architecture.md` §8.
- **Adapter behavior** (throw lists, coverage matrices) — covered by per-adapter integration test plans (`docs/12-…`, `docs/13-…`); those tests are normative for adapter conformance claims but are not portable vectors.
- **Performance** — `bench/`, per PRD DO-4: measured, not estimated.

## 9. Spec gaps blocking vector authorship

Found while writing this document. Each needs a spec issue (per `CONTRIBUTING.md`: issue → citation → breakage statement → vectors). Consolidated with proposed resolutions in `docs/07-implementation-plan.md` §5; summarized here because they gate specific files above:

| # | Gap | Blocks |
|---|---|---|
| G1 | Key-commitment construction undefined (§4.6 mandates it; no formula) | `commitment/`, `envelope/` expected values, salamander error vector |
| G2 | Argon2id IDF invocation incomplete: parallelism, output length, salt/secret strategy, version not specified (§7.3 gives only iterations/memory minima) | `blind-index/argon2id.json` |
| G3 | `truncate(raw, b bits)` bit-level semantics — **resolved 2026-08-08** (issue #3): spec §7.2 pins leading `⌈b/8⌉` bytes, MSB-first bit numbering, trailing bits of the final byte zeroed | `blind-index/hmac.json` unblocked; `argon2id.json` still waits on G2 |
| G4 | `tenant_id = null` encoding in `canonical_context` unspecified (§6.2 defines omission only for `row_id`); null vs zero-length ambiguity | `context/`, any envelope vector with absent tenant |
| G5 | Error classification/precedence undefined: the order of format → policy → key → commitment → AEAD checks, and how a context mismatch (which manifests as a wrong derived key under dual binding) maps onto `AAD_MISMATCH` vs `COMMITMENT_INVALID` | most of `errors/crypto.json` |
| G6 | No error code for mode violations (`encrypt()` in `readonly` mode); `readonly`'s non-envelope read behavior undefined — **resolved 2026-08-09** (issue #6): spec §9 adds `MODE_VIOLATION`, §10.3 specifies both axes per mode (`readonly` = pass-through on non-envelope input, refuses `encrypt`/`rotate`, permits `blind_index`) | `errors/policy.json` fully unblocked |
| G7 | Suite 0xFF02's AEAD (XChaCha20-Poly1305) has no IETF RFC; the spec does not name a normative definition (libsodium's construction is the de-facto standard; draft-irtf-cfrg-xchacha expired) | `envelope/ff02.json` confidence, though not its mechanics |
| G8 | Blind-index *stored* representation undefined (raw bytes vs hex; column width) — two implementations sharing one database must store identical index values — **resolved 2026-08-09** (issue #8): spec §7.11 makes raw `⌈b/8⌉` bytes in a binary column the MUST, lowercase hex without prefix the declared-per-column MAY, exact byte/string equality under a binary collation | `blind-index/` storage assertions unblocked; the adapter specs' interim recommendation is now normative |

**Status 2026-08-22 — nothing in this document is blocked any longer, and one family is deliberately held out.** G3, G6 and G8 closed on their merits; G1, G2, G4, G5 and G7 are *provisionally adopted* under Gate 0a (PRD §8) and remain open on the tracker, which is enough for a generator to be written against them. `tools/vector-gen/` emits `context/`, `kdf/`, `commitment/`, `blind-index/` and `envelope/ff01.json`.

**Status 2026-08-23 — suite 0.2.0-provisional adds `errors/` (66 vectors in `format.json`, `policy.json`, `crypto.json`) and `keys/test-keys.json`; both cores pass 127/127 with identical result ids.** The `errors/` family became authorable once the two cores declared the same decrypt-path order (docs/14 §4 `pinned_decisions`); its G5- and G15-dependent outcomes carry `provisional_on`. Still not emitted: `cross/` (each core produces its own static file by its production path — docs/14 §3; the `keys/` format it needs now exists) and `envelope/ff02.json` / `commitment/ff02.json` (G7). `schema/` remains empty.

**`blind-index/argon2id.json` is generated but NOT part of the pinned suite — now pending a decision rather than a check.** When it was held out (2026-08-22) its primitive had never been checked against an external known-answer source; since 2026-08-23 it is checked against libsodium's seven published answers on every generator run (§7), and the TypeScript core reproduces the file's values through an independent backend. Both reference implementations would otherwise inherit the same unverified assumption from one generator and agree with each other while being wrong — which is precisely the failure the two-implementation rule exists to prevent, so agreement here would be evidence of nothing. `MANIFEST.json` carries it under `held_out` rather than omitting it, with the reason and the unblocking condition; the file itself carries `"status": "held-out"`. A conformance run MUST iterate `files` only (`docs/14` §4).

What a provisional adoption costs is regeneration, not redesign: if Gate 0b changes a construction, the affected family is regenerated and the provisional suite identifier retires (spec §4.8).
