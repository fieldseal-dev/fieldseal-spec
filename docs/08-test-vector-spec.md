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
    test-keys.json         shared, PUBLIC test key material referenced by key_ref (never real keys)
  envelope/
    0001.json              suite 0x0001 round trips
    0002.json              suite 0x0002 round trips (consumed only by implementations claiming 0x0002)
  kdf/
    record-key.json
    index-key.json
  context/
    canonical.json
  blind-index/
    hmac-sha512.json
    argon2id.json
  commitment/
    0001.json
    0002.json
  errors/
    format.json            structural failures: truncation, unknown fmt_ver, unregistered suite
    policy.json            allow-list, read-mode cases
    crypto.json            tag flips, AAD alteration, commitment mismatch, salamander case
  cross/
    keys → ../keys/test-keys.json (by reference, not symlink — see §4.7's key_ref rule)
    static/
      python/0001.json     envelopes produced by each released implementation
      typescript/0001.json
```

`MANIFEST.json` carries a semver `vector_suite_version`. Implementations record the version they were validated against in their conformance claim (see `docs/14-conformance-ci.md`).

---

## 3. Encoding conventions (normative for vector files)

| Value | Encoding | Rationale |
|---|---|---|
| All binary values (keys, seeds, nonces, ciphertexts, contexts, UUID surrogates) | Lowercase hex, no `0x` prefix, even length | Matches `vectors/README.md`; unambiguous, diff-friendly |
| `suite_id` | String `"0x0001"` (4 hex digits, `0x` prefix) | Matches the existing README example; visually distinct from binary blobs |
| `fmt_ver` | String `"0x01"` | Same convention as `suite_id` |
| Absent optional value (`row_id`, `tenant_id`) | JSON `null` | Distinct from empty: `""` (hex) means *present with zero length*. See gap G4 in §9 — the spec must define whether zero-length and null are distinct on the wire before vectors covering that case are authored. |
| Text values (`purpose`, normalization names, error codes) | JSON string, ASCII | `purpose` is a protocol string, not user text |
| Sizes/lengths | JSON integer, bytes unless the field name says `_bits` | Truncation length `b` is in bits per spec §7.4 |

Vector files are UTF-8, LF line endings (repo `.gitattributes` pins LF), 2-space indent, keys in the order given by the schema — so that regenerated files diff cleanly.

---

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

- `id` — stable string, grammar: `<family>/<file-stem>/<slug>` where `slug` matches `[a-z0-9-]{1,64}`. Example: `envelope/0001/basic-roundtrip`. Never reused, even after retirement.
- `description` — one sentence, for failure messages.
- `spec_ref` — the section(s) the vector exercises, e.g. `"§3.1, §4.2"`.

### 4.1 `envelope/` — encrypt/decrypt round trips

Input state is complete: no key provider, no cache, no modes — this family tests the cryptographic core in isolation.

```json
{
  "id": "envelope/0001/basic-roundtrip",
  "description": "9-byte plaintext, tenant context, row_id absent",
  "spec_ref": "§3.1, §4.2, §5.3, §6.2, §6.3",
  "suite_id": "0x0001",
  "tenant_dek": "…64 hex chars (32 B)…",
  "key_id": "…32 hex chars (16 B)…",
  "msg_seed": "…64 hex chars (32 B)…",
  "nonce": "…24 hex chars (12 B for 0x0001)…",
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

Minimum case coverage per suite: empty plaintext (0 B) · 1 B · a 9-byte SSN-shaped value · a 1 KiB value · a value crossing an AEAD block boundary · `row_id` present · `row_id` absent · `tenant_id` present · multi-byte UTF-8 plaintext (as raw bytes — the core is bytes-in/bytes-out) · maximum-length `purpose` string.

### 4.2 `kdf/` — key derivation

```json
{
  "id": "kdf/record-key/row-id-absent",
  "spec_ref": "§5.3",
  "suite_id": "0x0001",
  "tenant_dek": "…hex…",
  "key_id": "…hex…",
  "msg_seed": "…hex…",
  "context": { ... },
  "expected": { "record_key": "…hex…" }
}
```

`kdf/index-key.json` mirrors it with `tenant_index_key` as input, `purpose` of the form `"index:<index-id>"`, `row_id` forced null (spec §7.2), and `expected.index_key`. Include two vectors differing **only** in the index identifier (`index:exact` vs `index:prefix3`) to pin the §7.2 distinctness rule, and two differing only in `column_uuid` to pin per-column separation.

### 4.3 `context/` — canonical encoding

Byte-exact `canonical_context` and `AAD` outputs for representative contexts. This family exists so an implementation can debug encoding independently of any cryptography.

Required cases: all fields present · `row_id` null (omitted entirely per §6.2) · `tenant_id` at boundary lengths (1 B, 16 B, 64 B) · `purpose` = `"encrypt"` and `"index:exact"` · a context whose fields contain bytes that would be misparsed under naive concatenation (e.g. a `tenant_id` ending in bytes that look like a `u64be` length prefix) — this is the anti-forgery case that justifies §6.2.

**Grammar refusals (G11, issue #11, resolved 2026-08-09):** spec §6.1 now constrains `index-id` to `[a-z0-9-]{1,32}`, so this family also carries negative *declarations* — `index:Exact` (uppercase), `index:é` (non-ASCII), `index:` (empty), and a 33-byte identifier. These pin a refusal at index-declaration time, not an error code: configuration validation sits outside the §9 taxonomy, so the vector asserts that the declaration is rejected and deliberately does not name a code (each core maps it to its own `ConfigurationError`, docs/09 §9). They belong here rather than in `errors/` for that reason.

**Blocked case:** `tenant_id` null vs zero-length — see gap G4 (§9). Do not author until the spec defines the encoding.

### 4.4 `blind-index/`

```json
{
  "id": "blind-index/hmac-sha512/email-15bit",
  "spec_ref": "§7.2, §7.3, §7.4, §7.11",
  "idf": "hmac-sha512",
  "idf_params": {},
  "index_key": "…hex (32 B)…",
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

- `plaintext` is the post-normalization byte string and is the normative input; `plaintext_preimage` documents where it came from and lets an implementation that ships the named normalizer test it too. Normalizer identifiers (`nfc-casefold-v1`, …) are declared in `docs/09-core-architecture.md` §7; the vector suite only ever references declared identifiers.
- `expected.stored` asserts the spec §7.11 storage contract (G8, issue #8). `stored.binary` MUST equal `expected.index` byte for byte and `stored.octets` MUST equal `⌈b/8⌉`; the redundancy is deliberate, because it converts an assumption every implementation would otherwise make silently into a test that fails when one of them pads, length-prefixes, or base64s the column. `stored.hex` is the lowercase text-column form for implementations supporting that alternative — a harness whose implementation is binary-only skips `stored.hex` and reports it skipped, but MUST assert `stored.binary` and `stored.octets`.
- Argon2id vectors carry full `idf_params`: `{"version": 19, "time_cost": …, "memory_kib": …, "parallelism": …, "output_len": 32, "salt": "…hex…"}`. Most Argon2id vectors use **reduced parameters** (small memory/time) so CI stays fast; at least one vector per file MUST use the spec-minimum production parameters (≥3 iterations / 32 MiB, spec §7.3) so the production configuration path is exercised.
- **Blocked (G2 only):** the exact Argon2id invocation (what is password vs salt vs secret, parallelism, output length) is not defined by spec v0.1 — gap G2 in §9. The bit-level truncation rule is now pinned (spec §7.2, G3 resolved 2026-08-08: leading `⌈b/8⌉` bytes, trailing bits of the final byte zeroed, MSB-first), so `blind-index/hmac.json` is fully authorable including truncated expected values. Per spec §12, each file carries at least three `b mod 8 ≠ 0` vectors (e.g. b = 12, 21, 30) plus one multiple-of-8 control. Argon2id expected values wait on G2.

### 4.5 `commitment/`

Key material + envelope inputs → expected 32-byte commitment. **Fully blocked by gap G1** (§9): spec §4.6 mandates a commitment and §3.1 reserves 32 bytes, but no construction is defined. The file layout is reserved; authoring waits on the spec issue.

### 4.6 `errors/`

```json
{
  "id": "errors/crypto/tag-bit-flip",
  "spec_ref": "§9",
  "suite_id": "0x0001",
  "config": {
    "allowed_suites": ["0x0001"],
    "read_mode": "strict",
    "registered_suites": ["0x0001", "0x0002"]
  },
  "tenant_dek": "…hex…",
  "context": { ... },
  "input": "…hex, the (possibly malformed) envelope bytes…",
  "derived_from": "envelope/0001/basic-roundtrip",
  "mutation": "flip bit 0 of tag byte 0",
  "expected": { "error": "TAG_INVALID" }
}
```

- `input` is always literal bytes — `derived_from`/`mutation` are documentation, not instructions; harnesses never compute mutations.
- `config` makes policy explicit because several errors are policy-dependent (`SUITE_NOT_ALLOWED` requires a suite that is registered but not allow-listed; `NOT_CIPHERTEXT` in `strict` vs the pass-through expectation in `permissive`).
- Permissive-mode vectors use `"expected": { "value": "…hex…" }` instead of an error, pinning the pass-through behavior of §10.3.

Required error coverage (each case = one or more vectors):

| Case | Expected error | Notes |
|---|---|---|
| Envelope shorter than minimum length; empty input; truncation at every field boundary (mid-`key_id`, mid-`msg_seed`, mid-nonce, mid-tag, mid-commitment) | `NOT_CIPHERTEXT` | Per spec §3.4 recognition rules |
| ASCII plaintext presented in `strict` mode | `NOT_CIPHERTEXT` | The migration-accident case |
| Same input in `permissive` mode | pass-through value | With the §10.3 warning requirement noted |
| `fmt_ver` = `0x00`, `0x02`, `0xff` on an otherwise valid envelope | **[blocked by G5]** | docs/09 §3.2 proposes `UNKNOWN_FORMAT_VERSION` only for reserved-known-future version bytes (e.g. `0x02`) and `NOT_CIPHERTEXT` (strict) / pass-through (permissive) for the rest (`0x00`, `0xff`) — spec §3.4 makes recognition require a *recognized* version. The split is pinned by the G5 issue |
| `suite_id` unregistered (e.g. `0x00ff`) | `NOT_CIPHERTEXT` | Recognition, not authorization — §3.4 |
| `suite_id` registered but not on allow-list | `SUITE_NOT_ALLOWED` | The §3.4 decoupling case: recognition must succeed |
| `key_id` unknown to the provider | `KEY_UNAVAILABLE` | |
| Each AAD-relevant context field altered on decrypt (wrong tenant, wrong column, wrong row, wrong purpose) | `AAD_MISMATCH` **[blocked by G5]** | Under the current construction a context mismatch surfaces at the KDF/commitment layer; classification needs the error-precedence spec issue |
| Single bit flips in ciphertext; in tag | `TAG_INVALID` | |
| Commitment bytes altered | `COMMITMENT_INVALID` | |
| A ciphertext valid under two keys (invisible salamander) | `COMMITMENT_INVALID` | Requires a dedicated construction script during vector authoring, following Len–Grubbs–Ristenpart (USENIX '21); this is the vector that proves §4.6 does its job |
| `msg_seed` altered | **[blocked by G5]** — self-authenticating per §3.2; whether it reports `COMMITMENT_INVALID` or `TAG_INVALID` depends on check order | |
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
  "suite_id": "0x0001",
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

- `key_ref` resolves into `vectors/keys/test-keys.json` so producers and consumers share key material without embedding it per file. **Everything in `keys/` is public test material by construction** — the file carries a banner field stating so, and no value in it may ever be used outside tests.
- **Static cross vectors** (`cross/static/<impl>/`): regenerated by each implementation at each release using its *real production path* — runtime CSPRNG for `msg_seed` and nonce, no injection. Checked in. Every other implementation decrypts every case and compares plaintext. This is the offline, versioned form of the claim.
- **Dynamic cross validation**: in CI, each implementation produces a fresh cross file as a build artifact; every other implementation consumes all of them (full N×N including self). Defined in `docs/14-conformance-ci.md`. CI MUST fail on any divergence (spec §12).
- Case set per producer: minimum 16 cases per supported suite spanning the same size/shape coverage as §4.1, plus at least one case per context shape (row_id present/absent, tenant present/absent).

---

## 5. Harness contract (per implementation)

Each language core ships a conformance harness (in its own test framework) that MUST:

1. Load `MANIFEST.json`, verify file hashes, and record `vector_suite_version`.
2. Validate every vector file against `vectors/schema/` before use (a malformed vector suite must fail loudly, not skip silently).
3. Run every vector for every family the implementation claims (0x0002 families only if the suite is implemented).
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
- Where an external, already-published vector exists for a primitive (HKDF-SHA-512 — RFC 5869 test vectors are SHA-256 only, so only structural reuse; Argon2id — RFC 9106 §5.3 test vector; AES-256-GCM — NIST CAVP GCM vectors; XChaCha20-Poly1305 — no RFC vectors exist, the construction has no RFC; libsodium's test suite is the de-facto source, see gap G7), the generator's primitive layer MUST be checked against it first. **[Flag: the primitive-vector sources named here were not re-verified against current publications; confirm during vector authoring.]**
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
| G7 | Suite 0x0002's AEAD (XChaCha20-Poly1305) has no IETF RFC; the spec does not name a normative definition (libsodium's construction is the de-facto standard; draft-irtf-cfrg-xchacha expired) | `envelope/0002.json` confidence, though not its mechanics |
| G8 | Blind-index *stored* representation undefined (raw bytes vs hex; column width) — two implementations sharing one database must store identical index values — **resolved 2026-08-09** (issue #8): spec §7.11 makes raw `⌈b/8⌉` bytes in a binary column the MUST, lowercase hex without prefix the declared-per-column MAY, exact byte/string equality under a binary collation | `blind-index/` storage assertions unblocked; the adapter specs' interim recommendation is now normative |

Nothing else in this document is blocked: file formats, schemas, harness contract, injection contract, cross protocol, and the `errors/format.json` + `errors/policy.json` families can be built immediately — `errors/policy.json` in full, now that G6 has closed.
