# G2 — §7.3: The Argon2id index-derivation invocation is incompletely specified

**Labels:** §7.3 · spec-gap · blocks-vectors · needs-crypto-review
**Blocks:** `blind-index/argon2id.json` — every Argon2id vector.

## Gap

§7.3 requires Argon2id for enumerable domains with "minimum 3 iterations / 32 MiB", but a conforming implementation cannot be written from that alone. Unspecified: **parallelism** (p), **output length**, **Argon2 version** (0x13 vs 0x10), and — most importantly — **how the inputs map onto Argon2's parameter slots**. Argon2 (RFC 9106) takes password, salt, and optional secret-key and associated-data inputs. A blind index must be deterministic per key, but Argon2 *requires* a salt; the spec does not say where the salt comes from or where `index_key` enters.

Cross-language consequence: two implementations that both "use Argon2id 3/32MiB" but disagree on any of these produce different index values over the same database — the exact failure the project exists to prevent.

## Proposed direction (starting point, not a decision)

Pin the full tuple in §7.3, with RFC 9106 as the normative reference:

- Argon2id, version 0x13, p = 1, output length 64 bytes (input to §7.4 truncation).
- Iterations/memory: the existing minima become the *vector-pinned* parameters (t = 3, m = 32 MiB); deployments may raise them, but raised parameters are a new index (§7.8 immutability applies).
- **Input mapping:** password = `normalize(plaintext)`; salt = `HKDF(ikm = index_key, salt = "", info = "fieldseal-argon2-salt-v1", length = 16)` (deterministic per index key, satisfying Argon2's salt requirement without per-value randomness); secret (K parameter, RFC 9106 §3.1) = `index_key`. Keying through the K parameter keeps the index keyed even if the salt derivation is misused elsewhere.

## Justification

RFC 9106 §3.1 defines the parameter slots, including the optional secret value K ("used for keyed hashing"); §4 gives parameter-choice guidance. The keyed-deterministic construction (keyed memory-hard hash, deterministic salt) is the shape CipherSweet documents for its blind indexes. The rationale for memory-hardness on enumerable domains is already in §7.3 (Paragonie's chosen-plaintext analysis).

## What it breaks

Every Argon2id blind-index value. No index has been written, so nothing real breaks; after v1.0 this tuple is frozen (§7.8: changing it requires a new index column and full backfill).

## Vector obligations

- `blind-index/argon2id.json`: full-parameter vectors — (index_key, plaintext, normalizer, b) → raw 64-byte output → truncated index; including a non-ASCII value exercising the normalizer, and at least one b not divisible by 8 (couples to G3).
- A negative vector: same plaintext under a different `index-id` (different derived key, §7.2) must produce a different index.

## Review flag

**Needs cryptographic review.** Reviewer questions: is the deterministic HKDF-derived salt sound for this keyed use of Argon2id (no per-value salt by design — determinism is the point of a blind index); and is routing the key through K rather than concatenating into the password the right binding?
