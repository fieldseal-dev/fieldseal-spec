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

## Portability finding (2026-08-22) — Argon2's `K` is not portable

**Verified against primary sources while preparing outreach on this issue.** The proposed direction routes `index_key` through RFC 9106's optional secret parameter `K`. That parameter is not reachable in much of the ecosystem, and the gap does not fall where the project needs it to:

| Binding | Exposes Argon2's `K`? | Evidence |
|---|---|---|
| libsodium `crypto_pwhash` | **No** — no secret parameter in the API at all | [libsodium docs](https://doc.libsodium.org/password_hashing/default_phf); parameters are `out`, `outlen`, `passwd`, `passwdlen`, `salt`, `opslimit`, `memlimit`, `alg` |
| Python `argon2-cffi` | **No**, in any supported API | [API docs](https://argon2-cffi.readthedocs.io/en/stable/api.html): `hash_secret_raw(secret, salt, time_cost, memory_cost, parallelism, hash_len, type, version)` where `secret` is the **password**. `K` is reachable only via the ultra-low-level `core()` call with hand-built CFFI structs, which the docs explicitly warn against |
| Node `node-argon2` | **Yes**, as `secret` | [Options wiki](https://github.com/ranisalt/node-argon2/wiki/Options): "Also known as 'pepper' … additional data used in the hashing process that does not get included in the hash like the salt" |

**Why this is a project-level problem, not a packaging detail.** Python and TypeScript are the two Phase 1 cores, and the central claim is byte-identical output across them. A construction the TypeScript core can express and the Python core cannot is not a dependency inconvenience — it is the claim failing before any code is written. `docs/10` §2 and `docs/11` §2 now carry this constraint; for TypeScript it disqualifies `sodium-native` outright, which was a leading candidate for the sync raw-output requirement.

**A naming trap worth recording separately.** argon2-cffi's `secret=` keyword means the *password*, while RFC 9106's "secret" means `K`. An implementer working from the RFC and the library at the same time can satisfy both readings and be wrong, with no error raised and a silently divergent index value. Any resolution of this issue must state which sense is meant at every use.

**Prior art points the other way.** CipherSweet's slow blind index uses Argon2id "where the blind index key is the Argon2 salt" — the construction this issue proposes to replace. That may be a considered cryptographic choice or a consequence of libsodium's API; the two readings imply different resolutions here, and the question has been put to its author. Outcome to be recorded in `docs/16-reviewer-brief.md` §4.

## Justification

RFC 9106 §3.1 defines the parameter slots, including the optional secret value K ("used for keyed hashing"); §4 gives parameter-choice guidance. The keyed-deterministic construction (keyed memory-hard hash, deterministic salt) is the shape CipherSweet documents for its blind indexes. The rationale for memory-hardness on enumerable domains is already in §7.3 (Paragonie's chosen-plaintext analysis).

## What it breaks

Every Argon2id blind-index value. No index has been written, so nothing real breaks; after v1.0 this tuple is frozen (§7.8: changing it requires a new index column and full backfill).

## Vector obligations

- `blind-index/argon2id.json`: full-parameter vectors — (index_key, plaintext, normalizer, b) → raw 64-byte output → truncated index; including a non-ASCII value exercising the normalizer, and at least one b not divisible by 8 (couples to G3).
- A negative vector: same plaintext under a different `index-id` (different derived key, §7.2) must produce a different index.

## Review flag

**Needs cryptographic review.** Reviewer questions: is the deterministic HKDF-derived salt sound for this keyed use of Argon2id (no per-value salt by design — determinism is the point of a blind index); and is routing the key through K rather than concatenating into the password the right binding?

**Third question added 2026-08-22, and it may dominate the other two:** given that `K` is unreachable in Python (see the portability finding above), is `K` worth insisting on? Concretely — if the alternatives are (a) `K = index_key` with a Python implementation that cannot conform, (b) CipherSweet's salt-as-key, or (c) an explicit domain-separated concatenation into the password, which is cryptographically defensible? This is no longer only a soundness question; it is a soundness question with one option ruled out on portability grounds, which is a materially different thing to ask.
