# TypeScript Core Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the TypeScript/Node binding of `docs/09-core-architecture.md`. Second Phase 1 implementation; it is also the **independent verifier** of the Python-generated vectors before freeze (docs/08 §7), so it MUST be written against the vector inputs and the spec, not against the Python code.

**Library-fact caveat:** as in the Python spec, dependency claims are marked **[VERIFY]** where they must be re-confirmed at implementation time.

---

## 1. Package identity and toolchain

| Item | Decision | Notes |
|---|---|---|
| Package name | `@fieldseal/core` | Claim the npm `@fieldseal` scope before first publish (PRD naming note) |
| Runtime target | **Node ≥ 24.7** (`package.json` `engines`) — the floor is set by `crypto.argon2Sync`, which landed in 24.7; earlier drafts said ≥ 20 LTS with the floor to be verified | Server-only. Browser/edge runtimes are **explicitly out of scope for v0**: the sync API + KMS provider model presumes a server process, and Web Crypto's AEAD API is async-only, which conflicts with spec §11.1. Say this in the README rather than letting bundler users discover it |
| Language/build | TypeScript strict mode; `tsc` emit, no bundler | Small surface; keep the toolchain boring |
| Module format | ESM with `exports` map; CJS compatibility decided at implementation **[flag]** — TypeORM/older Prisma toolchains still commonly `require()`; if CJS is dropped, document the interop path | |
| Tests | vitest | Same harness contract as Python (docs/08 §5) |
| Lint/format | eslint + prettier (or biome — implementer's choice, pinned in repo config) | |

## 2. Dependencies

| Purpose | Dependency | Status |
|---|---|---|
| AES-256-GCM, HKDF-SHA-512, HMAC, CSPRNG, constant-time compare | `node:crypto` | `createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 })` + `setAAD`; `createHmac("sha512", …)`; `randomBytes`; `timingSafeEqual`. Zero external deps for suite 0xFF01. **HKDF is RFC 5869 over `createHmac`, not `hkdfSync` (revised 2026-08-22):** both `hkdfSync` and Web Crypto `deriveBits` refuse an `info` longer than 1024 bytes, and `info` here is `canonical_context`, whose `tenant_id`/`row_id` are unbounded (spec §6.1) — an envelope another core writes under a ~1 KiB context would be unreadable. Pinned to RFC 5869 A.1–A.3 and to `hkdfSync` on every input it accepts (`tests/primitives.test.ts`) |
| XChaCha20-Poly1305 (suite 0xFF02) | `@noble/ciphers`, optional peer/optional dependency | `node:crypto` supports `chacha20-poly1305` but **not** the XChaCha (24-byte-nonce) variant **[VERIFY]**. `@noble/ciphers` is audited, pure-JS, and implements the libsodium-compatible construction. Alternative: `sodium-native` (faster, native build cost). Decision deferred to implementation with this default: **@noble/ciphers**, because an optional suite should not impose a native toolchain |
| Argon2id **synchronous** raw output | **Decided at implementation: `node:crypto.argon2Sync`** (Node ≥ 24.7) — sync, raw output, explicit 16-byte salt, `parallelism` settable to 1, no `K`/`X` exposed, zero dependencies. The earlier candidates (`sodium-native`, `@node-rs/argon2`, npm `argon2`) are superseded; the 2026-08-22 narrowing that removed `K` from spec §7.3 is what made a no-dependency backend sufficient | Still behind an internal backend seam so a runtime without `argon2Sync` could be served by another backend without API change; the shipped core does not carry one |
| KMS wrappers | `@fieldseal/kms-aws` etc., separate packages | Same rule as Python: required dependency set for suite 0xFF01 is **empty beyond node:crypto** |

**Event-loop honesty (must appear in the package README):** a synchronous Argon2id blocks the Node event loop for 10–100 ms per query term (spec §7.3's quoted cost at its pinned `t = 3` / 32 MiB invocation; 41 ms measured with `argon2Sync` on 2026-08-23). That is far worse for Node than for threaded runtimes. Guidance: (a) confine Argon2id-indexed queries to worker threads at the application layer, or (b) prefer HMAC indexes where the domain class permits (§7.3 table).

**Async companion (`blindIndexAsync`) — now permitted, not yet decided.** G9 (issue #9) closed 2026-08-09: spec §11.1 allows optional async companions, so this core no longer needs a spec change to ship one. What it does need is evidence and a price. The price is fixed by §11.1 and docs/08 §5 clause 9: byte-identical output, identical error codes, the whole vector suite run a second time through the async path, and a sync `blindIndex` that is *not* a blocking wait on the async one. The evidence is the WS-C week-one benchmark (`docs/07-implementation-plan.md` §6) at spec-minimum Argon2id parameters — ship the companion if that benchmark shows the sync path is untenable in a real Prisma request path, and skip it if HMAC domains and worker threads cover the realistic cases. Naming is deliberately unpinned by the spec, so `blindIndexAsync` is this core's choice; if the benchmark says the sync path is untenable *at all* parameters, that is no longer an ergonomics question and goes back to the spec as a §7.3 issue.

## 3. Module layout

```
core/typescript/src/
  index.ts           exports: Fieldseal, FieldContext, errors, providers — no testing exports
  api.ts             Fieldseal client class
  envelope.ts        parse/serialize/isCiphertext
  registry.ts        frozen suite table
  context.ts         FieldContext, canonicalContext(), aad()
  kdf.ts
  aead/gcm.ts
  aead/xchacha.ts    lazy-imported so @noble/ciphers stays optional
  commitment.ts      pending G1
  blindindex.ts      pending G2 for argon2id; hmac path complete (truncate pinned, spec §7.2)
  keyprovider.ts
  cache.ts
  config.ts
  errors.ts
  testing/index.ts   exposed ONLY via the "./testing" subpath export; inert unless armed —
                     every function throws unless FIELDSEAL_TEST_MODE=1 is set (docs/08 §6)
```

`package.json` `exports`: `"."` → main API; `"./testing"` → `encrypt_with_materials` (docs/08 §6 — deliberately snake_case, contrary to local convention: docs/09 §12 fixes the *same function name* across languages so the injection surface is greppable in any repo). The main entry has no code path that reaches `testing/`, and the testing module's doc comment carries the consequence verbatim: *"an implementation that accepts a caller-supplied nonce or seed outside of vector-test mode is non-conformant"* (`vectors/README.md`).

## 4. Public API shape

```ts
import { Fieldseal, FieldContext } from "@fieldseal/core";

const fs = new Fieldseal({
  keyProvider,   // EnvelopeKeyProvider carries the §5.5 cache policy in its own options
  allowedSuites: [0xFF01],
  writeSuite: 0xFF01,
  readMode: "strict",
  indexes: [ ... ],
});

fs.encrypt(pt: Uint8Array, ctx: FieldContext): Buffer      // sync
fs.decrypt(ct: Uint8Array, ctx: FieldContext): Buffer      // sync
fs.blindIndex(v: string | Uint8Array, ctx: FieldContext): Buffer  // sync; text OR bytes
fs.isCiphertext(v: Uint8Array): boolean                    // sync
fs.rotate(ct: Uint8Array, ctx: FieldContext): Buffer       // sync
await fs.warm(ctxs: Iterable<FieldContext>): Promise<void> // the only async method

// docs/09 §2 configuration reflection
fs.readMode: ReadMode
fs.writeSuite: number
fs.allowedSuites: ReadonlySet<number>
fs.provisionalArmed: boolean
fs.indexes: ReadonlyMap<string, ValidatedIndex>   // keyed by indexRegistryKey(...)
```

- Inputs typed `Uint8Array` (accepts `Buffer`); returns `Buffer` (a `Uint8Array` subclass) per Node convention. **Strings are not accepted — except by `blindIndex`, which requires them** (docs/09 §7.1; G16 part A). An implicit `utf8` coercion on the *envelope* operations would be exactly the cross-language divergence the vectors exist to catch, and that reasoning still holds for `encrypt`, `decrypt`, `rotate` and `isCiphertext`. It does not hold for index derivation, and inverting there was the point of G16 part A: `TextEncoder` substitutes U+FFFD for an unpaired surrogate rather than failing, so a caller who encodes first has already collapsed two distinct values into one before this core is entered. Passing the string keeps the refusal where the information still exists. This core previously refused strings with a message directing callers to encode themselves, which named the lossy conversion as the supported route.
- **The `encrypt`/`blindIndex` asymmetry is intended.** Normalization is a text operation; encryption is not. Index derivation is the only operation whose answer depends on the difference between a string and its encoding, so it is the only one that needs to see the string. The Python core has had the same asymmetry (`encrypt(plaintext: bytes)` against `blind_index(value: str | bytes)`) since it was written; this core now matches it rather than diverging from it.
- Well-formed text and its own encoding must produce the same index — the widening must not fork the function. `tests/index-boundary.test.ts` pins that, together with the distinguishable refusal of two different unpaired surrogates.
- Deviation from docs/09 §2's config sketch: there is **no client-level `cache` field**. The §5.5 cache policy is `EnvelopeKeyProvider`'s own required `cache` option (docs/09 §2's "required for EnvelopeKeyProvider", enforced at provider construction); a `cache` key present in the client config is refused with a `ConfigurationError` rather than accepted and ignored.
- Errors: `FieldsealError` subclasses, each with `code` matching the §9 strings (`"TAG_INVALID"`, …) for the vector harness mapping.
- Method naming is the docs/09 §12 casing rule applied: `blindIndex`/`isCiphertext` are the camelCase renderings of the fixed operation names.
- **Configuration reflection (docs/09 §2).** The first four accessors predate G18; `indexes` is what that issue added, and it is the one an adapter needs — before it, `docs/12` §5's E006 registry check was unimplementable in this language *at all*, not merely awkwardly: `#cfg` is a hard private field on an instance the constructor freezes, so there is no bad option to fall back on the way Python's `_indexes` offers one. `ValidatedIndex`, `validateIndexDeclaration` and `indexRegistryKey` are exported for the comparison. **Two runtime guarantees are load-bearing here and neither comes from a type.** `indexes` returns `new Map(this.#cfg.indexes)`, because `ReadonlyMap` is erased at runtime and one `as Map` cast on the live registry would let any caller clear it; the copy is O(declared indexes) on a startup-time call, never a value-path one. And `validateIndexDeclaration` freezes what it returns, because `readonly` on an interface member is a compile-time claim only — a caller with the record in hand could otherwise rewrite `truncateBits` through a single cast and change what the client derives.

## 5. Security-relevant implementation notes

- **Zeroization honesty:** `Buffer.fill(0)` on evicted DEKs overwrites the visible allocation; V8 may have copied during prior operations and `node:crypto` may hold internal copies. Same honest-limitation wording rule as Python (docs/09 §8.3). No `mlock` (documented deviation). **Provider-returned material is never zeroized by the core**, on either path — not the candidate arrays from `decryptionKeys` and not the key from `encryptionKey`. This is now the rule rather than an exception: docs/09 §8.1 makes that material provider-owned, on the reasoning this binding's decrypt path had already recorded in a comment (a custom provider may return a reference to a buffer it still needs). **The mechanism that makes this true on the write path is the defensive copy in `#encryptionKey`** (`api.ts:182`): it validates the provider's return — key length, `key_id` length, provider exceptions mapped to `KEY_UNAVAILABLE` — and hands back `new Uint8Array(ek.key)`, so the later `ek.key.fill(0)` erases the core's own copy and never the provider's buffer. The same helper serves the blind-index path (`api.ts:307`). That copy is **load-bearing and must not be refactored away**: without it, `.fill(0)` would destroy the material of any provider that returns a reference to its own cache. Under G17 (issue [#67](https://github.com/fieldseal-dev/fieldseal-spec/issues/67)) it stops being incidental — `providers.test.ts` ("key-material ownership") drives all three paths with a provider that deliberately hands out references and asserts its buffers survive. The cost of the rule is that the shipped providers' per-call copies reach GC unzeroized — copies of material the cache holds and erases on eviction anyway. **What the core does zeroize is what it derived itself:** the record key on both paths, the intermediate plaintext buffer, and the untruncated IDF output. Note that `readonly key: Uint8Array` on `EncryptionKey` does not enforce any of this — TypeScript's `readonly` is shallow, so `ek.key.fill(0)` type-checks; the rule is a specification obligation, and the regression test in `providers.test.ts` is what actually holds it.
- **Constant-time:** `crypto.timingSafeEqual` for commitment/tag-adjacent comparisons; it throws on length mismatch, so length-check first with a public-length rationale comment.
- **`Buffer` aliasing:** never return a `Buffer` that aliases an internal buffer (no `subarray` on cache-held material — always copy out). "Internal" includes Node's shared `Buffer` pool: `Buffer.from(bytes)` and small `Buffer.allocUnsafe` allocations are views into a pool `ArrayBuffer` shared with unrelated allocations, reachable from the returned value as `.buffer`. Every `Buffer` the client returns is therefore an unpooled `Buffer.alloc` copy whose `ArrayBuffer` is exactly the returned bytes.
- **Worker threads:** the client is safe to construct per-worker; DEK cache is per-instance and not shared across workers (no `SharedArrayBuffer` key storage — key material in a `SharedArrayBuffer` would widen the memory-exposure surface for no functional gain).

## 6. Testing plan

Mirrors the Python plan (docs/10 §6) with vitest: vector harness with schema validation and shared report format · both-direction envelope runs · exact error-code mapping · fuzz/property pass over the codec (`fast-check`) · cross-output producer script · a build-level test that `import "@fieldseal/core"` resolves no module under `testing/` · a runtime test that `encrypt_with_materials` throws when `FIELDSEAL_TEST_MODE` is unset.

One addition specific to this core's Phase 1 role: the **independence rule**. Until the first vector freeze, the TypeScript implementer works from `docs/02-spec-v0.1.md` + `docs/08` + `docs/09` + this document only — **no reading `core/python/**` or `tools/vector-gen/**`**. Divergences found this way are the review mechanism working (docs/08 §7); record each in `docs/06-verification-log.md` style in the implementation plan's decision log.

The rule is now a protocol rather than a sentence: [`docs/17-m2-implementer-brief.md`](17-m2-implementer-brief.md) is the handoff to give the implementer, and it carries the prohibition, the reading path, the order-of-work rule that keeps a mismatch from being quietly tuned away, and the deliverables. Hand that over rather than paraphrasing this paragraph — the paraphrase is where the order-of-work rule gets dropped, and it is the part that does the work.

## 7. Non-goals

No browser build, no Deno/Bun claims until CI covers them, no Prisma awareness (that's `adapters/prisma`), no WASM crypto fallbacks. Async companions to the five operations are permitted by spec §11.1 as of G9 but are **not** in the v0 scope; §2 states what would put `blindIndexAsync` in, and only it.
