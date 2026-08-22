# TypeScript Core Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the TypeScript/Node binding of `docs/09-core-architecture.md`. Second Phase 1 implementation; it is also the **independent verifier** of the Python-generated vectors before freeze (docs/08 §7), so it MUST be written against the vector inputs and the spec, not against the Python code.

**Library-fact caveat:** as in the Python spec, dependency claims are marked **[VERIFY]** where they must be re-confirmed at implementation time.

---

## 1. Package identity and toolchain

| Item | Decision | Notes |
|---|---|---|
| Package name | `@fieldseal/core` | Claim the npm `@fieldseal` scope before first publish (PRD naming note) |
| Runtime target | Node ≥ 20 LTS **[VERIFY current LTS floor at implementation]** | Server-only. Browser/edge runtimes are **explicitly out of scope for v0**: the sync API + KMS provider model presumes a server process, and Web Crypto's AEAD API is async-only, which conflicts with spec §11.1. Say this in the README rather than letting bundler users discover it |
| Language/build | TypeScript strict mode; `tsc` emit, no bundler | Small surface; keep the toolchain boring |
| Module format | ESM with `exports` map; CJS compatibility decided at implementation **[flag]** — TypeORM/older Prisma toolchains still commonly `require()`; if CJS is dropped, document the interop path | |
| Tests | vitest | Same harness contract as Python (docs/08 §5) |
| Lint/format | eslint + prettier (or biome — implementer's choice, pinned in repo config) | |

## 2. Dependencies

| Purpose | Dependency | Status |
|---|---|---|
| AES-256-GCM, HKDF-SHA-512, HMAC, CSPRNG, constant-time compare | `node:crypto` | `createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 })` + `setAAD`; `hkdfSync("sha512", …)`; `createHmac("sha512", …)`; `randomBytes`; `timingSafeEqual`. Zero external deps for suite 0xFF01. **[VERIFY]** `hkdfSync` salt/info argument order and output type against current Node docs |
| XChaCha20-Poly1305 (suite 0xFF02) | `@noble/ciphers`, optional peer/optional dependency | `node:crypto` supports `chacha20-poly1305` but **not** the XChaCha (24-byte-nonce) variant **[VERIFY]**. `@noble/ciphers` is audited, pure-JS, and implements the libsodium-compatible construction. Alternative: `sodium-native` (faster, native build cost). Decision deferred to implementation with this default: **@noble/ciphers**, because an optional suite should not impose a native toolchain |
| Argon2id **synchronous** raw output | **Open decision — the hardest dependency choice in either Phase 1 core.** Candidates: `sodium-native` (`crypto_pwhash` is sync, raw output, explicit salt) · `@node-rs/argon2` (**[VERIFY]** whether a sync raw-output API exists) · npm `argon2` (async-only API **[VERIFY]** — unusable for the sync §11.1 `blind_index` if so) | Abstract behind an internal `Argon2Backend` interface so the choice is swappable without API change. Blocked for expected values by spec gap G2 regardless |
| KMS wrappers | `@fieldseal/kms-aws` etc., separate packages | Same rule as Python: required dependency set for suite 0xFF01 is **empty beyond node:crypto** |

**Event-loop honesty (must appear in the package README):** a synchronous Argon2id blocks the Node event loop for 10–100 ms per query term (spec §7.3's quoted cost, measured at 4 iterations / 32 MiB — slightly above its 3-iteration minimum). That is far worse for Node than for threaded runtimes. Guidance: (a) confine Argon2id-indexed queries to worker threads at the application layer, or (b) prefer HMAC indexes where the domain class permits (§7.3 table).

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
  keyProvider,
  allowedSuites: [0xFF01],
  writeSuite: 0xFF01,
  readMode: "strict",
  cache: { maxAgeMs: 600_000, maxUses: 1_000_000, capacity: 10_000 },
  indexes: [ ... ],
});

fs.encrypt(pt: Uint8Array, ctx: FieldContext): Buffer      // sync
fs.decrypt(ct: Uint8Array, ctx: FieldContext): Buffer      // sync
fs.blindIndex(pt: Uint8Array, ctx: FieldContext): Buffer   // sync
fs.isCiphertext(v: Uint8Array): boolean                    // sync
fs.rotate(ct: Uint8Array, ctx: FieldContext): Buffer       // sync
await fs.warm(ctxs: Iterable<FieldContext>): Promise<void> // the only async method
```

- Inputs typed `Uint8Array` (accepts `Buffer`); returns `Buffer` (a `Uint8Array` subclass) per Node convention. **Strings are never accepted** — encoding is the adapter's job (docs/09 §5), and an implicit `utf8` coercion here is exactly the kind of cross-language divergence the vectors exist to catch.
- Errors: `FieldsealError` subclasses, each with `code` matching the §9 strings (`"TAG_INVALID"`, …) for the vector harness mapping.
- Method naming is the docs/09 §12 casing rule applied: `blindIndex`/`isCiphertext` are the camelCase renderings of the fixed operation names.

## 5. Security-relevant implementation notes

- **Zeroization honesty:** `Buffer.fill(0)` on evicted DEKs overwrites the visible allocation; V8 may have copied during prior operations and `node:crypto` may hold internal copies. Same honest-limitation wording rule as Python (docs/09 §8.3). No `mlock` (documented deviation).
- **Constant-time:** `crypto.timingSafeEqual` for commitment/tag-adjacent comparisons; it throws on length mismatch, so length-check first with a public-length rationale comment.
- **`Buffer` aliasing:** never return a `Buffer` that aliases an internal buffer (no `subarray` on cache-held material — always copy out).
- **Worker threads:** the client is safe to construct per-worker; DEK cache is per-instance and not shared across workers (no `SharedArrayBuffer` key storage — key material in a `SharedArrayBuffer` would widen the memory-exposure surface for no functional gain).

## 6. Testing plan

Mirrors the Python plan (docs/10 §6) with vitest: vector harness with schema validation and shared report format · both-direction envelope runs · exact error-code mapping · fuzz/property pass over the codec (`fast-check`) · cross-output producer script · a build-level test that `import "@fieldseal/core"` resolves no module under `testing/` · a runtime test that `encrypt_with_materials` throws when `FIELDSEAL_TEST_MODE` is unset.

One addition specific to this core's Phase 1 role: the **independence rule**. Until the first vector freeze, the TypeScript implementer works from `docs/02-spec-v0.1.md` + `docs/08` + `docs/09` only — no reading the Python source. Divergences found this way are the review mechanism working (docs/08 §7); record each in `docs/06-verification-log.md` style in the implementation plan's decision log.

## 7. Non-goals

No browser build, no Deno/Bun claims until CI covers them, no Prisma awareness (that's `adapters/prisma`), no WASM crypto fallbacks. Async companions to the five operations are permitted by spec §11.1 as of G9 but are **not** in the v0 scope; §2 states what would put `blindIndexAsync` in, and only it.
