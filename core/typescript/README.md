# @fieldseal/core (TypeScript / Node)

The TypeScript reference core for the Fieldseal specification
([`docs/02-spec-v0.1.md`](../../docs/02-spec-v0.1.md)): transparent field-level
encryption at the data-access layer, in a portable envelope that any conformant
core in any language can read.

**Status: provisional, unreviewed, not for production use.** This core
implements suite `0xFF01` (`FLE-AES256GCM-HKDF-SHA512-PROVISIONAL`). Every
identifier in the `0xFF00`–`0xFFFF` range is provisional (spec §4.8): its
constructions have not been independently reviewed (Gate 0b,
[`docs/01-prd.md`](../../docs/01-prd.md) §8) and may change. Writing under a
provisional suite therefore requires an affirmative arming act, described
below. This package is the M2 deliverable of
[`docs/17-m2-implementer-brief.md`](../../docs/17-m2-implementer-brief.md); the
divergence report it was built to produce is
[`docs/18-m2-report.md`](../../docs/18-m2-report.md).

## Requirements

- **Node ≥ 24.7.0** (`engines` is enforced). The floor is set by
  `crypto.argon2Sync`, which this core uses as its Argon2id backend with no
  external dependency; it requires OpenSSL ≥ 3.2 in the Node build.
- **Server-side only.** Browser and edge runtimes are out of scope: the five
  operations are synchronous by specification (§11.1) and Web Crypto's AEAD API
  is async-only. The two asynchronous companions below are additive — they do
  not make the core callable from a runtime without a synchronous AEAD.
- Zero runtime dependencies. `node:crypto` supplies AES-256-GCM, HKDF-SHA-512,
  HMAC-SHA-512, Argon2id, the CSPRNG and the constant-time compare.

## Usage

```ts
import { Fieldseal, DerivedKeyProvider } from "@fieldseal/core";

const fs = new Fieldseal(
  {
    keyProvider: new DerivedKeyProvider({ rootSecret, versions: [1], activeVersion: 1 }),
    allowedSuites: [0xff01], // explicit; there is no default (spec §4.3)
    writeSuite: 0xff01,
    readMode: "strict",      // strict | permissive | readonly (spec §10.3)
    indexes: [
      {
        tableUuid, columnUuid, indexId: "email-eq",
        idf: "hmac-sha512", normalize: "nfc-casefold-v1",
        truncateBits: 15, projectedPopulation: 100_000,
      },
    ],
    onWarning: (w) => log.warn(w.message),
  },
  // Spec §4.8: arming is a SEPARATE argument so a copied config cannot inherit it.
  { armProvisionalSuites: true },
);

const ctx = { tableUuid, columnUuid, tenantId, rowId: null, purpose: "encrypt" };
const envelope = fs.encrypt(plaintextBytes, ctx);   // Buffer, 111 + |plaintext| bytes
const plaintext = fs.decrypt(envelope, ctx);        // Buffer
const bidx = fs.blindIndex(plaintextBytes, { ...ctx, purpose: "index:email-eq" }); // ⌈b/8⌉ raw bytes
fs.isCiphertext(value);                              // boolean; never decrypts
fs.rotate(envelope, ctx);                            // fresh envelope under the active key
fs.unindexableMarker({ ...ctx, purpose: "index:email-eq" }); // this column's reserved bucket
await fs.warm([ctx]);                                // spec §11.2 prefetch; all KMS I/O lives here

// spec §11.1 asynchronous companions: the two Argon2id derivations, and only
// those. See "Argon2id blind indexes cost real time per query term" below.
await fs.blindIndexAsync(plaintextBytes, { ...ctx, purpose: "index:email-eq" });
await fs.unindexableMarkerAsync({ ...ctx, purpose: "index:email-eq" });
```

All five operations are synchronous and perform no I/O (spec §11.1). Inputs are
`Uint8Array`; outputs are `Buffer`. **Strings are not accepted by the envelope
operations** — an implicit UTF-8 coercion there is exactly the kind of
cross-language divergence the vector suite exists to catch. `blindIndex` is the
deliberate exception and takes text *or* bytes (docs/09 §7.1): index derivation
is the one operation whose answer depends on the difference between a string
and its encoding, because `TextEncoder` silently substitutes U+FFFD for an
unpaired surrogate — so a caller who encodes first has already collapsed two
distinct values into one index before this core is entered.

`blindIndexAsync` and `unindexableMarkerAsync` are the spec §11.1 companions to
the two Argon2id derivations: byte-identical output, the same §9 error for the
same condition (as a rejection), and the synchronous forms are **not**
implemented by blocking on them. The conformance report runs the entire vector
suite a second time through them (`async_companions: true`, 178 `#async`
results).

### Arming provisional writes (spec §4.8)

`encrypt()` and `rotate()` raise `SUITE_PROVISIONAL` unless the deployment has
armed provisional use by **either** passing `{ armProvisionalSuites: true }` as
the *second* constructor argument **or** setting
`FIELDSEAL_ARM_PROVISIONAL_SUITES=1` in the environment. A property inside the
config object does nothing — that is deliberate. `decrypt()`, `blindIndex()`
and `isCiphertext()` never require arming: reading data one has already
written is not what the gate exists to prevent. Arming does not make the suite
reviewed; it records that the operator was told.

### Errors

Every failure is a `FieldsealError` with a machine-readable `code` — the ten
spec §9 codes (`UNKNOWN_FORMAT_VERSION`, `SUITE_NOT_ALLOWED`,
`KEY_UNAVAILABLE`, `AAD_MISMATCH`, `TAG_INVALID`, `COMMITMENT_INVALID`,
`NOT_CIPHERTEXT`, `MODE_VIOLATION`, `LENGTH_EXCEEDED`, `SUITE_PROVISIONAL`)
plus two implementation-local ones that never describe envelope bytes:
`CONFIGURATION_ERROR` (construction-time refusals) and `INVALID_ARGUMENT`
(malformed non-byte call arguments). Arbitrary bytes handed to `decrypt()`
always resolve to a §9 code. Messages never contain plaintext or key material.

The decrypt-path precedence is pinned by this core under the still-open G5
question and declared verbatim in its conformance report
(`pinned_decisions.decrypt-order`). One consequence to know: **`AAD_MISMATCH`
is never raised on the `0xFF01` path.** Under dual-layer binding (§6.3) a wrong
context changes the derived key, so at decrypt time it is indistinguishable
from a wrong key and surfaces as `COMMITMENT_INVALID`.

### Key providers (spec §8)

| Provider | Use | Value-path I/O |
|---|---|---|
| `StaticKeyProvider` | tests and development only; the client warns through `onWarning` unless `FIELDSEAL_TEST_MODE=1` | none |
| `DerivedKeyProvider` | tenant DEK and sibling index key derived from a root secret with HKDF-SHA-512 under distinct labels; multiple versions, one active | none |
| `EnvelopeKeyProvider` | KMS-wrapped DEKs behind a `Wrapper { unwrap }` seam; **unwrap happens only in `warm()`**; the value path is cache-only and a miss is `KEY_UNAVAILABLE` | none |

## Honest limitations (required by the specification)

These are stated because the specification requires every implementation to
state them, and because the project's credibility rests on not overclaiming.

- **No protection against a compromised application process** (spec §2.2 N1).
  The keys are in that process. Anything the application can read, the
  adversary can read. Query logs, slow-query logs, the DBMS buffer cache and
  replication logs are sensitive artifacts and must be protected like the
  ciphertext (§2.3).
- **Storage overhead is real** (§3.3). Every envelope carries 111 bytes of
  fixed overhead under `0xFF01`: a 9-byte value becomes 120 bytes binary. This
  core is bytes-in/bytes-out and never emits base64; a deployment that stores
  base64 pays a further 33% on every row and must document it.
- **The key service is a hard dependency in the read path** (§8.1). With
  `EnvelopeKeyProvider`, every query touching an encrypted field depends on
  what `warm()` has loaded into the cache; a KMS outage means `KEY_UNAVAILABLE`
  for everything not cached. The degradation mode is recorded in the provider
  (`fail-closed` / `serve-cached`) and on the value path both mean the same
  thing: serve only what the cache can decrypt.
- **The DEK cache is an in-memory plaintext key cache** (§5.5). It is exposed
  to memory dumps, core files and swap. Zeroization on eviction is
  `Buffer.fill(0)` on the visible allocation; V8 may have copied the bytes and
  `node:crypto` may hold internal copies; there is no `mlock` for GC-managed
  memory. Cache TTL and max-uses are security parameters, not tuning knobs.
  Construct clients after forking in prefork servers.
- **Argon2id blind indexes cost real time per query term** (§7.3): roughly
  44–70 ms per term at the spec-minimum 3 iterations / 32 MiB, measured on two
  machines (docs/07 §7). **A synchronous derivation blocks the event loop** for
  that whole time, stalling every concurrent request in the process — twenty
  derivations let the loop take **one turn**. In order:
  1. Prefer `hmac-sha512` wherever the §7.3 domain class permits it —
     microseconds instead of milliseconds. §7.3 requires Argon2id precisely for
     the low-entropy domains where a blind index is most needed, so this is not
     available everywhere the problem is.
  2. Otherwise use `blindIndexAsync` / `unindexableMarkerAsync`, **and size
     `UV_THREADPOOL_SIZE` at or above the number of concurrent derivations.**
     The companion moves the cost to the libuv threadpool rather than removing
     it, and that pool is shared with `fs`, `dns` and `zlib`: four concurrent
     derivations against the default pool took an unrelated `fs.readFile` from
     p50 ~0.28 ms into the tens-to-hundreds of milliseconds on both machines.
     An under-sized pool delays unrelated work instead of index lookups, which
     is not an improvement.
  3. Worker threads remain possible and are not free here: the DEK cache is
     per-instance with no `SharedArrayBuffer` key storage, so a pool of four
     means four clients, four caches, four times the KMS unwrap traffic, and a
     `max_uses` counter fragmented across instances.
- **Blind indexes are filters, never answers** (§7.5). Candidates fetched by
  index must be decrypted and compared before being returned; pagination
  directly on an indexed column is incorrect (over-fetch → decrypt → filter →
  paginate).
- **What blind indexes do not support** (§7.10, reproduced as required):

  | Operation | Supported | Honest fallback |
  |---|---|---|
  | Equality | **Yes** | — |
  | Membership (`IN`) | **Yes** — N indexes OR'd | — |
  | Prefix | Gated, §7.9 | — |
  | `GROUP BY` / `DISTINCT` on an indexed column | Yes, groups by index including collisions | — |
  | Equi-join across encrypted columns | **No** | Keep the join key in plaintext |
  | Range, `<`, `>`, `ORDER BY` | **No** | A coarse plaintext bucket column with its own risk assessment, plus exact filtering after decryption |
  | `LIKE '%x%'`, regex | **No** | Decrypt-and-search over a bounded candidate set |
  | Full-text search | **No** | A separate search system, risk-assessed |
  | Aggregates (`SUM`, `AVG`) | **No** | Out of scope |
  | Unique constraints | **No** — not on randomized ciphertext, not on a blind index (§7.4 mandates collisions) | Application-level check inside a transaction, with the race documented (§7.10) |
  | Foreign keys | **No** | Keep the join key plaintext |

- **Cardinality gate** (§7.6): an index on a column with fewer than 2¹⁰ distinct
  values, or declared skewed, is refused at construction unless an explicit
  `cardinalityOverride { reason, approvedBy, date }` is given.
- **`nfc-casefold-v1`** uses vendored Unicode 17.0.0 tables for **both** NFC
  and full case folding, so an index value does not depend on the runtime's
  ICU. The conformance report records the platform's ICU/Unicode versions for
  information only, and names the vendored version it actually used. A value
  containing a code point the pinned version does not assign is refused, or —
  where the column declares it — bucketed under a reserved marker; it is never
  silently indexed under a substituted character.
- **Plaintext length** is bounded at 2³¹−1 bytes (§3.5); the bound is a
  ceiling, not a guarantee that a runtime can allocate it. Node 24's buffer
  maximum (2⁵³−1) is above the bound, so on this platform the spec bound is the
  binding one.
- **Suite `0xFF02`** is registered (recognized by `isCiphertext()`) but not
  implemented (gap G7); allow-listing it is refused at construction.

## Testing namespace

`@fieldseal/core/testing` exports `encrypt_with_materials(client, plaintext,
ctx, msgSeed, nonce)`, which runs the full production pipeline with
caller-supplied seed and nonce in place of the two CSPRNG draws. It is inert —
every call throws — unless `FIELDSEAL_TEST_MODE=1` is set. *An implementation
that accepts a caller-supplied nonce or seed outside of vector-test mode is
non-conformant* (`vectors/README.md`). The main entry never reaches this
module, and the production `encrypt()` takes no seed or nonce in any form.

## Developing

```
npm ci
npm test            # vitest: vector suite (both passes) + gates + totality +
                    # primitives + providers + async companions
npm run vectors     # emit the docs/14 §4 conformance report to stdout
npm run build       # tsc → dist/
npm run typecheck
```

The harness iterates `vectors/MANIFEST.json` `files` only and never
`held_out`. As of suite `0.6.0-provisional` the suite holds nothing out —
`blind-index/argon2id.json` was the last entry and is now pinned and counted
(`docs/07` §7), so a green run reports `held_out: 0`.
