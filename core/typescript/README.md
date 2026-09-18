# @fieldseal/core (TypeScript / Node)

Field-level encryption for Node applications, with a format that other
languages can read.

> **Experimental release: not independently reviewed, not for production data.**
> The cryptographic design this package implements has not been reviewed by
> anyone outside the project. It is pre-1.0: the stored format may change
> before 1.0, and data written with it now may have to be re-encrypted if
> review changes a construction. Writing refuses until you explicitly arm
> provisional use (spec §4.8). This release is for evaluation and feedback;
> the terms it is published under are in [PRD §8](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/01-prd.md#8-scope-and-phasing).

`@fieldseal/core` encrypts individual values, such as a column in a database
row, inside your application, so the database and its backups hold only
ciphertext. It also derives **blind indexes**, short keyed hashes that let you
find a row by an encrypted value without decrypting the whole table.

It is the TypeScript core of [Fieldseal](https://fieldseal.dev), an open
specification for field-level encryption. What it writes, the
[Python core](https://pypi.org/project/fieldseal/) can read, and the reverse.
Most applications use it through an ORM adapter instead:
[`@fieldseal/prisma`](https://www.npmjs.com/package/@fieldseal/prisma) for
Prisma.

## Features

- **Authenticated encryption with key commitment.** AES-256-GCM, with a fresh
  key derived for every value, and a commitment that makes decrypting under
  the wrong key fail instead of producing garbage.
- **Context binding.** Each value is bound to its table, column and, if you
  use one, tenant. Moving a ciphertext to another column or tenant makes it
  fail to decrypt.
- **Blind indexes** for equality lookups, with Argon2id or HMAC-SHA-512 and
  three normalizers (case-insensitive, exact, digits only).
- **Key rotation.** Several key versions can be valid at once, and `rotate()`
  re-encrypts a value under the active one.
- **Three key providers**: static for tests, derived from a root secret, and
  KMS-wrapped keys unwrapped ahead of time so encryption never waits on the
  network.
- **Zero runtime dependencies.** Everything comes from `node:crypto`.
- **Cross-language.** The same test vectors pin this core and the Python core,
  and CI checks on every run that each decrypts what the other wrote.

## Requirements

- **Node 24.7 or later**, built with OpenSSL 3.2 or later. The floor comes
  from `crypto.argon2Sync`, which this core uses for Argon2id.
- **Server-side only.** Browsers and edge runtimes are not supported: the
  core's operations are synchronous, and Web Crypto's AES-GCM is async-only.

## Install

```sh
npm install @fieldseal/core
```

## Quickstart

```ts
import { randomBytes } from "node:crypto";
import { Fieldseal, DerivedKeyProvider } from "@fieldseal/core";

// Fixed identifiers for the table and column. Never derive them from names.
const uuid = (s: string) => Buffer.from(s.replaceAll("-", ""), "hex");
const USERS = uuid("a3e1f7c2-5b94-4d08-b6e3-9f2a7c1d4e85");
const EMAIL = uuid("0c9e4b7a-2d15-4f6e-8a3b-1e7d5c9f2a64");

const fs = new Fieldseal(
  {
    // Evaluation only: keep a real root secret in a secret manager. See "Keys" below.
    keyProvider: new DerivedKeyProvider({ rootSecret: randomBytes(32) }),
    allowedSuites: [0xff01],
    writeSuite: 0xff01,
    indexes: [{
      tableUuid: USERS, columnUuid: EMAIL,
      idf: "argon2id", normalize: "nfc-casefold-v1",
      truncateBits: 15, projectedPopulation: 100_000,
    }],
  },
  { armProvisionalSuites: true },   // writing refuses without it; see the warning above
);

const ctx = { tableUuid: USERS, columnUuid: EMAIL, purpose: "encrypt" };
const plaintext = new TextEncoder().encode("ada@example.com");

const envelope = fs.encrypt(plaintext, ctx);   // Buffer, 126 bytes: 111 + the value
fs.decrypt(envelope, ctx);                     // Buffer: "ada@example.com"
fs.isCiphertext(envelope);                     // true, without decrypting

const index = { ...ctx, purpose: "index:exact" };
await fs.blindIndexAsync("Ada@Example.com", index);   // 2 bytes; the same as for "ada@example.com"

fs.rotate(envelope, ctx);                      // a fresh envelope under the active key
```

Store `envelope` in the encrypted column and the blind-index value in a
sibling column; *Blind indexes* below explains how to look values up.

## Blind indexes

A blind index is what makes an encrypted column searchable. Next to each
encrypted value, you store a short keyed hash of it, derived with the context's
`purpose` set to `"index:<indexId>"`. To find a value, derive its hash the same
way, select the rows whose index column matches, then **decrypt each candidate
and compare**. The hash is deliberately truncated, so unrelated values share
hashes and the query returns a few rows that do not match; the comparison is
what makes the answer correct. The ORM adapters do this for you.

Each index is declared up front in `indexes: [...]`. An invalid declaration is
refused when the `Fieldseal` client is constructed, not at the first lookup.
Choose the options before the first write: changing `idf`, `argon2`,
`normalize`, `truncateBits` or `indexId` later changes every stored hash, so
the index has to be rebuilt.

| Field | Default | Accepted values |
|---|---|---|
| `tableUuid`, `columnUuid` | **required** | The column the index belongs to, 16 bytes each. |
| `projectedPopulation` | **required** | How many *distinct* values the column will hold, at least 16. |
| `idf` | **required** | `"argon2id"`: slow on purpose, for anything guessable (emails, phone numbers, IDs, birth dates). `"hmac-sha512"`: fast, only for high-entropy values nobody could enumerate, such as random tokens. |
| `normalize` | **required** | `"nfc-casefold-v1"`: Unicode-normalized and case-folded, so `Ada@Example.com` matches `ada@example.com`. `"identity"`: exact, case-sensitive. `"digits-only-v1"`: digits only, so `+1 (555) 010-0199` matches `15550100199`. |
| `truncateBits` | **required** | Bits of each hash kept. Must satisfy 2 ≤ P / 2<sup>b</sup> < √P, where P is `projectedPopulation`: 7–11 for 5,000 distinct values, 9–15 for 100,000, 10–18 for 1,000,000. |
| `argon2` | the minimum | `{ timeCost, memoryKib }`, to raise the Argon2id cost above 3 passes and 32 MiB. It cannot lower it, and it is refused with `"hmac-sha512"`. |
| `indexId` | `"exact"` | 1–32 lowercase letters, digits and hyphens. Selected with `purpose: "index:<indexId>"`. |
| `skewed` | `false` | `true` if a few values dominate the column. A skewed column is gated like a small one (next row). |
| `cardinalityOverride` | none | `{ reason, approvedBy, date }`. A column with fewer than 1,024 distinct values, or a skewed one, is refused without it: an index over so few values reveals too much. |
| `onUnindexable` | `"refuse"` | For a value containing a character `"nfc-casefold-v1"` cannot index: `"refuse"` it, or `"bucket"` it under the column's reserved hash (`unindexableMarker`). |
| `unindexableOverride` | none | `{ reason, approvedBy, date }`, required for `"bucket"`. |

`nfc-casefold-v1` uses Unicode 17.0.0 tables bundled with the package
(`UNICODE_VERSION`), so an index value does not depend on the Node version's
ICU, and matches the Python core's.

**Argon2id and the event loop.** An Argon2id derivation takes tens of
milliseconds, and `blindIndex()` blocks the event loop for all of it. In a
server, use `blindIndexAsync()` and `unindexableMarkerAsync()`, which run on
libuv's threadpool and return the same bytes; see *Limitations* for sizing
that pool.

## Concepts

### Contexts

A context names where a value lives: `tableUuid` and `columnUuid` (16 bytes
each), optionally `tenantId`, and a `purpose`: `"encrypt"` for values,
`"index:<indexId>"` for blind indexes. The context is bound into the
encryption, so decrypting with a different one fails with
`COMMITMENT_INVALID`. The two UUIDs are part of the key derivation: never
change one once a value has been written, and never derive one from a table
or column name, or a rename makes every existing value unreadable.

### Operations

| Method | What it does |
|---|---|
| `encrypt(plaintext, ctx)` | Encrypts a `Uint8Array`. Needs arming. |
| `decrypt(envelope, ctx)` | Decrypts, or throws. Never returns unauthenticated data. |
| `blindIndex(value, indexCtx)` | Derives the index value for a string or bytes. Blocks during Argon2id. |
| `blindIndexAsync(value, indexCtx)` | The same, off the event loop. |
| `unindexableMarker(indexCtx)`, `unindexableMarkerAsync(indexCtx)` | The column's reserved index value for values that cannot be indexed. |
| `rotate(envelope, ctx)` | Re-encrypts under the active key version. Needs arming. |
| `isCiphertext(value)` | Recognises an envelope without decrypting it. Never throws. |
| `warm(contexts)` | Async. Loads keys ahead of time; see *Keys* below. |

Everything except `warm()` and the two `Async` methods is synchronous and
never touches the network. Inputs are `Uint8Array` and outputs are `Buffer`.
The envelope operations refuse strings: encode text yourself, and encode other
types the same way every time. The ORM adapters use the canonical forms in
spec §3.6, so follow them if another implementation will read your data.

### Keys

| Provider | Use |
|---|---|
| `StaticKeyProvider({ dek, keyId, indexKey })` | One data key and one index key, for tests. The client warns through `onWarning` unless `FIELDSEAL_TEST_MODE=1`. |
| `DerivedKeyProvider({ rootSecret, versions, activeVersion })` | Data and index keys derived from one root secret (32 bytes or more) with HKDF-SHA-512. Several versions can be valid at once; `activeVersion` is the one new values are written under. |
| `EnvelopeKeyProvider({ wrapper, directory, cache })` | Data keys stored wrapped by your KMS. `wrapper` is your object with an `unwrap` method; no KMS client ships with the package. `directory` lists the wrapped keys (`InMemoryKeyDirectory`, or your own), and `cache` is `{ maxAgeMs, maxUses, capacity }`. |

With `EnvelopeKeyProvider`, keys are unwrapped only by `await fs.warm(contexts)`,
never during `encrypt` or `decrypt`. A cold cache therefore means
`KEY_UNAVAILABLE`: warm the contexts you will use before serving traffic.

### Configuration

| Option | Meaning |
|---|---|
| `keyProvider` | One of the providers above. Required. |
| `allowedSuites` | The cipher suites this deployment accepts. Required, with no default. `[0xff01]` is the only one implemented. |
| `writeSuite` | The suite new values are written under: `0xff01`. Required. |
| `readMode` | `"strict"` (default) throws `NOT_CIPHERTEXT` for anything that is not an envelope. `"permissive"` returns it unchanged, and `"readonly"` does the same and refuses writes. Both are for migrating a column that still holds plaintext, and warn while active. |
| `indexes` | Blind-index declarations; see above. |
| `onWarning` | A callback for warnings, such as a static provider outside tests. |
| `metrics` | Optional callbacks, `plaintextReads()` and `decryptErrors(code)`, to feed your own counters. |

**Arming.** `encrypt()` and `rotate()` throw `SUITE_PROVISIONAL` until you arm
provisional use: pass `{ armProvisionalSuites: true }` as the *second*
constructor argument, or set `FIELDSEAL_ARM_PROVISIONAL_SUITES=1` in the
environment. The flag does nothing inside the config object, so copying a
config does not copy the decision. Decrypting never needs it. Arming does not
make the design reviewed: it records that you were told.

### Errors

Every failure is a `FieldsealError` with a `code`: `UNKNOWN_FORMAT_VERSION`,
`SUITE_NOT_ALLOWED`, `KEY_UNAVAILABLE`, `AAD_MISMATCH`, `TAG_INVALID`,
`COMMITMENT_INVALID`, `NOT_CIPHERTEXT`, `MODE_VIOLATION`, `LENGTH_EXCEEDED` and
`SUITE_PROVISIONAL`, plus `CONFIGURATION_ERROR` and `INVALID_ARGUMENT` for bad
setup and arguments. Each has its own class (`CommitmentInvalidError`, …).
Messages never contain plaintext or key material. A wrong key and a wrong
context look the same and both throw `COMMITMENT_INVALID`, so `AAD_MISMATCH`
is never thrown under this suite. The order in which errors are checked is
provisional and may change before 1.0.

## Limitations

The specification requires every implementation to state these.

- **No protection against a compromised application process.** The keys are
  in that process, so anything the application can read, an attacker inside
  it can read.
- **Logs are sensitive.** A lookup sends a blind-index value as a query
  parameter, so database query logs, slow-query logs and replication logs
  record it. Protect them like the ciphertext.
- **Storage overhead.** Each envelope carries 111 bytes of overhead: a 9-byte
  value becomes 120 bytes. Storing it as base64 adds another third.
- **Argon2id costs real time per query term**: 44–70 ms measured at the
  minimum cost, paid for every value written with an index and every value
  searched for. It is a security property, not a tuning option. In Node it
  also competes for the event loop or the threadpool:
  1. Prefer `"hmac-sha512"` wherever the value is high-entropy. It costs
     microseconds, but it is not safe for guessable values, which is exactly
     where an index is most wanted.
  2. Otherwise use the `Async` methods, and set `UV_THREADPOOL_SIZE` to at
     least the number of concurrent derivations. The threadpool also serves
     `fs`, `dns` and `zlib`: with the default four threads, four concurrent
     derivations delayed an unrelated `fs.readFile` from about 0.3 ms to tens
     or hundreds of milliseconds.
  3. Worker threads work, but each needs its own client, so each has its own
     key cache and makes its own KMS calls.
- **The KMS is a hard dependency in the read path.** With
  `EnvelopeKeyProvider`, a KMS outage means `KEY_UNAVAILABLE` for every key not
  already in the cache.
- **The key cache holds plaintext keys in memory**, exposed to memory dumps,
  core files and swap. Evicted keys are zeroed, but V8 and OpenSSL may hold
  copies and garbage-collected memory cannot be locked, so this narrows the
  exposure rather than closing it. The cache's `maxAgeMs` and `maxUses` are
  security settings. In a server that forks workers, construct clients after
  the fork.
- **Only one cipher suite is implemented.** `0xff01` (AES-256-GCM).
  `0xff02` (XChaCha20-Poly1305) is recognised and refused.

## Learn more

- [`REFERENCE.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/core/typescript/REFERENCE.md):
  where this core came from, the behaviours it pins, the testing namespace and
  development setup.
- [Core design](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/11-core-typescript.md)
  and the [specification](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/02-spec-v0.1.md).
- [Reviewer brief](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/16-reviewer-brief.md):
  if you can review the cryptographic design, this is where to start.
- Bugs and interoperability problems:
  [issues](https://github.com/fieldseal-dev/fieldseal-spec/issues).
  Suspected vulnerabilities:
  [`SECURITY.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/SECURITY.md),
  not a public issue.
