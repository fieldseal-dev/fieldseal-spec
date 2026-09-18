# @fieldseal/prisma

Encrypt Prisma model fields at rest, and keep looking rows up by them.

> **Experimental release: not independently reviewed, not for production data.**
> The cryptographic design this package implements has not been reviewed by
> anyone outside the project. It is pre-1.0: the stored format may change
> before 1.0, and data written with it now may have to be re-encrypted if
> review changes a construction. Writing refuses until you explicitly arm
> provisional use (spec §4.8). This release is for evaluation and feedback;
> the terms it is published under are in [PRD §8](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/01-prd.md#8-scope-and-phasing).

`@fieldseal/prisma` is a Prisma Client extension. It encrypts the fields you
mark in your schema before they reach the database, and decrypts them when you
read them back. The database, its backups and its replicas hold only
ciphertext. A blind index keeps `findMany({ where: { email } })` working on an
encrypted column.

It is the Prisma adapter for [Fieldseal](https://fieldseal.dev), an open
specification for field-level encryption. What this package writes, any
conformant implementation can read, including the
[Python core](https://pypi.org/project/fieldseal/) and the
[Django adapter](https://pypi.org/project/fieldseal-django/).

## Features

- **Declared in the schema.** Mark fields with `/// @fieldseal(...)` comments;
  a Prisma generator turns them into a field map at `prisma generate`, and a
  malformed declaration fails the generate, not the first request.
- **Transparent.** `create`, `createMany`, `update`, `updateMany` and nested
  relation writes encrypt; reads decrypt, including `include` and `select`.
- **Equality search on encrypted columns.** `findMany` with equality or `in`
  goes through a blind index. The index is deliberately lossy, so every
  candidate row is decrypted and re-checked before you get it: you never see a
  false match.
- **Refuses what it cannot answer.** Ordering, ranges, `contains`, aggregates,
  negation and `count` over an encrypted column throw an error naming what to
  run instead, rather than returning a plausible wrong answer.
- **Eight value types**: text, bytes, integers, decimals, floats, booleans,
  dates and datetimes, stored exactly as the Django adapter stores them.
- **Keys fetched when needed.** With a KMS-backed key provider, a query that
  needs a key not yet in the cache waits for it instead of failing.
- **Tenant binding.** A row encrypted for one tenant cannot be decrypted as
  another tenant's, even by the same application.
- **No cryptography of its own.** Every cipher, key derivation and random draw
  lives in [`@fieldseal/core`](https://www.npmjs.com/package/@fieldseal/core).

## Requirements

- **Node 24.7 or later**, and **Prisma 7.10 or later, below 8**
  (`@prisma/client` and the `prisma` CLI). Pin both: the `prisma` CLI's
  `latest` tag currently points at an 8.0 release candidate.
- CI runs the test suite on **PostgreSQL and SQLite**.
- **`prisma generate` does not run this generator on Windows.** With Prisma
  7.10 and Node 24, Prisma fails to start it (`spawn … ENOENT`). Run
  `prisma generate` under WSL, Linux or macOS; the generated field map is an
  ordinary file you commit, so the application itself runs anywhere.

## Install

```sh
npm install @fieldseal/prisma @fieldseal/core @prisma/client@7.10
npm install --save-dev prisma@7.10
```

The quickstart also uses SQLite's driver adapter,
`@prisma/adapter-better-sqlite3@7.10`; use your own database's instead.

## Quickstart

**1. Declare the encrypted fields** in `schema.prisma`. Each encrypted table
and column needs a UUID that never changes; generate them once
(`node -e "console.log(crypto.randomUUID())"`) and paste them in:

```prisma
generator client {
  provider = "prisma-client"
  output   = "../src/generated/prisma"
}

generator fieldseal {
  provider = "fieldseal-prisma-generator"
  output   = "../src/generated"
}

datasource db {
  provider = "sqlite"   // the url goes in prisma.config.ts, as usual in Prisma 7
}

/// @fieldseal(table_uuid: "a3e1f7c2-5b94-4d08-b6e3-9f2a7c1d4e85")
model Patient {
  id        Int     @id @default(autoincrement())
  /// @fieldseal(encrypted, column_uuid: "6f1d8a52-3b7e-4c0a-9e21-5d4c7b8a9f10")
  name      Bytes
  /// @fieldseal(encrypted, column_uuid: "0c9e4b7a-2d15-4f6e-8a3b-1e7d5c9f2a64")
  email     Bytes
  /// @fieldseal(index: "email", idf: "argon2id", normalize: "nfc-casefold-v1",
  ///            truncate_bits: 15, projected_population: 100000)
  emailBidx Bytes?

  @@index([emailBidx])
}
```

An encrypted column is `Bytes`, because it holds an envelope. `emailBidx` is
the blind index for `email`: optional, indexed, never `@unique`.

**2. Generate and create the tables:**

```sh
npx prisma generate      # also writes src/generated/fieldseal-map.ts; commit it
npx prisma db push
```

**3. Extend the client.** Register the extension **last**, so every other
extension sees plaintext:

```ts
import { randomBytes } from "node:crypto";
import { PrismaBetterSqlite3 } from "@prisma/adapter-better-sqlite3";
import { DerivedKeyProvider } from "@fieldseal/core";
import { fieldsealExtension } from "@fieldseal/prisma";
import { PrismaClient } from "./generated/prisma/client.ts";
import { fieldsealFieldMap } from "./generated/fieldseal-map.ts";

const prisma = new PrismaClient({
  adapter: new PrismaBetterSqlite3({ url: "file:./dev.db" }),
}).$extends(
  fieldsealExtension({
    fieldMap: fieldsealFieldMap,
    // Evaluation only: keep a real root secret in a secret manager. See "Keys" below.
    keyProvider: new DerivedKeyProvider({ rootSecret: randomBytes(32) }),
    allowedSuites: [0xff01],
    writeSuite: 0xff01,
    armProvisionalSuites: true,   // writing refuses without it; see the warning above
  }),
);
```

**4. Use it** like any other model:

```ts
await prisma.patient.create({
  data: { name: "Ada Lovelace" as never, email: "ada@example.com" as never },
});

await prisma.patient.findMany({ where: { email: "ADA@example.com" as never } });
await prisma.patient.findMany({
  where: { email: { in: ["ada@example.com", "grace@example.com"] as never } },
});

await prisma.patient.count({ where: { email: "ada@example.com" as never } });
// throws FieldsealNotSupported: the database would count the index bucket
```

The `as never` casts are there because Prisma types an encrypted column as
`Uint8Array` (its storage type), while you write the value itself. See
*Declaring columns* below for the alternative.

## Declaring columns

Declarations are `///` comments, read by the generator at `prisma generate`.

**On the model:** `@fieldseal(table_uuid: "...")`, required on any model with
an encrypted column.

**On an encrypted field:** `@fieldseal(encrypted, column_uuid: "...", ...)`:

| Key | Default | Accepted values |
|---|---|---|
| `column_uuid` | **required** | The column's UUID. |
| `as` | `"string"` | The value's type: `"string"`, `"bytes"`, `"int"`, `"decimal"`, `"float"`, `"boolean"`, `"date"`, `"datetime"`. |
| `storage` | `"binary"` | `"binary"` on a `Bytes` column; `"base64"` on a `String` column, which costs a third more space but types as `string`, so text values need no cast. |
| `tenant_bound` | off | A flag, written bare: `@fieldseal(encrypted, tenant_bound, ...)`. See *Tenant binding* below. |
| `noun` | the field name | The word used for the value in error messages. |

**The UUIDs are part of the key derivation.** Never change one once a row has
been written, and never derive one from a model or field name: either makes
every existing row in that column unreadable.

**Types.** Each type is stored in one canonical form, byte-for-byte what the
Django adapter writes. JavaScript has no decimal or calendar-date type, so:

- **`decimal`** is written as a string (`"1.50"`) or a `Prisma.Decimal`, and
  read back as its canonical string (`"1.5"`). A `number` is refused.
- **`date`** is written and read as a `Date` at exactly UTC midnight. Any
  other time of day is refused rather than truncated.
- A stored `datetime` with microseconds a `Date` cannot hold is refused on
  read, and so is any stored value not in canonical form.

Changing `as` on a column that has rows needs a backfill.

## Blind indexes

A blind index is what makes an encrypted column searchable. The index field
stores a short keyed hash of the encrypted field's value. `findMany({ where:
{ email: v } })` is rewritten to look for `v`'s hash instead. The hash is
deliberately truncated, so unrelated values share hashes: the database returns
a few extra rows, and the extension decrypts every candidate and drops the
ones that do not match before you see them.

The index field must be `Bytes?` (optional), should have an `@@index`, and
must not be `@unique` or `@id`: the generator refuses those. Its value is
derived on every write; you never set it, and it is left out of results unless
`exposeIndexColumns: true`.

The options decide what counts as a match, how hard the hashes are to attack,
and how much the index reveals. Choose them before the first write: changing
`idf`, `normalize`, `truncate_bits`, `index_id` or the Argon2id cost later
changes every stored hash, so the index has to be rebuilt.

**On the index field:** `@fieldseal(index: "<encrypted field>", ...)`:

| Key | Default | Accepted values |
|---|---|---|
| `index` | **required** | The name of the encrypted field this indexes. |
| `projected_population` | **required** | How many *distinct* values the column will hold, at least 16. |
| `idf` | **required** | `"argon2id"`: slow on purpose, for anything guessable (emails, phone numbers, IDs, birth dates). `"hmac-sha512"`: fast, only for high-entropy values nobody could enumerate, such as random tokens. |
| `normalize` | **required** | `"nfc-casefold-v1"`: Unicode-normalized and case-folded, so `Ada@Example.com` matches `ada@example.com`. `"identity"`: exact, case-sensitive. `"digits-only-v1"`: digits only, so `+1 (555) 010-0199` matches `15550100199`. |
| `truncate_bits` | **required** | Bits of each hash kept. Must satisfy 2 ≤ P / 2<sup>b</sup> < √P, where P is `projected_population`: 7–11 for 5,000 distinct values, 9–15 for 100,000, 10–18 for 1,000,000. |
| `argon2_time_cost`, `argon2_memory_kib` | the minimum | Both together, to raise the Argon2id cost above 3 passes and 32 MiB (`32768`). They cannot lower it. |
| `index_id` | `"exact"` | 1–32 lowercase letters, digits and hyphens. Another implementation searching this column must use the same value. |
| `skewed` | `false` | `true` if a few values dominate the column. A skewed column is gated like a small one (below). |
| `on_unindexable` | `"refuse"` | For a value containing a character `"nfc-casefold-v1"` cannot index: `"refuse"` it with `FieldsealUnindexable`, or `"bucket"` it under the column's reserved hash. |

**Overrides, in code.** A column with fewer than 1,024 distinct values, or a
skewed one, is refused unless you record who accepted the risk, because an
index over so few values reveals too much. `"bucket"` needs the same record.
Both are extension options, not schema comments, so they sit in reviewed code:

```ts
fieldsealExtension({
  // ...
  cardinalityOverride: [
    { model: "Patient", field: "email", reason: "...", approvedBy: "...", date: "2026-09-18" },
  ],
  unindexableOverride: [ /* the same shape */ ],
});
```

**Argon2id and the event loop.** Each Argon2id derivation takes tens of
milliseconds, and this adapter still derives synchronously, so it blocks the
Node event loop, and every other request in the process, for that time. See
*Limitations*.

## Extension options

| Option | Default | Meaning |
|---|---|---|
| `fieldMap` | **required** | The generated `fieldsealFieldMap`. |
| `keyProvider` | **required** | A key provider from `@fieldseal/core`. |
| `allowedSuites` | **required** | The cipher suites this deployment accepts. `[0xff01]` is the only one implemented. |
| `writeSuite` | **required** | The suite new values are written under: `0xff01`. |
| `armProvisionalSuites` | `false` | `true` to allow writing under a provisional suite. Setting `FIELDSEAL_ARM_PROVISIONAL_SUITES=1` in the environment does the same. Reading never needs it. |
| `readMode` | `"strict"` | `"permissive"` or `"readonly"` pass non-envelope values through, for migrating a column that still holds plaintext; `onPlaintextRead` is called for each. |
| `tenant` | none | A function `(args, model, operation) => tenant` resolving the tenant from the query, as an alternative to `tenantScope`. |
| `warmOnKeyMiss` | `true` | Fetch a missing key and retry, instead of failing; see *Keys* below. |
| `strictRaw` | `false` | `true` makes `$queryRaw` and `$executeRaw` throw; see *Raw SQL* below. |
| `onRawOperation` | none | Called with the operation name for every raw query. |
| `exposeIndexColumns` | `false` | Leave index fields in returned objects. |
| `cardinalityOverride`, `unindexableOverride` | none | See *Blind indexes* above. |
| `onWarning` | none | A callback for warnings, such as a static key provider outside tests. |

## Keys

The key provider comes from `@fieldseal/core`:

- **`StaticKeyProvider`**: one data key and one index key, for tests.
- **`DerivedKeyProvider`**: keys derived from one root secret, with several
  versions valid at once.
- **`EnvelopeKeyProvider`**: data keys stored wrapped by your KMS, unwrapped
  into a cache.

With `EnvelopeKeyProvider`, a key that is not in the cache would normally mean
`KEY_UNAVAILABLE`. Because Prisma queries are asynchronous, this extension
instead fetches the keys the query needs and runs it again. It retries only
while each attempt needs keys no earlier fetch covered, so it never loops, and
if fetching fails, that error is thrown. `warmOnKeyMiss: false` turns this
off, so no query ever waits on the KMS.

## Tenant binding

Mark a field `tenant_bound`, then write and read inside a tenant scope, or
pass a `tenant` resolver:

```ts
import { tenantScope } from "@fieldseal/prisma";

await tenantScope("tenant-a", async () => {
  await prisma.patient.create({ data: { name: "Ada Lovelace" as never, email: "ada@example.com" as never } });
});
```

A write to a tenant-bound field with no tenant is refused. A row written for
one tenant fails to decrypt under another: the binding is cryptographic, not a
filter.

## Querying encrypted columns

The extension can only re-check rows that come back to it. In Prisma that is
the top-level `where` of `findMany`, and a relation `where` under `include` or
`select`. Anywhere the database computes the answer itself, it is refused:

| Works | Refused |
|---|---|
| `findMany` with `equals` or `in` on an indexed field | `findFirst`, `findUnique` |
| A relation `where` under `include` / `select` | `count`, `aggregate`, `groupBy` with such a filter |
| `where: { field: null }` and `{ not: null }` | `update`, `updateMany`, `delete`, `deleteMany`, `upsert` with such a filter |
| Reading the field after filtering on another one | `take`, `skip`, `cursor`, `distinct` beside such a filter |
| `_count` over an encrypted field (it reads no bytes) | `OR` including the field; `not`, `notIn`, `NOT`, `none`, `isNot` |
| | `contains`, `startsWith`, `endsWith`, `lt`/`gte`, `search`, `mode: "insensitive"` |
| | `orderBy`, `distinct`, `groupBy`, `_min`/`_max`/`_sum`/`_avg` on the field |
| | Relation filters (`some`, `every`, `none`, `is`) naming the field |
| | Equality on an encrypted field with no index |

Each refusal throws `FieldsealNotSupported`, naming what to run instead. To
paginate, fetch the verified rows with `findMany` and slice them in your code.

**`candidateScope`** turns the re-check off for one callback, and hands you the
raw candidates:

```ts
import { candidateScope } from "@fieldseal/prisma";

const bucketSize = await candidateScope(() =>
  prisma.patient.count({ where: { email: "ada@example.com" as never } }),
);
```

Inside it, `count` returns the bucket size, a `take`-limited page can hold rows
that do not match, and **`deleteMany` deletes the whole bucket**. It does not
lift the refusals on negation, ordering, grouping or aggregates. Construct the
operation inside the callback.

### Raw SQL

`$queryRaw` and `$executeRaw` are not intercepted: their parameters are written
as given, which means plaintext in an encrypted column. By default they pass
through and call `onRawOperation`; `strictRaw: true` makes them throw.

## Limitations

The specification requires every implementation to state these.

- **No protection against a compromised application process.** The keys are
  in that process, so anything the application can read, an attacker inside
  it can read.
- **Logs and caches can hold sensitive data.** An equality lookup sends the
  blind-index value as a query parameter, so database query logs, slow-query
  logs and replication logs record it. Any cache outside the extension holds
  decrypted values.
- **Storage overhead.** Each encrypted value carries 111 bytes of overhead: a
  9-byte value becomes about 120 bytes, or 160 as base64. Across a 20-column,
  100-million-row table the overhead alone is about 220 GB.
- **Argon2id stalls the whole process.** Each derivation takes 44–70 ms, and
  this adapter runs it synchronously, so it blocks the event loop for every
  request in the process, not only the one that asked. Measured: under eight
  concurrent Argon2id lookups, an unrelated query's p99 went from 0.8 ms to
  352 ms. Prefer `"hmac-sha512"` wherever the value is high-entropy. The core
  has asynchronous derivation; this adapter does not use it yet.
- **The KMS is a hard dependency in the read path.** With
  `EnvelopeKeyProvider`, a KMS outage fails every query that needs a key not
  already in the cache.
- **The key cache holds plaintext keys in memory**, exposed to memory dumps,
  core files and swap. Evicted keys are zeroed, but V8 may hold copies and
  garbage-collected memory cannot be locked, so this narrows the exposure
  rather than closing it. The cache's lifetime and use limits are security
  settings. In a server that forks workers, create the client after the fork.
- **Equality is the normalizer's.** A lookup matches values that are equal
  after the index's normalization, such as a different case, not only
  identical strings.
- **Writes to `Bytes` columns need a cast**, because Prisma types them by
  storage. For text, `String` with `storage: "base64"` avoids it, at a third
  more space.
- **No row binding.** A value is bound to its table, column and tenant, but
  not to its row, so someone with database write access can swap encrypted
  values between rows of the same column.

## Learn more

- [`REFERENCE.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/adapters/prisma/REFERENCE.md):
  every query path and its test, the reasoning behind each refusal, how key
  fetching retries, why declarations come from a generator, and development
  setup.
- [Adapter design](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/13-adapter-prisma.md)
  and the [specification](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/02-spec-v0.1.md).
- [Reviewer brief](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/16-reviewer-brief.md):
  if you can review the cryptographic design, this is where to start.
- Bugs and interoperability problems:
  [issues](https://github.com/fieldseal-dev/fieldseal-spec/issues).
  Suspected vulnerabilities:
  [`SECURITY.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/SECURITY.md),
  not a public issue.
