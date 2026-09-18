# fieldseal (Python core)

Field-level encryption for Python applications, with a format that other
languages can read.

> **Experimental release: not independently reviewed, not for production data.**
> The cryptographic design this package implements has not been reviewed by
> anyone outside the project. It is pre-1.0: the stored format may change
> before 1.0, and data written with it now may have to be re-encrypted if
> review changes a construction. Writing refuses until you explicitly arm
> provisional use (spec §4.8). This release is for evaluation and feedback;
> the terms it is published under are in [PRD §8](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/01-prd.md#8-scope-and-phasing).

`fieldseal` encrypts individual values, such as a column in a database row,
inside your application, so the database and its backups hold only ciphertext.
It also derives **blind indexes**, short keyed hashes that let you find a row
by an encrypted value without decrypting the whole table.

It is the Python core of [Fieldseal](https://fieldseal.dev), an open
specification for field-level encryption. What it writes, the
[TypeScript core](https://www.npmjs.com/package/@fieldseal/core) can read, and
the reverse. Most applications use it through an ORM adapter instead:
[`fieldseal-django`](https://pypi.org/project/fieldseal-django/) for Django.

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
- **KMS-backed keys**, unwrapped ahead of time so encryption and decryption
  never wait on the network.
- **Cross-language.** The same test vectors pin this core and the TypeScript
  core, and CI checks on every run that each decrypts what the other wrote.

## Requirements

Python 3.10 or later. The cryptography comes from
[`cryptography`](https://cryptography.io) (AES-GCM, HKDF, HMAC) and, for
Argon2id blind indexes, [`argon2-cffi`](https://pypi.org/project/argon2-cffi/).

## Install

```sh
pip install "fieldseal[argon2]"
```

The `argon2` extra is needed for Argon2id blind indexes, which is what the
specification requires for guessable values such as email addresses. Without
it, the first Argon2id derivation raises `ModuleNotFoundError`. Leave it out
only if you use no blind indexes, or only HMAC-SHA-512 ones.

## Quickstart

```python
import secrets, uuid
from fieldseal import Fieldseal, FieldContext, IndexDeclaration
from fieldseal.keyprovider import StaticKeyProvider

# Evaluation only: keys held in memory, no KMS. See "Keys" below.
keys = StaticKeyProvider(
    key_id=secrets.token_bytes(16),
    tenant_dek=secrets.token_bytes(32),
    tenant_index_key=secrets.token_bytes(32),
)

# Fixed identifiers for the table and column. Never derive them from names.
USERS = uuid.UUID("a3e1f7c2-5b94-4d08-b6e3-9f2a7c1d4e85").bytes
EMAIL = uuid.UUID("0c9e4b7a-2d15-4f6e-8a3b-1e7d5c9f2a64").bytes

fs = Fieldseal(
    key_provider=keys,
    allowed_suites={0xFF01},
    write_suite=0xFF01,
    indexes=[IndexDeclaration(
        table_uuid=USERS, column_uuid=EMAIL,
        idf="argon2id", normalize="nfc-casefold-v1",
        truncate_bits=15, projected_population=100_000,
    )],
    arm_provisional_suites=True,   # writing refuses without it; see the warning above
)

ctx = FieldContext(table_uuid=USERS, column_uuid=EMAIL)

envelope = fs.encrypt(b"ada@example.com", ctx)    # 126 bytes: 111 + the value
fs.decrypt(envelope, ctx)                          # b'ada@example.com'
fs.is_ciphertext(envelope)                         # True, without decrypting

index = ctx.for_index("exact")
fs.blind_index("Ada@Example.com", index)           # 2 bytes; the same as for "ada@example.com"

fs.rotate(envelope, ctx)                           # a fresh envelope under the active key
```

Store `envelope` in the encrypted column and the blind-index value in a
sibling column; *Blind indexes* below explains how to look values up.

## Blind indexes

A blind index is what makes an encrypted column searchable. Next to each
encrypted value, you store a short keyed hash of it: `blind_index(value,
ctx.for_index(index_id))`. To find a value, derive its hash the same way,
select the rows whose index column matches, then **decrypt each candidate and
compare**. The hash is deliberately truncated, so unrelated values share
hashes and the query returns a few rows that do not match; the comparison is
what makes the answer correct. The ORM adapters do this for you.

Each index is declared up front in `indexes=[IndexDeclaration(...)]`. An
invalid declaration is refused when the `Fieldseal` client is built, not at
the first lookup. Choose the options before the first write: changing `idf`,
`argon2`, `normalize`, `truncate_bits` or `index_id` later changes every
stored hash, so the index has to be rebuilt.

| Field | Default | Accepted values |
|---|---|---|
| `table_uuid`, `column_uuid` | **required** | The column the index belongs to, 16 bytes each. |
| `projected_population` | **required** | How many *distinct* values the column will hold, at least 16. |
| `idf` | **required** | `"argon2id"`: slow on purpose, for anything guessable (emails, phone numbers, IDs, birth dates). `"hmac-sha512"`: fast, only for high-entropy values nobody could enumerate, such as random tokens. |
| `normalize` | **required** | `"nfc-casefold-v1"`: Unicode-normalized and case-folded, so `Ada@Example.com` matches `ada@example.com`. `"identity"`: exact, case-sensitive. `"digits-only-v1"`: digits only, so `+1 (555) 010-0199` matches `15550100199`. |
| `truncate_bits` | **required** | Bits of each hash kept. Must satisfy 2 ≤ P / 2<sup>b</sup> < √P, where P is `projected_population`: 7–11 for 5,000 distinct values, 9–15 for 100,000, 10–18 for 1,000,000. |
| `argon2` | the minimum | `Argon2Params(time_cost=..., memory_kib=...)`, to raise the Argon2id cost above 3 passes and 32 MiB. It cannot lower it, and it is refused with `"hmac-sha512"`. |
| `index_id` | `"exact"` | 1–32 lowercase letters, digits and hyphens. Selected with `ctx.for_index(index_id)`. |
| `skewed` | `False` | `True` if a few values dominate the column. A skewed column is gated like a small one (next row). |
| `cardinality_override` | `None` | `CardinalityOverride(reason=..., approved_by=..., date=...)`. A column with fewer than 1,024 distinct values, or a skewed one, is refused without it: an index over so few values reveals too much. |
| `on_unindexable` | `"refuse"` | For a value containing a character `"nfc-casefold-v1"` cannot index: `"refuse"` it, or `"bucket"` it under the column's reserved hash (`unindexable_marker`). |
| `unindexable_override` | `None` | A `CardinalityOverride`, required for `"bucket"`. |

`nfc-casefold-v1` uses Unicode 17.0.0 tables bundled with the package
(`fieldseal.UNICODE_VERSION`), so an index value does not depend on the Python
version, and matches the TypeScript core's.

## Concepts

### Contexts

A `FieldContext` names where a value lives: `table_uuid` and `column_uuid`
(16 bytes each), and optionally `tenant_id`. The context is bound into the
encryption, so decrypting with a different one fails with
`COMMITMENT_INVALID`. The two UUIDs are part of the key derivation: never
change one once a value has been written, and never derive one from a table
or column name, or a rename makes every existing value unreadable.

### Operations

All of these are synchronous and never touch the network:

| Method | What it does |
|---|---|
| `encrypt(plaintext, ctx)` | Encrypts bytes. Needs arming. |
| `decrypt(envelope, ctx)` | Decrypts, or raises. Never returns unauthenticated data. |
| `blind_index(value, index_ctx)` | Derives the index value for text or bytes. |
| `unindexable_marker(index_ctx)` | The column's reserved index value for values that cannot be indexed. |
| `rotate(envelope, ctx)` | Re-encrypts under the active key version. Needs arming. |
| `is_ciphertext(value)` | Recognises an envelope without decrypting it. Never raises. |

`warm(contexts)` (async) and `warm_blocking(contexts)` load keys ahead of time;
see *Keys* below.

Values are bytes. Encode text yourself, and encode other types the same way
every time: the ORM adapters use the canonical forms in spec §3.6, so follow
them if another implementation will read your data.

### Keys

- **`StaticKeyProvider`**: one data key and one index key held in memory, for
  tests and evaluation. It does not yet warn when used outside tests.
- **`EnvelopeKeyProvider(wrapper=..., directory=..., cache=...)`**: data keys
  stored wrapped by your KMS. `wrapper` is your object with an async
  `unwrap(wrapped, scope)` method; no KMS client ships with the package.
  `directory` lists the wrapped keys per tenant (`InMemoryKeyDirectory`, or
  your own); `cache` is a `CachePolicy(max_age=..., max_uses=..., capacity=...)`.

With `EnvelopeKeyProvider`, keys are unwrapped only by `warm()` or
`warm_blocking()`, never during `encrypt` or `decrypt`. A cold cache therefore
means `KEY_UNAVAILABLE`: warm the contexts you will use before serving
traffic. A third provider in the specification, `DerivedKeyProvider`, is
available in the TypeScript core and not yet in Python.

### Arming

`encrypt()` and `rotate()` raise `SUITE_PROVISIONAL` until you arm provisional
use, with `arm_provisional_suites=True` on the constructor or
`FIELDSEAL_ARM_PROVISIONAL_SUITES=1` in the environment. Decrypting never
needs it. Arming does not make the design reviewed: it records that you were
told.

### Read modes

`read_mode="strict"` (the default) raises `NOT_CIPHERTEXT` for anything that is
not an envelope. `"permissive"` returns non-envelope input unchanged, and
`"readonly"` does the same and also refuses writes. Both are for migrating a
column that still holds plaintext: they warn when the client is built and
count what they pass through in `fs.plaintext_reads`.

### Errors

Every failure is a subclass of `fieldseal.errors.FieldsealError` with a
`code`: `UNKNOWN_FORMAT_VERSION`, `SUITE_NOT_ALLOWED`, `KEY_UNAVAILABLE`,
`AAD_MISMATCH`, `TAG_INVALID`, `COMMITMENT_INVALID`, `NOT_CIPHERTEXT`,
`MODE_VIOLATION`, `LENGTH_EXCEEDED` and `SUITE_PROVISIONAL`, plus
`CONFIGURATION_ERROR` and `INVALID_ARGUMENT` for bad setup and arguments.
Messages never contain plaintext or key material. A wrong key and a wrong
context look the same and both raise `COMMITMENT_INVALID`, so `AAD_MISMATCH`
is never raised under this suite. The order in which errors are checked is
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
  value becomes 120 bytes. Storing it as base64 adds another third. Across a
  20-column, 100-million-row table the overhead alone is about 220 GB.
- **Argon2id costs 10–100 ms per query term** (about 37 ms measured). It is
  paid for every value written with an index and every value searched for.
  It delays the requesting thread only: two derivations on separate threads
  take about as long as one. It is a security property, not a tuning option.
- **The KMS is a hard dependency in the read path.** With
  `EnvelopeKeyProvider`, a KMS outage means `KEY_UNAVAILABLE` for every key not
  already in the cache.
- **The key cache holds plaintext keys in memory**, exposed to memory dumps,
  core files and swap. Evicted keys are overwritten with zeros, but Python
  copies `bytes` freely and cannot lock memory, so this narrows the exposure
  rather than closing it. The cache's `max_age` and `max_uses` are security
  settings. In a server that forks workers, build the client after the fork,
  or every worker inherits a copy of the cached keys.
- **Only one cipher suite is implemented.** `0xFF01` (AES-256-GCM).
  `0xFF02` (XChaCha20-Poly1305) is recognised and refused.

## Learn more

- [`REFERENCE.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/core/python/REFERENCE.md):
  conformance status, the behaviours this core pins where the specification
  leaves a choice, what its tests do and do not prove, and development setup.
- [Core design](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/10-core-python.md)
  and the [specification](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/02-spec-v0.1.md).
- [Reviewer brief](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/16-reviewer-brief.md):
  if you can review the cryptographic design, this is where to start.
- Bugs and interoperability problems:
  [issues](https://github.com/fieldseal-dev/fieldseal-spec/issues).
  Suspected vulnerabilities:
  [`SECURITY.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/SECURITY.md),
  not a public issue.
