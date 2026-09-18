# fieldseal-django

Encrypt Django model fields at rest, and keep looking rows up by them.

> **Experimental release: not independently reviewed, not for production data.**
> The cryptographic design this package implements has not been reviewed by
> anyone outside the project. It is pre-1.0: the stored format may change
> before 1.0, and data written with it now may have to be re-encrypted if
> review changes a construction. Writing refuses until you explicitly arm
> provisional use (spec §4.8). This release is for evaluation and feedback;
> the terms it is published under are in [PRD §8](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/01-prd.md#8-scope-and-phasing).

`fieldseal-django` encrypts the model fields you choose inside your application,
before they reach the database, and decrypts them when you read them back. The
database, its backups and its replicas hold only ciphertext. A blind index keeps
`filter(email=...)` working on an encrypted column.

It is the Django adapter for [Fieldseal](https://fieldseal.dev), an open
specification for field-level encryption. What this package writes, any
conformant implementation can read, including the
[TypeScript core](https://www.npmjs.com/package/@fieldseal/core) and the
[Prisma adapter](https://www.npmjs.com/package/@fieldseal/prisma).

## Features

- **Transparent.** `save()`, `create()`, `bulk_create()`, `bulk_update()` and
  `update()` encrypt; reads, `values()` and `raw()` results decrypt. Your model
  code and forms keep working with plain values.
- **Equality search on encrypted columns.** `filter(email=...)` and `__in` go
  through a blind index. The index is deliberately lossy, so every candidate row
  is decrypted and re-checked before you get it: you never see a false match.
- **Refuses what it cannot answer.** Ordering, ranges, `startswith`, aggregates
  and `exclude()` over an encrypted column raise an error instead of returning
  a plausible wrong answer.
- **Eight value types**: text, bytes, integers, decimals, floats, booleans,
  dates and datetimes, stored exactly as the Prisma adapter stores them.
- **Tenant binding.** A row encrypted for one tenant cannot be decrypted as
  another tenant's, even by the same application.
- **No cryptography of its own.** Every cipher, key derivation and random draw
  lives in the [`fieldseal`](https://pypi.org/project/fieldseal/) core, which
  is AES-256-GCM with key commitment and a fresh derived key for every write.

## Requirements

Python 3.12 or later, and Django 5.2 or later. CI runs the test suite on
PostgreSQL and SQLite.

## Install

```sh
pip install fieldseal-django
```

This also installs the `fieldseal` core and `argon2-cffi`, which the default
blind index needs.

## Quickstart

**1. Create evaluation keys and add the app.** This example uses static keys
from environment variables, which is fine for evaluation and wrong for anything
else (see *Keys* below). Every `manage.py` command needs them, so set them
first:

```sh
export FIELDSEAL_KEY_ID=$(python -c "import secrets; print(secrets.token_hex(16))")
export FIELDSEAL_DEK=$(python -c "import secrets; print(secrets.token_hex(32))")
export FIELDSEAL_INDEX_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

Keep them: data written under one set of keys cannot be read under another.

```python
# settings.py
import os
from fieldseal.keyprovider import StaticKeyProvider

INSTALLED_APPS = [
    # ...
    "fieldseal_django",
    "patients",
]

def fieldseal_keys():
    return StaticKeyProvider(
        key_id=bytes.fromhex(os.environ["FIELDSEAL_KEY_ID"]),              # 16 bytes
        tenant_dek=bytes.fromhex(os.environ["FIELDSEAL_DEK"]),             # 32 bytes
        tenant_index_key=bytes.fromhex(os.environ["FIELDSEAL_INDEX_KEY"]), # 32 bytes, not the DEK
    )

FIELDSEAL = {
    "KEY_PROVIDER": fieldseal_keys,
    "ALLOWED_SUITES": {0xFF01},
    "WRITE_SUITE": 0xFF01,
    "ARM_PROVISIONAL_SUITES": True,   # writing refuses without it; see the warning above
}
```

**2. Get identifiers for your table and columns.** Each encrypted table and
column needs a UUID that never changes:

```sh
python manage.py fieldseal_gen_uuids --count 3
```

**3. Declare the encrypted fields**, pasting in the UUIDs:

```python
# patients/models.py
from django.db import models
from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta

class Patient(models.Model):
    name = Encrypted(
        models.CharField(max_length=200),
        column_uuid="6f1d8a52-3b7e-4c0a-9e21-5d4c7b8a9f10",
    )
    email = Encrypted(
        models.EmailField(),
        column_uuid="0c9e4b7a-2d15-4f6e-8a3b-1e7d5c9f2a64",
        index=BlindIndex(projected_population=100_000),   # makes it searchable
    )
    email_bidx = Encrypted.index_column("email")          # must come after `email`

    fieldseal = FieldsealMeta(table_uuid="a3e1f7c2-5b94-4d08-b6e3-9f2a7c1d4e85")
```

**4. Migrate and use it** like any other model:

```sh
python manage.py makemigrations patients && python manage.py migrate
```

```python
Patient.objects.create(name="Ada Lovelace", email="ada@example.com")

Patient.objects.get(email="ADA@example.com").name   # 'Ada Lovelace'
Patient.objects.filter(email__in=["ada@example.com", "grace@example.com"])

Patient.objects.filter(email__startswith="ada")     # raises FieldsealNotSupported
```

The `name` column now holds a binary envelope of 123 bytes, and
`email_bidx` holds a 2-byte index value, not the address.

## Declaring columns

`Encrypted(inner_field, *, column_uuid, index=None, tenant_bound=None,
storage="binary")` wraps an ordinary Django field. The inner field keeps its
validation and form behaviour and decides the value type.

- **`column_uuid`** (required): the column's identifier; see below.
- **`index`**: a `BlindIndex(...)` to make the column searchable by equality
  (see *Blind indexes* below), or `None` (the default) for a column you only
  read and write.
- **`tenant_bound`**: `None` (the default) follows the model's
  `FieldsealMeta(tenant_bound=...)`; `True` or `False` overrides it for this
  column. See *Tenant binding* below.
- **`storage`**: `"binary"` (the default) stores the envelope in a
  `BinaryField`. `"base64"` stores it as text in a `TextField`, for databases
  that cannot hold binary, and costs a third more space.

**The UUIDs are part of the key derivation.** Never change one once a row has
been written, and never derive one from a model or field name: either makes
every existing row in that column unreadable. Startup fails (system check
`fieldseal.E004`) if a model declares an encrypted column without a
`FieldsealMeta`.

**Supported inner fields.** `CharField`, `TextField` and their subclasses
(`EmailField`, `SlugField`, `URLField`, …), `BinaryField`, the `IntegerField`
family, `DecimalField`, `FloatField`, `BooleanField`, `DateField` and
`DateTimeField`. Any other field is refused when the model is declared,
including `UUIDField`, `JSONField`, `TimeField` and `DurationField`; store
those as a `CharField` holding a format your application owns. Three details
follow from storing one canonical form per value:

- `Decimal("1.50")` is read back as `Decimal("1.5")`, which is what lets
  `filter(amount=Decimal("1.50"))` find it.
- A naive `datetime` is refused on write. Datetimes are read back as aware UTC.
- A stored value that is not in canonical form raises on read rather than
  being coerced.

## Blind indexes

A blind index is what makes an encrypted column searchable. Next to the
encrypted column, the adapter stores a short keyed hash of each value in the
`_bidx` column. `filter(email=v)` hashes `v` the same way and looks for
matching hashes. The hash is deliberately truncated, so unrelated values share
hashes: the database returns a few extra rows, and the adapter decrypts every
candidate and drops the ones that do not match before you see them.

The options decide what counts as a match, how hard the hashes are to attack,
and how much the index reveals. Choose them before the first write: changing
`idf`, `time_cost`, `memory_kib`, `normalize`, `truncate_bits` or `index_id`
later changes every stored hash, so the index has to be rebuilt.

```python
email = Encrypted(
    models.EmailField(),
    column_uuid="0c9e4b7a-2d15-4f6e-8a3b-1e7d5c9f2a64",
    index=BlindIndex(
        projected_population=100_000,   # required
        idf="argon2id",                 # the defaults, spelled out
        normalize="nfc-casefold-v1",
        truncate_bits=15,
    ),
)
email_bidx = Encrypted.index_column("email")
```

| Option | Default | Accepted values |
|---|---|---|
| `projected_population` | none: **required** | an integer, at least 16 |
| `normalize` | `"nfc-casefold-v1"` | `"nfc-casefold-v1"`, `"identity"`, `"digits-only-v1"` |
| `idf` | `"argon2id"` | `"argon2id"`, `"hmac-sha512"` |
| `time_cost` | `3` | an integer, at least 3 (Argon2id only) |
| `memory_kib` | `32768` (32 MiB) | an integer, at least 32768 (Argon2id only) |
| `truncate_bits` | `15` | an integer in the range set by `projected_population` |
| `skewed` | `False` | `True`, `False` |
| `cardinality_override` | `None` | `Override(reason=..., approved_by=..., date=...)` |
| `on_unindexable` | `"refuse"` | `"refuse"`, `"bucket"` |
| `unindexable_override` | `None` | `Override(...)`, required for `"bucket"` |
| `index_id` | `"exact"` | 1–32 lowercase letters, digits and hyphens |

### `projected_population`

How many *distinct* values you expect the column to hold, not how many rows.
It sets the allowed range for `truncate_bits`, and it gates the index: a
column with fewer than 1,024 distinct values is refused unless you record a
`cardinality_override`, because an index over so few values reveals too much
about which rows are equal.

### `normalize`

How a value is prepared before hashing. Lookups match whatever the normalizer
makes equal:

- `"nfc-casefold-v1"`: Unicode-normalized and case-folded, so
  `Ada@Example.com` matches `ada@example.com`, and `é` matches `e` plus a
  combining accent. Right for emails, usernames and names.
- `"identity"`: the exact value, so matching is case-sensitive. Right for
  codes and identifiers where case matters.
- `"digits-only-v1"`: keeps only the digits 0–9, so `+1 (555) 010-0199`
  matches `15550100199`. Right for phone numbers and similar identifiers.

### `idf`, `time_cost` and `memory_kib`

The index function, and its cost:

- `"argon2id"`: deliberately slow (10–100 ms per value), so someone holding
  the database cannot cheaply try every likely value. Use it for anything
  guessable: emails, phone numbers, national IDs, birth dates.
- `"hmac-sha512"`: microseconds. Only for high-entropy values nobody could
  enumerate, such as random tokens.

`time_cost` (passes) and `memory_kib` set the Argon2id cost. The defaults are
the minimum the specification allows; you can raise either per column, not
lower it. They are refused with `"hmac-sha512"`.

### `truncate_bits`

How many bits of each hash are kept. Fewer bits mean more unrelated values
share a hash: the index reveals less, and each lookup fetches more extra rows
to re-check. The value must satisfy 2 ≤ P / 2<sup>b</sup> < √P, where P is
`projected_population`:

| Distinct values | Allowed `truncate_bits` |
|---|---|
| 5,000 | 7–11 |
| 100,000 | 9–15 |
| 1,000,000 | 10–18 |

The default, 15, fits from 65,536 to about a billion distinct values. A value
outside the range is refused at startup.

### `skewed` and `cardinality_override`

Set `skewed=True` if a few values dominate the column, for example when most
rows share one value. A skewed column is gated like one with fewer than 1,024
distinct values. To index a gated column anyway, pass
`cardinality_override=Override(reason=..., approved_by=..., date=...)`
(`from fieldseal_django import Override`). It records who accepted the risk,
and it is refused with any field left empty.

### `on_unindexable`

For a value containing a character the pinned Unicode version does not
define, which `"nfc-casefold-v1"` cannot hash:

- `"refuse"`: the value fails validation. Right for a login email, where such
  a character usually means something upstream is broken.
- `"bucket"`: the row saves under a reserved hash shared by all such rows in
  the column, and the re-check keeps lookups correct. Right for names, where
  rare characters are legitimate. Needs
  `unindexable_override=Override(...)`, and only applies with
  `"nfc-casefold-v1"`.

### `index_id`

The index's name. It is part of the index key, so changing it means
rebuilding the index, and another implementation that searches this column,
such as a TypeScript service, must use the same value. The default is fine for
most columns.

## Settings

| Key | Required | Meaning |
|---|---|---|
| `KEY_PROVIDER` | yes | A `KeyProvider`, or a callable returning one. |
| `ALLOWED_SUITES` | yes | The cipher suites this deployment accepts. `{0xFF01}` is the only one implemented. |
| `WRITE_SUITE` | yes | The suite new values are written under: `0xFF01`. |
| `ARM_PROVISIONAL_SUITES` | to write | `True` to allow writing under a provisional suite. Setting `FIELDSEAL_ARM_PROVISIONAL_SUITES=1` in the environment does the same. Reading never needs it. |
| `READ_MODE` | no | `"strict"` (default), `"permissive"` or `"readonly"`. The last two are for migrating existing plaintext columns and warn while active. |
| `WARM_ON_READY` | no | Load keys at startup; see *Keys* below. |
| `WARM_TENANTS` | no | The tenants to load keys for when warming. |
| `CLIENT` | no | A `fieldseal.Fieldseal` client you built yourself, instead of the one the adapter builds from your models. |

An unknown key raises at startup, so a typo cannot silently change nothing.

## Keys

The core offers two key providers in Python:

- **`StaticKeyProvider`**: one data key and one index key held in memory. For
  tests and evaluation only.
- **`EnvelopeKeyProvider`**: data keys stored wrapped by your KMS. You supply
  a wrapper with an async `unwrap` method and a directory of wrapped keys. Keys
  are unwrapped only when the cache is **warmed**, never while serving a query,
  so a query never waits on the KMS.

With `EnvelopeKeyProvider`, a cold cache means every read fails with
`KEY_UNAVAILABLE`. Run `python manage.py fieldseal_warm` before serving
traffic, or set `WARM_ON_READY = True`. Warming at startup is off by default
because `ready()` also runs for `makemigrations`, `shell` and tests. If your
server loads the application before forking workers (gunicorn's `--preload`),
warm in each worker instead, so the warmed keys are not copied into all of them.

## Tenant binding

Set `FieldsealMeta(table_uuid=..., tenant_bound=True)`, then write and read
inside a tenant scope:

```python
from fieldseal_django import tenant_scope

with tenant_scope(b"tenant-a"):
    Patient.objects.create(name="Ada Lovelace", email="ada@example.com")
```

A write to a tenant-bound column with no tenant set is refused. A row written
for one tenant fails to decrypt under another: the binding is cryptographic,
not a filter. Management commands, Celery tasks and shell sessions run outside
your middleware, so they must set the tenant themselves.

## Querying encrypted columns

| Works | Refused |
|---|---|
| `filter(field=v)`, `filter(field__in=[...])` | `startswith`, `contains`, `gt`/`lt`, `range`, `regex`, `iexact` |
| `get()`, `first()`, `last()`, `count()`, `exists()`, `iterator()` | `order_by()`, `earliest()`, `latest()` on the column |
| `filter(field=None)`, `__isnull` | `exclude()`, `~Q` and `XOR` over the column |
| Reading the column after filtering on another one | Slicing and pagination of a query filtered on the column |
| `.candidates()`: the raw candidate rows, unchecked | `aggregate()`, `Min`, `Sum`, `distinct` and grouping on the column |
| | `update()` and `delete()` on a query filtered on the column |

Counts, `exists()` and `get()` answer for the verified rows, not the
candidates. Slicing is refused because the database would apply `LIMIT` before
the re-check; to paginate, fetch the verified rows and page through them in
Python. If you need the unchecked candidates, `.candidates()` returns them and
says so; it does not lift the refusals on negation or ordering.

Two more things do not go through the adapter:

- **`loaddata` is refused.** A fixture holds ciphertext, and loading it
  through Django would encrypt it a second time without any error. To move
  encrypted data, copy the ciphertext columns directly.
- **Raw SQL is not intercepted.** `.extra()`, `RawSQL()` and
  `cursor.execute()` write their parameters as given, which means plaintext
  in an encrypted column. Use the ORM, or encrypt with the core yourself.

The full list of query paths, each with the test that proves its behaviour, is
in [`REFERENCE.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/adapters/django/REFERENCE.md).

## Limitations

The specification requires every implementation to state these.

- **No protection against a compromised application process.** The keys are
  in that process, so anything the application can read, an attacker inside
  it can read.
- **Logs and caches can hold sensitive data.** An equality lookup sends the
  blind-index value as a query parameter, so database query logs, slow-query
  logs and replication logs record it. Django's cache framework holds
  whatever model instances you put in it, decrypted.
- **Storage overhead.** Each encrypted value carries 111 bytes of overhead: a
  9-byte value becomes 120 bytes. `storage="base64"` (for text-only stores)
  adds another third on top. Across a 20-column, 100-million-row table the
  overhead alone is about 220 GB, before the index columns.
- **Argon2id costs 10–100 ms per query term.** It is paid on every write that
  derives an index value and on every value you search for: `__in` with ten
  values derives ten. The cost falls on the requesting thread, not the whole
  process. It is a security property, not a tuning option.
- **The KMS is a hard dependency in the read path.** With
  `EnvelopeKeyProvider`, a KMS outage means `KEY_UNAVAILABLE` for every key not
  already in the cache.
- **The key cache holds plaintext keys in memory**, exposed to memory dumps,
  core files and swap. Evicted keys are overwritten, but Python copies `bytes`
  freely and cannot lock memory, so this narrows the exposure rather than
  closing it. The cache's lifetime and use limits are security settings.
- **Equality is the normalizer's.** A lookup matches values that are equal
  after Unicode normalization and case folding, not only identical strings.
- **No row binding.** A value is bound to its table, column and tenant, but
  not to its row, so someone with database write access can swap encrypted
  values between rows of the same column.

## Learn more

- [`REFERENCE.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/adapters/django/REFERENCE.md):
  every query path and its test, the reasoning behind each refusal, known gaps
  and development setup.
- [Adapter design](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/12-adapter-django.md)
  and the [specification](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/02-spec-v0.1.md).
- [Reviewer brief](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/16-reviewer-brief.md):
  if you can review the cryptographic design, this is where to start.
- Bugs and interoperability problems:
  [issues](https://github.com/fieldseal-dev/fieldseal-spec/issues).
  Suspected vulnerabilities:
  [`SECURITY.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/SECURITY.md),
  not a public issue.
