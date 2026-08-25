# fieldseal-django

Transparent field-level encryption at rest for Django. Design:
[`docs/12-adapter-django.md`](../../docs/12-adapter-django.md).

**Status: L1 only, and not usable in production.** Values encrypt and decrypt
transparently and the blind-index column is written correctly, but **equality
lookups are refused** — L2 is not implemented yet. Nothing here is frozen:
the suite identifier is provisional (spec §4.8), Gate 0b is open, and the
project does not invite adoption.

**AD-1 (spec §11.3): this package contains no cryptography.** It calls the
core's sync operations and nothing else. `pip`-installing it pulls in
`fieldseal`, and that is where every cipher, KDF and random draw lives.

---

## Declaring a column

```python
from django.db import models
from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta

class Patient(models.Model):
    email = Encrypted(
        models.EmailField(),                # the logical type; keeps its
                                            # validation, forms and to_python
        column_uuid="018f3c2e-...",         # REQUIRED, immutable (spec §6.1)
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,   # DISTINCT values; sizes §7.4
        ),
    )
    email_bidx = Encrypted.index_column("email")   # must come *after* `email`

    fieldseal = FieldsealMeta(table_uuid="018f3c2e-...")
```

The UUIDs are surrogates written literally in the source and captured into
migrations. They must never be derived from the app, model or field name:
spec §6.1 binds key derivation to them, so a rename would make every existing
row undecryptable. System check `fieldseal.E004` fails startup without them.

The index column is explicit rather than auto-injected because
`SQLInsertCompiler.as_sql` iterates fields in declaration order, and the
index's `pre_save` must run after the encrypted field's. Check
`fieldseal.E001` asserts the order at startup rather than trusting it.

## Settings

```python
FIELDSEAL = {
    "KEY_PROVIDER": lambda: ...,   # returns a fieldseal KeyProvider
    "ALLOWED_SUITES": {0xFF01},
    "WRITE_SUITE": 0xFF01,
    "READ_MODE": "strict",         # strict | permissive | readonly
}
```

The adapter builds the `Fieldseal` client itself, in `AppConfig.ready()`,
assembling the index registry from the model declarations. That is not a
convenience: the core's §7.4 truncation band and §7.6 cardinality gate run at
client construction, and this is the only arrangement where they see the
columns that actually exist. `FIELDSEAL["CLIENT"]` overrides it and is
reported by `fieldseal.W004` — see *Known gaps*.

## Tenant binding (spec §10, L3)

Django field types cannot see the record, so the tenant arrives through a
contextvar. **An unset tenant on a tenant-bound column refuses the write**
rather than falling back to a tenantless context, which would store a row no
correctly configured reader can decrypt:

```python
from fieldseal_django import tenant_scope

with tenant_scope(b"tenant-a"):
    Patient.objects.create(email="ada@example.com")
```

Management commands, Celery tasks and shell sessions run outside any
middleware and must set it themselves.

---

## Coverage matrix

This is what the code does **today**, verified by the test named in each row —
not the target matrix in `docs/12` §6.

| Path | Behaviour | Test |
|---|---|---|
| `Model.save()`, `create()` | ✅ encrypts; index sibling written | `test_save_then_read_returns_the_plaintext` |
| Database holds an envelope, never plaintext | ✅ | `test_the_database_holds_an_envelope_not_the_plaintext` |
| Repeated writes of one value | ✅ fresh nonce + `msg_seed` each time (spec §4.4) | `test_two_writes_of_one_value_differ` |
| `bulk_create()` | ✅ encrypts and indexes | `test_bulk_create_encrypts_and_indexes` |
| `bulk_update()` | ✅ encrypts (Case/When carries literals) | `test_bulk_update_encrypts` |
| `QuerySet.update(field=value)` | ✅ encrypts | covered by `bulk_update` path |
| `update(field=F(...))`, arithmetic, DB functions | 🛑 raises `FieldsealNotSupported` | `test_expression_rhs_is_refused` |
| Reads: `get()`, `filter()` on other columns, `.values()` | ✅ decrypts | `test_save_then_read_returns_the_plaintext` |
| `NULL` | ✅ stays `NULL`, not an envelope | `test_null_stays_null` |
| Non-text inner types (`IntegerField`, …) | ✅ round-trips as its own type | `test_non_text_inner_type_round_trips_as_its_own_type` |
| `dumpdata` / `loaddata` | ✅ ciphertext, never plaintext, in fixtures | `test_dumpdata_emits_ciphertext_not_plaintext` |
| Blind index written on insert | ✅ deterministic, case-folded, `ceil(b/8)` bytes | `TestIndexSibling` |
| Tampered ciphertext | ✅ raises; never returns garbage | `test_a_tampered_envelope_raises_rather_than_returning_garbage` |
| Tenant-bound column, no tenant set | ✅ refuses the write | `test_writing_without_a_tenant_refuses_rather_than_falling_back` |
| Wrong tenant reading a row | ✅ raises (binding is cryptographic, not a filter) | `test_another_tenant_cannot_read_the_row` |
| **`filter(field=...)` / `__in`** | 🛑 **refused — L2 not implemented** | `TestEqualityIsRefusedUntilItCanReVerify` |
| **`filter(field_bidx=...)`** | 🛑 **refused — needs §7.5 re-verification** | same |
| `contains`, `startswith`, `gt`, `range`, `regex`, `iexact`, … | 🛑 raise (spec §7.10 lists the fallback for each) | `test_refused_lookups_raise_rather_than_return_nothing` |
| `.extra()`, `RawSQL()`, `cursor.execute()` params | 🛑 **cannot intercept — plaintext hazard** | — see below |
| `django.core.cache` of model instances | ⚠️ holds plaintext (spec §10.2) | — |
| `row_id` binding (L3-row) | ❌ not in v0 | — |

### Why equality is refused rather than approximated

A direct comparison against a randomized envelope matches nothing, so
`filter(email="...")` would return an **empty queryset** — a wrong answer, not
an error. Matching on the index column alone is no better: spec §7.4 *mandates*
collisions in a truncated index, so the rows returned would include values
that merely share a fingerprint. Spec §7.5 therefore requires candidates to be
decrypted and re-verified before they reach the caller, and until that is
implemented both paths raise. Spec §10.2 is the rule: where a path would
silently return wrong results, the adapter throws.

The index column is written correctly in the meantime, so enabling L2 later
needs no backfill.

### Raw SQL is a real hazard

No ORM encrypts raw query parameters, and this adapter cannot either.
`.extra()`, `RawSQL()` and `cursor.execute()` write whatever you hand them —
in plaintext, into the encrypted column. Use ORM paths, or call the core
directly and pass the resulting envelope.

## Known gaps

- **`fieldseal.W004` instead of `E006`.** `docs/12` §5 specifies an *error*
  when `FIELDSEAL["CLIENT"]`'s index registry does not match the model
  declarations. The core exposes no public accessor for a client's validated
  registry, so implementing it would mean reading a private attribute — a
  check that breaks silently when internals move. It is reported as a warning
  naming the gap instead, and the missing accessor is a follow-up against
  `docs/09` §8.
- **No `fieldseal_gen_uuids` management command yet**; error messages name it.
- **No Postgres run in CI yet.** The suite runs on SQLite by default and
  supports Postgres via `FIELDSEAL_TEST_DB=postgres`; `docs/12` §8 requires
  both, because binary-column behaviour differs.
- **`docs/12` §1 writes `from fieldseal.django import ...`.** The import path
  is `fieldseal_django`. `fieldseal.django` would require making the core a
  namespace package or shipping adapter code inside the core distribution,
  and the second would put adapter code in the package that holds all the
  cryptography.

## Development

```
python -m venv .venv && .venv/bin/pip install -e ".[dev]" -e ../../core/python
.venv/bin/pytest tests -q
.venv/bin/ruff check src tests
.venv/bin/mypy --strict src/fieldseal_django
```
