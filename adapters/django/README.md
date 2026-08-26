# fieldseal-django

Transparent field-level encryption at rest for Django. Design:
[`docs/12-adapter-django.md`](../../docs/12-adapter-django.md).

**Status: L1 + L2, and not usable in production.** Values encrypt and decrypt
transparently, and `filter(email=...)` / `__in` are served through the blind
index with the spec §7.5 re-verification that makes them correct. Nothing here
is frozen: the suite identifier is provisional (spec §4.8), Gate 0b is open,
and the project does not invite adoption.

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
columns that actually exist. `FIELDSEAL["CLIENT"]` overrides it, and
`fieldseal.E006` then checks the supplied client's registry against the model
declarations — an exact match in both directions, comparing the validated
form, because a client carrying an index the models do not declare stores
values for that column under rules no model states and nothing raises.

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
| `QuerySet.update(field=value)` | ✅ encrypts | `test_plain_update_encrypts` |
| `update(field=F(...))`, arithmetic, DB functions | 🛑 raises `FieldsealNotSupported` | `test_expression_rhs_is_refused` |
| Reads: `get()`, `filter()` on other columns | ✅ decrypts | `test_save_then_read_returns_the_plaintext` |
| `.values()`, `values_list()`, `only()`, `raw()` results | ✅ decrypts | `TestReadPathsTheMatrixClaims` |
| `NULL` | ✅ stays `NULL`, not an envelope | `test_null_stays_null` |
| Non-text inner types (`IntegerField`, …) | ✅ round-trips as its own type | `test_non_text_inner_type_round_trips_as_its_own_type` |
| `dumpdata` | ✅ ciphertext, never plaintext, in fixtures | `test_dumpdata_emits_ciphertext_not_plaintext` |
| **`loaddata`** | 🛑 **refused — would double-encrypt silently** | `TestLoaddataIsRefused` |
| Blind index written on insert | ✅ deterministic, case-folded, `ceil(b/8)` bytes | `TestIndexSibling` |
| Tampered ciphertext | ✅ raises; never returns garbage | `test_a_tampered_envelope_raises_rather_than_returning_garbage` |
| Tenant-bound column, no tenant set | ✅ refuses the write | `test_writing_without_a_tenant_refuses_rather_than_falling_back` |
| Wrong tenant reading a row | ✅ raises (binding is cryptographic, not a filter) | `test_another_tenant_cannot_read_the_row` |
| **`filter(field=...)` / `__in`** | ✅ rewritten to the index, then §7.5-verified | `TestEqualityRoundTrips`, `TestReVerification` |
| A colliding candidate row | ✅ dropped before it reaches the caller | `test_a_colliding_candidate_is_dropped` |
| `count()`, `exists()`, `first()`, `last()` | ✅ count/answer **verified** rows, not candidates | `TestReVerification` |
| Case variant / canonical-equivalent spelling | ✅ matches — equality is the normalizer's (G19) | `TestNormalizedEquality` |
| Slicing / pagination on a verified queryset | 🛑 refused — LIMIT precedes verification (§7.5) | `test_slicing_refuses` |
| `update()`, `delete()` on a verified queryset | 🛑 refused — would write to collision rows | `test_sql_answered_paths_refuse` |
| `aggregate()`, `values()`, `values_list()`, `only()`, `defer()` | 🛑 refused — answered from SQL, or drop the column verification needs | same |
| `exclude(field=...)` | 🛑 refused — false negatives are unrecoverable | `test_exclude_refuses` |
| `Q` with `OR`/negation over an encrypted column | 🛑 refused — cannot decide a candidate | `test_or_through_q_refuses` |
| `.candidates()` | ✅ bucket semantics, unverified, every refusal lifted | `TestCandidatesOptOut` |
| Verifying manager auto-installed | ✅ when the model declares no manager | `test_the_manager_is_installed_without_being_asked_for` |
| Hand-written manager | 🛑 E008 — not overwritten, reported | `test_a_hand_written_manager_is_not_replaced_but_is_reported` |
| **`filter(field_bidx=...)`** | 🛑 **refused — cannot re-verify from a field hook** | `test_exact_on_the_index_column_refuses_naming_the_collision_rule` |
| `contains`, `startswith`, `gt`, `range`, `regex`, `iexact`, … | 🛑 raise (spec §7.10 lists the fallback for each) | `test_refused_lookups_raise_rather_than_return_nothing` |
| `.extra()`, `RawSQL()`, `cursor.execute()` params | 🛑 **cannot intercept — plaintext hazard** | — see below |
| `django.core.cache` of model instances | ⚠️ holds plaintext (spec §10.2) | — |
| `on_unindexable="refuse"` | ✅ field-level `ValidationError`, §10.2 wording | `TestRefuse`, `TestTheMessage` |
| `on_unindexable="bucket"` | ✅ row saves, stays findable by its own value | `TestBucket` |
| Two different unindexable values | ✅ do not match each other (§7.5 does the work) | `test_two_different_unindexable_values_do_not_match_each_other` |
| `manage.py fieldseal_gen_uuids` | ✅ prints surrogates; never edits source | `tests/test_gen_uuids.py` |
| `manage.py fieldseal_warm` | ✅ primes data **and** index keys (spec §5.2) | `tests/test_warm.py` |
| `FIELDSEAL["WARM_ON_READY"]` | ✅ opt-in; warns rather than dying | `TestReadyHook` |
| A row written here, read by the TypeScript core | ✅ CI cross matrix; `django` is a producer | `tests/test_cross_produce.py` |
| A blind index written here, derived by another core | ❌ next cross-language increment | — |
| `row_id` binding (L3-row) | ❌ not in v0 | — |

### Equality, and the part that is not the rewrite

`filter(email="ada@example.com")` compiles to a comparison on the `email_bidx`
sibling, not on the ciphertext — a direct comparison against a randomized
envelope matches nothing and would return an empty queryset, which is a wrong
answer rather than an error.

**That rewrite alone is only half of it.** Spec §7.4 *mandates* collisions in
a truncated index, so the rows the database returns are a **superset** of the
answer. Spec §7.5 requires candidates to be decrypted and re-verified before
they reach the caller, and `FieldsealQuerySet` does that in `_fetch_all` — so
the default path is the safe path and there is nothing to remember. The
manager is installed automatically on models that declare none of their own;
where you wrote your own, system check **E008** asks you to mix
`FieldsealQuerySet` in rather than the adapter silently replacing it.

**What shrinks is the design work.** Verification drops rows after the
database has already applied `COUNT`, `LIMIT` and `OFFSET`, so anything
answered from SQL would be answering about candidates. `count()`, `exists()`,
`first()` and `last()` are implemented against verified rows; slicing,
`update()`, `delete()`, `aggregate()` and the projections are **refused**, and
so is `exclude()` — a filter's false positives are recoverable, an exclusion's
false negatives are not. `.candidates()` opts out of all of it and hands you
bucket semantics, documented as unverified.

**Equality is the column's normalizer's** (G19). On a `nfc-casefold-v1`
column, `filter(email="ada@example.com")` matches a row stored as
`Ada@Example.com`, and precomposed `é` matches decomposed `e`+`◌́`. That is
why `iexact` is refused: the column has exactly one equality, and a second
would be a second question the index cannot answer.

**Pagination is the one to read twice.** Spec §7.5 states outright that
pagination built directly on an indexed encrypted column is incorrect. The
documented pattern is over-fetch → decrypt → filter → paginate.

### Why `loaddata` is refused

`dumpdata` writes base64 ciphertext, which is what stops fixtures leaking
plaintext. Reloading one is the problem: Django's deserializer routes every
fixture value through `to_python`, the same hook that sees plaintext a user
typed, so the ciphertext is accepted as text, stored, and **encrypted a second
time**. The row then reads back as base64 instead of the value, with no error
anywhere. Measured: text columns corrupted while an `IntegerField` column
survived, so the damage is per-inner-type and a smoke test on the wrong column
reports success.

The refusal keys on the core's `is_ciphertext`, which spec §3.4 defines as
total over arbitrary input, and is used in the fail-closed direction only — the
worst case is refusing a plaintext that happens to be valid base64 for a valid
envelope. Supporting `loaddata` properly needs a way to tell fixture ciphertext
from user plaintext at that hook, which is a design question, not an oversight.
To move encrypted data between databases, use the backfill tooling (`docs/15`)
or copy the ciphertext column directly.

### Raw SQL is a real hazard

No ORM encrypts raw query parameters, and this adapter cannot either.
`.extra()`, `RawSQL()` and `cursor.execute()` write whatever you hand them —
in plaintext, into the encrypted column. Use ORM paths, or call the core
directly and pass the resulting envelope.

### Unindexable values, and the transaction footnote

A value containing a character the pinned Unicode version does not define
**stores fine and cannot be indexed**. Per column you choose `refuse` (the
default — right for a login email, where such a character usually means
something upstream is broken) or `bucket` (right for a legal name, where rare
characters legitimately appear). `bucket` needs the same
`{reason, approved_by, date}` ceremony spec §7.6 requires elsewhere.

Under `refuse`, **validate through a form or `full_clean()`**. The index can
only be derived in `pre_save`, which runs inside the INSERT, so a refusal
there marks the transaction for rollback — Django does that for any exception
out of `save()`. `Encrypted.validate()` moves the failure to `full_clean()`,
which every `ModelForm` calls first, so the form path never touches the
database. A direct `Model.objects.create()` still raises *and* leaves the
transaction needing a rollback.

### Warming the cache is not optional under an `EnvelopeKeyProvider`

Every field hook is synchronous, so the core confines KMS unwrapping to
`warm()` and forbids the value path from blocking on network (`docs/09` §8.2).
A cold cache therefore serves `KEY_UNAVAILABLE` on **every** read. Run
`manage.py fieldseal_warm` before serving traffic, or set
`FIELDSEAL["WARM_ON_READY"] = True`.

It is off by default on purpose: `ready()` runs for `makemigrations`, `shell`
and every test process, and a migration that cannot run because the KMS is
unreachable is a worse failure than a cold cache. Tenant-bound columns need
their tenants named (`--tenant`, or `FIELDSEAL["WARM_TENANTS"]`) — the adapter
cannot enumerate them.

## Known gaps

- **`dumpdata` re-encrypts** rather than emitting the stored bytes, so a dump
  is not byte-reproducible, and it needs a tenant scope: `dumpdata` over a
  tenant-bound model outside `tenant_scope(...)` refuses. Both are correct
  (fail closed) and neither is obvious.
- **The AD-1 CI grep is a tripwire, not a proof** — it matches `import`/`from`
  lines and would not catch `importlib`.
- **E001 is hygiene, not a live bug.** Declaration order does not affect the
  index value today (measured); the check exists for column-order determinism
  and because L3-row binding would make order load-bearing. `docs/12` §1.2
  carries the correction.
- **Postgres and SQLite both run in CI**, per `docs/12` §8. This earned
  itself immediately: `bulk_update` wraps each `Value` in a `Cast` on
  PostgreSQL (`requires_casted_case_in_updates`) and not on SQLite, so the
  same call builds a different expression tree per backend and the
  expression refusal passed on one and failed on the other. Run Postgres
  locally with `FIELDSEAL_TEST_DB=postgres`.
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
