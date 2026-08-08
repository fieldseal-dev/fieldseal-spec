# Django Adapter Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the engineering design for `adapters/django` (package `fieldseal-django`), targeting Django 6.1 / 5.2 LTS. Built directly on the verified hook analysis in `docs/04-orm-adapter-notes.md` §1; ORM facts below that were verified there are cited as such, everything else is flagged.

**Conformance target (spec §10.1):** L0 ✅ · L1 ✅ · L2 (a)+(b) ✅ · L3 via documented contextvar side channel ⚠️ · L3-row only with client-generated PKs ⚠️ · L4 ❌.

**Hard rule (spec §11.3 / AD-1):** zero cryptography in this package. The only calls into `fieldseal` are the five sync operations plus `warm`.

---

## 1. Declaration surface

Composition over Django's existing field types — the Rails `encrypts` shape that `docs/04` §8 says to adopt:

```python
from fieldseal.django import Encrypted, BlindIndex, FieldsealMeta

class Patient(models.Model):
    email = Encrypted(
        models.EmailField(),                 # the logical type; drives to_python/validation/forms
        column_uuid="018f3c2e-…",            # REQUIRED, immutable surrogate (spec §6.1)
        index=BlindIndex(                    # optional; presence declares L2
            index_id="exact",
            idf="argon2id",
            normalize="nfc-casefold-v1",
            truncate_bits=15,                # §7.4 band for P=100,000 is 9–15 bits; 16 is out of band
            projected_population=100_000,
        ),
    )
    email_bidx = Encrypted.index_column("email")   # explicit sibling column — see §1.2

    class Meta:
        pass

    fieldseal = FieldsealMeta(table_uuid="018f3c2e-…")   # REQUIRED per model
```

### 1.1 Why explicit UUID surrogates in code

`table_uuid`/`column_uuid` MUST be immutable surrogates, not SQL names (spec §6.1). They are supplied literally in the model source and captured by `deconstruct()` into migrations, so a rename never changes them. The adapter ships a management command `fieldseal_gen_uuids` that prints ready-to-paste values; a system check (E004, §5) fails if any encrypted field lacks one. Deriving them from `app_label.ModelName.field` is forbidden — that is a rename time bomb, exactly what §6.1's justification warns about.

### 1.2 The index sibling column

The blind-index column is a real, explicit field (`Encrypted.index_column`), not a hidden auto-injected one, for two reasons:

1. **Declaration-order safety.** `SQLInsertCompiler.as_sql` iterates fields in declaration order, and the index field's `pre_save` must run after the encrypted field's (`docs/04` §1, verified). With an explicit column the order is visible in source; system check **E001** asserts it at startup rather than trusting convention.
2. **Migration transparency.** `makemigrations` emits the column with no magic; the operator sees exactly what DDL runs.

`Encrypted.index_column("email")` returns a `BinaryField`-backed field whose `pre_save` reads the *sibling plaintext* off the instance (available — `pre_save` receives `model_instance`, `docs/04` §1) and calls `core.blind_index`. Storage: raw bytes, length `ceil(b/8)` — **interim pending spec gap G8** (`docs/08` §9); the field notes the pending status in its docstring.

## 2. Value path

| Concern | Design |
|---|---|
| Storage column | `BinaryField` (`bytea`) by default (spec §3.3). Optional `storage="base64"` emits `TextField` with the documented 33% overhead warning at check time (W003) |
| Write transform | Implemented in **`get_db_prep_value`**, not `get_prep_value` — the placement `docs/04` §1 verified as the one both the save path and the lookup path traverse. `pre_save` is used only by the index sibling and for `readonly`-mode write blocking |
| Read transform | `from_db_value` → `core.decrypt` → inner field's `to_python`. Covers `.values()`, aggregates, and `raw()` results (Django decrypts raw *results* — `docs/04` §1, verified) |
| Serialization to bytes | The inner field's value is serialized via a fixed, non-executing codec before encryption: text fields → UTF-8; `IntegerField`/`DecimalField`/`DateField` etc. → their `value_to_string` UTF-8 bytes. Never pickle (`docs/04` §8, the Rails `Marshal` RCE lesson) |
| `value_to_string` | Overridden so `dumpdata` emits base64 ciphertext rather than misbehaving (`docs/04` §1 gotcha) |
| Expressions | `QuerySet.update(field=value)` encrypts (hits `get_db_prep_save` — `docs/04` §1 table). `update(field=F(...))` and any expression RHS **raise `FieldsealNotSupported`** — `get_db_prep_save` short-circuits on expressions (verified), so silence here would write garbage or plaintext |
| `bulk_update` | Supported — routes through `Case/When` with `Value(attr, output_field=field)` which reaches `get_db_prep_save` (`docs/04` §1, verified). Covered by an integration test because the path is subtle |

## 3. Query path

### 3.1 L2 (a) — explicit index property

`Patient.objects.filter(email_bidx=plaintext)`: the index field's `get_db_prep_value` derives the blind index from the plaintext parameter through ordinary parameter conversion. Works today with zero rewriting; the query surface is explicit (spec §10 L2(a)).

### 3.2 L2 (b) — transparent rewrite

A registered `Exact` lookup on the encrypted field compiles to a `Col` for the sibling index column (the clean route `docs/04` §1 documents, composing with `Q`, joins, and subqueries):

```python
class EncryptedExact(Lookup):
    lookup_name = "exact"
    def as_sql(self, compiler, connection):
        bidx_field = self.lhs.output_field.fieldseal_index_field
        bidx_col = bidx_field.get_col(self.lhs.alias)
        lhs_sql, lhs_params = compiler.compile(bidx_col)
        rhs = core.blind_index(serialize(self.rhs), bidx_field.fieldseal_ctx)
        return f"{lhs_sql} = %s", [*lhs_params, rhs]
```

`In` gets the same treatment (N index values OR'd/`IN`, spec §7.10). **Mandatory over-fetch re-verification (spec §7.5):** the adapter wraps matching querysets in a decrypt-and-compare filter before results reach the caller; the queryset's `_fetch_all` path re-verifies candidates and drops collisions. Pagination guidance (over-fetch → decrypt → filter → paginate) goes in the package docs verbatim from §7.5. **[Design note: intercepting `_fetch_all` is private-API territory — the implementation may instead return a documented `.verified()` queryset method as the supported surface and make plain `filter()` on encrypted fields emit the candidate semantics warning. Decide during implementation; either way the *default documented pattern* must re-verify.]**

### 3.3 Refused lookups (spec §10.2 — throw, never degrade)

On the encrypted field, every lookup except the rewritten `exact`/`in` (and `isnull`) raises `FieldsealNotSupported` with the honest-fallback text from spec §7.10: `contains`, `icontains`, `startswith`, `gt/gte/lt/lte`, `range`, `regex`, `iexact` (case folding belongs to the normalizer, not the query), `search`. Without a declared index, `exact`/`in` raise too ("no blind index declared for this column").

## 4. Context assembly and modes

- `FieldContext` per column is built once at `contribute_to_class` time (table/column UUIDs, suite from settings). Tenant: `fieldseal.django.context.set_tenant(tenant_id)` contextvar, with a shipped middleware example; documented as the L3 side channel of spec §10 — including that any code path outside the middleware scope (management commands, celery tasks) must set it explicitly or encryption fails closed (`ConfigurationError`), never silently falls back to tenantless context when a tenant-bound column is declared.
- `row_id` binding: not in v0 of the adapter. Django cannot see the PK at INSERT with identity keys (`docs/04` PK table); L3-row support arrives only for models the check system can prove use client-generated PKs (`default=uuid7`-style) — deferred, tracked in the coverage matrix as ❌ with the reason.
- Read mode has exactly one owner: `settings.FIELDSEAL["READ_MODE"]` feeds the client the **adapter constructs** (§7) — there is no second mode knob, and the client is immutable after construction (docs/09 §2), so a mode change is a process restart. `permissive` emits a `fieldseal.plaintext_read` signal per event plus a counter metric (spec §10.3 requires the warning + SHOULD metric).

## 5. System checks (startup-enforced correctness)

| ID | Level | Condition |
|---|---|---|
| fieldseal.E001 | Error | Index sibling declared before its encrypted field (order rule, §1.2) |
| fieldseal.E002 | Error | `unique=True` on an encrypted column (unenforceable under a randomized suite, spec §7.10) — and **not** to be moved to the index column either: the §7.4 band mandates collisions, so a UNIQUE truncated index rejects legitimate distinct values (spec issue G12) |
| fieldseal.E003 | Error | Blind index declared without `projected_population`, or population below the §7.6 gate without a logged override — this surfaces the core's construction-time gate (docs/09 §2) as a system check at startup; the core remains the enforcing layer |
| fieldseal.E004 | Error | Missing `table_uuid`/`column_uuid` |
| fieldseal.E005 | Error | Encrypted field **or its index sibling** named in a `UniqueConstraint` or composite index (uniqueness over ciphertext is meaningless; uniqueness over a truncated index is G12) |
| fieldseal.E006 | Error | A user-supplied `FIELDSEAL["CLIENT"]` whose index registry does not exactly match the model-declared indexes (§7) |
| fieldseal.W001 | Warning | Encrypted field in `ModelAdmin.search_fields` (generates `icontains` → will raise at runtime; `docs/04` §1 gotcha) |
| fieldseal.W002 | Warning | `db_index=True` on ciphertext column (pointless index bloat) |
| fieldseal.W003 | Warning | base64 storage selected (documented 33% overhead, spec §3.3) |

## 6. Coverage matrix (the AD-2 normative deliverable)

Shipped in the package README, kept in sync with tests by generating both from one table:

| Path | Behavior |
|---|---|
| `Model.save()`, `bulk_create()` | ✅ encrypts (+ index sibling via `pre_save`) |
| `QuerySet.update(field=value)` | ✅ encrypts; ⚠️ index sibling must be passed explicitly (no `pre_save` on `.update()` — `docs/04` §1); check-time documentation + runtime error if index column omitted while encrypted column present |
| `bulk_update()` | ✅ encrypts |
| `update(field=F(...))`, expression RHS | 🛑 raises `FieldsealNotSupported` |
| `filter(email=…)` / `In` | ✅ rewritten to index column when declared; 🛑 raises otherwise |
| Other lookups | 🛑 raise (§3.3) |
| `.values()`, aggregates on other columns, `raw()` results | ✅ decrypts |
| `.extra()`, `RawSQL()`, `cursor.execute()` params | 🛑 **cannot intercept** — documented plaintext hazard (`docs/04` §1: no ORM encrypts raw parameters); listed in README with remediation (use ORM paths or call the core directly) |
| `django.core.cache` of model instances | ⚠️ holds plaintext (spec §10.2) — documented, with per-field `exclude_from_cache` guidance |
| `dumpdata`/`loaddata` | ✅ ciphertext round-trip via `value_to_string` |

## 7. Async, warm-up, and operations

- All field hooks are sync; Django's async ORM wraps sync (`docs/04` §1) — so the DEK cache is mandatory, and the adapter's docs say so in bold. `warm()`: an `AppConfig.ready()` hook schedules background refresh via the provider; a `fieldseal_warm` management command supports pre-deploy cache priming.
- Settings surface and client construction: `FIELDSEAL = {"KEY_PROVIDER": callable, "READ_MODE": …, "ALLOWED_SUITES": …, "WRITE_SUITE": …, "CACHE": …}`. The **adapter constructs the `Fieldseal` client** in `AppConfig.ready()`, after model loading, assembling the `IndexDeclaration` registry from the model-level `BlindIndex(...)` declarations — that is the only way the core's construction-time validation (docs/09 §2: §7.6 gate, §7.4 band) runs against the indexes actually declared on models. Escape hatch: `FIELDSEAL["CLIENT"]` (callable returning a pre-built client) for deployments that must own provider wiring, gated by system check E006 — its index registry must exactly match the model declarations, or startup fails.
- Migration/backfill: the adapter ships nothing beyond field defaults; the zero-downtime procedure and tooling live in `tools/backfill` (`docs/15-tooling.md`), following the dual-write shape of `docs/04` §11 (backfill MUST use `bulk_update`, never `queryset.update(F(...))`).

## 8. Test plan

- **Path matrix tests:** one integration test per row of §6, against Postgres and SQLite in CI (binary column behavior differs; both are supported targets).
- **Refusal tests:** every §3.3 lookup and every 🛑 row asserts the typed exception, not a generic error.
- **Ordering regression:** a model with index-before-encrypted declaration must fail E001; a model without the check bypassed must produce correct sibling values under `bulk_create`.
- **Candidate re-verification:** seed two plaintexts that collide at the configured truncation length (construct via brute force at small `b` in the test), assert the collision row is filtered out.
- **Permissive-mode metric:** plaintext read increments the signal exactly once per value.
- **Cross-language sharing test (the point of the project):** a Postgres row written by this adapter is decrypted by the TypeScript core, and vice versa, using the `cross/` key material — this is the adapter-level echo of the CI cross job.

## 9. Deliberate non-goals

No transparent `row_id` binding (v0), no query support beyond `exact`/`in`/`isnull`, no admin search integration, no automatic tenant inference from the request (explicit contextvar only), no support for `Encrypted` on relational fields (`ForeignKey` stays plaintext — spec §7.10), no Django < 5.2 support.
