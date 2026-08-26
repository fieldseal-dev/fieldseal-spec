# Django Adapter Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the engineering design for `adapters/django` (package `fieldseal-django`), targeting Django 6.1 / 5.2 LTS. Built directly on the verified hook analysis in `docs/04-orm-adapter-notes.md` §1; ORM facts below that were verified there are cited as such, everything else is flagged.

**Conformance target (spec §10.1):** L0 ✅ · L1 ✅ · L2 (a)+(b) ✅ · L3 via documented contextvar side channel ⚠️ · L3-row only with client-generated PKs ⚠️ · L4 ❌.

**Hard rule (spec §11.3 / AD-1):** zero cryptography in this package. The only calls into `fieldseal` are the five sync operations plus `warm`.

---

## 1. Declaration surface

Composition over Django's existing field types — the Rails `encrypts` shape that `docs/04` §8 says to adopt:

```python
from fieldseal_django import Encrypted, BlindIndex, FieldsealMeta

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

1. **Declaration-order clarity.** With an explicit column the order is visible in source, and system check **E001** asserts it at startup. **Corrected at implementation (2026-08-25): the original reason given here was wrong.** This section claimed the index field's `pre_save` "must run after the encrypted field's" because `SQLInsertCompiler.as_sql` iterates in declaration order. Measured: a model with the sibling declared *first* produces the **byte-identical** index value, because `pre_save` reads the instance attribute, which Python set long before any field hook ran. Declaration order cannot affect the index today. E001 is kept for the reasons that are true — deterministic column order in migrations and DDL, readability, and the fact that L3-row binding would make the source's `pre_save` mutate the instance and turn order into a real dependency whose failure *would* be silent. Establishing it now is free; claiming a failure that cannot happen is not.
2. **Migration transparency.** `makemigrations` emits the column with no magic; the operator sees exactly what DDL runs.

`Encrypted.index_column("email")` returns a `BinaryField`-backed field whose `pre_save` reads the *sibling plaintext* off the instance (available — `pre_save` receives `model_instance`, `docs/04` §1) and calls `core.blind_index`. Storage: raw bytes, length `ceil(b/8)`, per spec §7.11 (G8 resolved) — normative now, not interim. The generated column is `BinaryField`, and the adapter's migration check MUST verify the column's collation is binary where the backend allows a text index column at all (§7.11); MySQL is the case that bites, since a `VARCHAR` index column under a `_ci` collation silently matches values the core treats as distinct.

## 2. Value path

| Concern | Design |
|---|---|
| Storage column | `BinaryField` (`bytea`) by default (spec §3.3). Optional `storage="base64"` emits `TextField` with the documented 33% overhead warning at check time (W003) |
| Write transform | Implemented in **`get_db_prep_value`**, not `get_prep_value` — the placement `docs/04` §1 verified as the one both the save path and the lookup path traverse. `pre_save` is used only by the index sibling and for `readonly`-mode write blocking |
| Read transform | `from_db_value` → `core.decrypt` → inner field's `to_python`. Covers `.values()`, aggregates, and `raw()` results (Django decrypts raw *results* — `docs/04` §1, verified) |
| Serialization to bytes | The inner field's value is serialized via a fixed, non-executing codec before encryption: text fields → UTF-8; `IntegerField`/`DecimalField`/`DateField` etc. → their `value_to_string` UTF-8 bytes. Never pickle (`docs/04` §8, the Rails `Marshal` RCE lesson) |
| `value_to_string` | Overridden so `dumpdata` emits base64 ciphertext rather than **plaintext** into a fixture file (`docs/04` §1 gotcha). It re-encrypts rather than emitting the stored bytes, so a dump is not byte-reproducible, and it needs the tenant context — `dumpdata` over a tenant-bound model outside a `tenant_scope` refuses |
| `loaddata` | **Refused (v0).** Django's deserializer routes fixture values through `to_python`, which also sees user-typed plaintext, so a reloaded fixture's ciphertext is stored and encrypted *again* — the row then reads back as base64 instead of the value, silently. Measured 2026-08-25: text columns corrupted, an `IntegerField` column survived, so the damage is per-inner-type and invisible to a smoke test on the wrong column. `to_python` now refuses a value the core's §3.4 `is_ciphertext` recognizes, in the fail-closed direction only. Moving encrypted data between databases is `tools/backfill`'s job (`docs/15`) |
| Expressions | `QuerySet.update(field=value)` encrypts (hits `get_db_prep_save` — `docs/04` §1 table). `update(field=F(...))`, arithmetic and database functions **raise `FieldsealNotSupported`** — `Field.get_db_prep_save` returns anything with `as_sql` untouched, so silence here would write garbage or plaintext. **Corrected at implementation (2026-08-25): "any expression RHS" is too wide and takes `bulk_update` down with it.** `bulk_update` builds a `Case/When` whose results are `Value(...)` literals, and `Value.as_sql` calls `output_field.get_db_prep_save` on the literal (`for_save=True`), which re-enters the field and encrypts. The refusal therefore tests the *written* expression, not its conditions: `Value` and `Case` trees of `Value`s are served, everything else with `as_sql` is refused. A `When` may reference any column it likes, because that decides which row is updated rather than what is stored in it |
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

`In` gets the same treatment (N index values `IN`'d, spec §7.10).

**Mandatory over-fetch re-verification (spec §7.5) — decided at implementation, 2026-08-26.** The design note this paragraph used to carry is settled as **option C**: `FieldsealQuerySet._fetch_all` re-verifies by default and **`.candidates()`** opts out. The rejected alternative was an explicit `.verified()`, whose failure mode is silent — one forgotten call returns collision rows, which is the §10.2 wrong answer the adapter exists to prevent. The safe path has to be the default path.

**The manager arrives without being asked for.** A default that must be installed by hand is not a default, so `class_prepared` installs `FieldsealManager` on any model with an indexed encrypted column **that declares no manager of its own** — Django marks its own auto-created `objects` with `auto_created`, which is an exact test for "the author did not choose". Where the author did choose, the adapter does not overwrite it; system check **E008** requires them to mix `FieldsealQuerySet` in.

**What re-verification compares is G19 ([#78](https://github.com/fieldseal-dev/fieldseal-spec/issues/78)):** `normalize(stored)` against `normalize(queried)` under the index's own normalizer. The normalizer comes from the core (`fieldseal.normalize`, made public for this); an adapter that reimplemented `nfc-casefold-v1` would be reimplementing portability surface where a disagreement is a silent lookup miss.

**The design work is not the rewrite, it is what shrinks.** Verification drops rows *after* the database has applied `COUNT`, `LIMIT` and `OFFSET`, so every queryset method answered from SQL is wrong by default. Each is handled explicitly:

| Surface | Behaviour on a verifying queryset | Why |
|---|---|---|
| iteration, `list()`, `len()`, `bool()` | verified | all route through `_fetch_all` |
| `count()`, `exists()`, `first()`, `last()` | **implemented correctly** | materialize and verify; `exists()`/`first()` stop at the first verified match. Cost is bounded by the bucket, which §7.4 sizes at `2 ≤ P·2^−b < √P` by design |
| `get()` | **implemented correctly** | Django's `get()` samples `LIMIT MAX_GET_RESULTS` (21) of the *candidates*, so a §7.4 bucket larger than the window could hold the true match past it and raise `DoesNotExist` about a row that exists. Verified `get()` materializes the whole bucket (found in the PR #79 review round) |
| `iterator()`, `aiterator()` | **verified, still streaming** | both bypass `_fetch_all` by design (no result cache), so the stream is filtered as it passes. `aiterator` is the one async method that does not delegate to its sync twin; every other `a*` method wraps the overridden sync one, and the test suite pins that |
| `filter(field=None)`, `__isnull`, `exclude(field=None)` | **served exactly, no verification needed** | NULL plaintext stores NULL in both columns and Django rewrites `exact=None` to `isnull`, so the SQL is `IS [NOT] NULL` on the envelope column itself — precise, touches no blind index, allowed in any combination including negation and `OR` |
| slicing / pagination / `qs[i]` | **refused** | LIMIT/OFFSET precede verification, so the page is short and the next one misaligned — and `qs[i]` is `LIMIT i,1`, the `first()` failure behind different syntax. §7.5 states outright that pagination built directly on an indexed encrypted column is incorrect; the documented pattern is over-fetch → decrypt → filter → paginate |
| `earliest()`, `latest()` | **refused** | `LIMIT 1` applied by the database before verification — `first()`'s failure behind another name; the message points at `.order_by(f).first()` |
| `update()`, `delete()` | **refused** | the statement runs in the database against the bucket, so it would write to or destroy rows whose value differs. The only unrecoverable case on this list |
| `aggregate()` | **refused** | answered from SQL, over candidates |
| `values()`, `values_list()`, `only()`, `defer()` | **refused** | they decide which columns come back, and verification needs the encrypted one |
| `exclude()` | **refused** | the SQL excludes the whole bucket, so it drops rows it should keep and they never reach the adapter for §7.5 to put back. **A filter's false positives are recoverable; an exclusion's false negatives are not** |
| `Q` with `OR`/`XOR` or negation over an encrypted column | **refused** | a candidate may be present because another branch matched, so verification cannot decide it without evaluating the whole predicate in Python. A **plain AND of positive terms** records obligations and verifies exactly like keyword arguments — under AND, every returned row must satisfy the encrypted term too, so per-term verification is exact |
| subquery embedding (`__in=qs`, `Subquery`, `Exists`) | **refused** | the subquery runs entirely in the database, where §7.5 cannot run, so the outer query would receive unverified candidates — silently. Escape: materialize verified pks, or embed `.candidates()` |
| `union()`, `intersection()`, `difference()` | **refused, on either side** | the combined statement is answered by the database, and this queryset's obligations cannot be applied to rows the *other* operand contributed — the AND-composition argument only holds within one WHERE clause |
| relation traversal (`filter(rel__enc=...)`, forward or reverse) | **refused, at two layers** | the join matches the blind-index sibling, but §7.5 runs on the queryset that owns the column: a `FieldsealQuerySet` refuses at `filter()` time, and the lookup itself refuses at compile time for **every other queryset** — a related model with a plain manager never passes through this package's queryset at all, so the field layer is the layer that actually holds (PR #79 review round). Escapes: `filter(rel__in=Owner_qs.filter(col=v).candidates())` for bucket semantics, or verified primary keys |

`.candidates()` lifts every refusal in that table — including the filter-time ones (`exclude`, `Q` under `OR`), since the SQL semantics they refuse are exactly what it hands over — and returns bucket semantics, documented as unverified. An escape hatch that refuses the same things is not one. The one refusal it cannot lift is the cross-model traversal, because another model's queryset cannot take on §7.5; the opt-in there is the *owning* model's `.candidates()`, embedded as above.

**The G20 family ([#80](https://github.com/fieldseal-dev/fieldseal-spec/issues/80), closed 2026-08-26): SQL that computes on envelope bytes.** A second refusal family, orthogonal to §7.5 verification and active on **every** `FieldsealQuerySet`, obligations or none — a meaningless order needs no filter present to be wrong — and **not lifted by `.candidates()`**: bucket semantics are a meaningful thing to accept for a filter; ciphertext order has no semantics to accept. Measured before the refusals were written: `order_by("email")` returned envelope-byte order; `values("email").annotate(n=Count("pk"))` returned four groups of `n=1` where the truth was three with one `n=2`, two groups printing the identical key; **`aggregate(Min("age"))` over `{30, 40}` returned `40`** — the byte-wise minimum *envelope* decrypts cleanly to an arbitrary row's value, presented as the minimum, with nothing raised.

| Surface (any `FieldsealQuerySet`) | Behaviour | Why |
|---|---|---|
| `order_by()` naming an encrypted column — direct, `-`-prefixed, through a relation, or inside an expression (`F("email").asc()`, `Lower("email")`) | **refused** | sorts envelope bytes; §7.10 ciphertext row |
| `earliest()`/`latest()` naming one, or falling back to a `Meta.get_latest_by` that names one | **refused** | the same ordering through a different door (`add_ordering`, never `order_by()`) |
| aggregate or function expressions referencing an encrypted column, in `aggregate()`, `annotate()`, `alias()`, `values()` | **refused** | `MIN()`/`MAX()` return an arbitrary envelope's value decrypted and presented as the extreme; `SUM()` produces garbage misreported as `NOT_CIPHERTEXT`; `COUNT(DISTINCT)` counts envelopes; `LENGTH()` reports ciphertext size. A non-null count is `filter(f__isnull=False).count()` |
| `values(...).annotate(<aggregate>)` with an encrypted column in the projection | **refused** | the projection becomes the `GROUP BY`: one group per row, wrong counts under identical printed keys |
| `distinct("field")`, or `distinct()` over a `values()`/`values_list()` projection naming an encrypted column (either call order) | **refused** | every envelope is distinct; deduplicates nothing, silently |
| a bare `F("email")` annotation | **allowed** | it only *selects* the column, and the converter decrypts what comes back — exact |
| `order_by("email_bidx")` (the index sibling) | **allowed** | deterministic, documented as meaningless — a stable tiebreaker |
| `Meta.ordering` / `Meta.get_latest_by` naming an encrypted column | **system check E009** (Error) | the compiler applies both directly, where no queryset refusal can see them |
| an encrypted column the admin changelist would order by | **system check W005** (Warning) | `ModelAdmin.ordering` breaks every changelist request; a sortable column breaks on a header click — both now raise, so the check says so at startup |

**Interception honesty (`docs/04` §1):** Django resolves ordering names to a plain `Col` with no field hook in the path, so the refusals are queryset-level plus the two checks — which means a *plain-manager* model ordering through a relation onto another model's encrypted column is not reachable, unlike the equality traversal, which is closed at the lookup layer. That residue is documented in the raw-SQL class.

### 3.3 Refused lookups (spec §10.2 — throw, never degrade)

On the encrypted field, every lookup except the rewritten `exact`/`in` (and `isnull`) raises `FieldsealNotSupported` with the honest-fallback text from spec §7.10: `contains`, `icontains`, `startswith`, `gt/gte/lt/lte`, `range`, `regex`, `iexact` (case folding belongs to the normalizer, not the query — and as of G19 ([#78](https://github.com/fieldseal-dev/fieldseal-spec/issues/78)) that is a rule rather than an aside: §7.5 re-verification compares normalized values, so on a `nfc-casefold-v1` column `exact` **is** the caseless lookup and a second one would be a second equality the index cannot serve), `search`. Without a declared index, `exact`/`in` raise too ("no blind index declared for this column").

## 4. Context assembly and modes

- `FieldContext` per column is built once at `contribute_to_class` time (table/column UUIDs, suite from settings). Tenant: `fieldseal.django.context.set_tenant(tenant_id)` contextvar, with a shipped middleware example; documented as the L3 side channel of spec §10 — including that any code path outside the middleware scope (management commands, celery tasks) must set it explicitly or encryption fails closed (`ConfigurationError`), never silently falls back to tenantless context when a tenant-bound column is declared.
- `row_id` binding: not in v0 of the adapter. Django cannot see the PK at INSERT with identity keys (`docs/04` PK table); L3-row support arrives only for models the check system can prove use client-generated PKs (`default=uuid7`-style) — deferred, tracked in the coverage matrix as ❌ with the reason.
- Read mode has exactly one owner: `settings.FIELDSEAL["READ_MODE"]` feeds the client the **adapter constructs** (§7) — there is no second mode knob, and the client is immutable after construction (docs/09 §2), so a mode change is a process restart. `permissive` emits a `fieldseal.plaintext_read` signal per event plus a counter metric (spec §10.3 requires the warning + SHOULD metric).

## 5. System checks (startup-enforced correctness)

| ID | Level | Condition |
|---|---|---|
| fieldseal.E001 | Error | Index sibling declared before its encrypted field, or declared against a field with no `BlindIndex`, or a `BlindIndex` with no sibling column (§1.2 — note the corrected rationale there: this is column-order hygiene and future-proofing, not a live corruption) |
| fieldseal.E002 | Error | `unique=True` on an encrypted column (unenforceable under a randomized suite, spec §7.10) — and **not** to be moved to the index column either: the §7.4 band mandates collisions, so a UNIQUE truncated index rejects legitimate distinct values. Normative as of §7.10 (G12 resolved 2026-08-09); the check's error text points the user at §7.10's application-level fallback and its race |
| fieldseal.E003 | Error | Blind index declared without `projected_population`, or population below the §7.6 gate without a logged override — this surfaces the core's construction-time gate (docs/09 §2) as a system check at startup; the core remains the enforcing layer. **`FIELDSEAL["CLIENT"]` used to switch this off silently** (found 2026-08-26 while implementing E006): `build_client` returns a supplied client immediately without ever assembling the registry, so on that path the core never sees the model declarations and neither the §7.4 band nor the §7.6 gate ran against them. The E006 check validates the model side anyway, and reports a refusal there under **E003**, because it is E003's condition rather than a registry mismatch |
| fieldseal.E004 | Error | Missing `table_uuid`/`column_uuid` |
| fieldseal.E005 | Error | Encrypted field **or its index sibling** named in a `UniqueConstraint` or composite index (uniqueness over ciphertext is meaningless; uniqueness over a truncated index is forbidden by §7.10, G12 resolved) |
| fieldseal.E006 | Error | A user-supplied `FIELDSEAL["CLIENT"]` whose index registry does not exactly match the model-declared indexes (§7). Compared in the **validated** form on both sides, so a client carrying the right key set with a different resolved truncation length or Argon2 cost is caught too — under spec §7.8 that is a *different index*, not a reconfiguration of one. **Exact match, not a subset**, because only one direction is loud: a client missing a declared index fails every lookup on that column at runtime, while a client carrying an index the models do not declare stores values for that column under rules no model states and nothing raises. **Shipped as `W004` and untested between 2026-08-25 and 2026-08-26** — the core kept its validated registry private, so the check could only have been written against `Fieldseal._indexes`; `docs/09` §2's *Configuration reflection* clause (G18, [#75](https://github.com/fieldseal-dev/fieldseal-spec/issues/75)) closed that and the check is now the Error this row always specified |
| fieldseal.E008 | Error | A model with an indexed encrypted column whose default manager does not re-verify blind-index candidates. **Added at implementation (2026-08-26):** the adapter installs `FieldsealManager` automatically when a model declares no manager of its own, and deliberately does **not** overwrite one the author wrote — so this is the case it will not touch. Without a verifying queryset, §7.4's mandated collisions reach the caller as results |
| fieldseal.E009 | Error | `Meta.ordering` or `Meta.get_latest_by` naming an encrypted column (G20, [#80](https://github.com/fieldseal-dev/fieldseal-spec/issues/80)). The SQL compiler applies both directly — `Meta.ordering` never passes through `order_by()` (pinned in `test_query_private_api.py`) — so the queryset-level G20 refusal cannot see them: `Meta.ordering` would make every unordered query silently sort by envelope bytes, and `get_latest_by` makes every `earliest()`/`latest()` raise. The declaration is the only interception point |
| fieldseal.W001 | Warning | Encrypted field in `ModelAdmin.search_fields` (generates `icontains` → will raise at runtime; `docs/04` §1 gotcha) |
| fieldseal.W002 | Warning | `db_index=True` on ciphertext column (pointless index bloat) |
| fieldseal.E007 | Error | `FIELDSEAL` settings missing or unknown keys present, on a project that declares encrypted fields. **Added at implementation:** these were reported as E003 ("the core refused an index declaration"), which sends an operator who has simply not configured the adapter to look at models that are fine |
| fieldseal.W003 | Warning | base64 storage selected (documented 33% overhead, spec §3.3) |
| fieldseal.W005 | Warning | An encrypted column the admin changelist would order by (G20): `ModelAdmin.ordering` naming one breaks every changelist request, and a sortable changelist column (a `list_display` field, or a callable whose `admin_order_field` points at one, not excluded by `sortable_by`) breaks on a header click — both emit `order_by()` over the encrypted column, which now raises, so the failure is loud but arrives as a 500 on a page view instead of at startup. Warning rather than Error because the refusal itself is the enforcement; this is the notice that moves it to `manage.py check` |
| ~~fieldseal.W004~~ | — | **Withdrawn 2026-08-26 (G18).** It existed only to report that E006 could not be implemented; with the accessor in place the condition it warned about is an Error again, and leaving both would give two ids to one condition — which is how a check suite starts overstating its coverage. The id is not reused |

## 6. Coverage matrix (the AD-2 normative deliverable)

Shipped in the package README, kept in sync with tests by generating both from one table:

| Path | Behavior |
|---|---|
| `Model.save()`, `bulk_create()` | ✅ encrypts (+ index sibling via `pre_save`) |
| `QuerySet.update(field=value)` | ✅ encrypts; ⚠️ index sibling must be passed explicitly (no `pre_save` on `.update()` — `docs/04` §1); check-time documentation + runtime error if index column omitted while encrypted column present |
| `bulk_update()` | ✅ encrypts |
| `update(field=F(...))`, expression RHS | 🛑 raises `FieldsealNotSupported` |
| `filter(email=…)` / `In` | **(target)** ✅ rewritten to index column when declared; 🛑 raises otherwise. **Not implemented as of 2026-08-25** — both the encrypted column and the index sibling refuse, because serving either without §7.5 re-verification returns wrong rows (§7.4 mandates collisions). The index column is written correctly meanwhile, so enabling L2 needs no backfill |
| Other lookups | 🛑 raise (§3.3) |
| `.values()`, aggregates on other columns, `raw()` results | ✅ decrypts |
| `.extra()`, `RawSQL()`, `cursor.execute()` params | 🛑 **cannot intercept** — documented plaintext hazard (`docs/04` §1: no ORM encrypts raw parameters); listed in README with remediation (use ORM paths or call the core directly) |
| `django.core.cache` of model instances | ⚠️ holds plaintext (spec §10.2) — documented, with per-field `exclude_from_cache` guidance |
| `dumpdata` | ✅ ciphertext, never plaintext, via `value_to_string` |
| `loaddata` | 🛑 **refused (v0)** — would double-encrypt silently; see §2 |

## 7. Async, warm-up, and operations

- All field hooks are sync; Django's async ORM wraps sync (`docs/04` §1) — so the DEK cache is mandatory, and the adapter's docs say so in bold. **Implemented 2026-08-26**, with one deliberate departure from the sentence this bullet used to carry. `manage.py fieldseal_warm` primes the cache for every declared column, and the `AppConfig.ready()` hook exists but is **opt-in** (`FIELDSEAL["WARM_ON_READY"]`) rather than automatic: `ready()` runs for `makemigrations`, `shell`, `collectstatic` and every test process, so warming unconditionally would make a command that touches no encrypted row pay a KMS round trip — and fail when the key service is unreachable, so a migration could not run because of it. **A migration blocked by a cold KMS is a worse failure than a cold cache.** The honest consequence is documented instead of defaulted around: under an `EnvelopeKeyProvider`, §8.2 confines unwrapping to `warm` and forbids the value path from blocking on network, so **something** must warm the cache before the first read — the setting or the command, with no third option and no silent fallback that would make a cold read work. A warming failure at `ready()` warns and continues, because a web worker that exits on a transient KMS blip takes the deployment down for a condition the next request might not have.
- **Warming covers index keys, not just data keys.** Spec §5.2 makes the index key a *sibling* of the tenant DEK rather than something derived from it, so a cache warmed only for the data key still stalls every indexed lookup — and the symptom looks like a slow query rather than a cold cache. **Tenant-bound columns need their tenants named** (`--tenant`, or `FIELDSEAL["WARM_TENANTS"]`): a tenant-bound context carries a `tenant_id`, and the adapter cannot enumerate a deployment's tenants, which live in application data under a schema this package knows nothing about. A run that omits them names the columns it skipped rather than reporting a warm cache it did not warm.
- Settings surface and client construction: `FIELDSEAL = {"KEY_PROVIDER": callable, "READ_MODE": …, "ALLOWED_SUITES": …, "WRITE_SUITE": …, "CACHE": …}`. The **adapter constructs the `Fieldseal` client** in `AppConfig.ready()`, after model loading, assembling the `IndexDeclaration` registry from the model-level `BlindIndex(...)` declarations — that is the only way the core's construction-time validation (docs/09 §2: §7.6 gate, §7.4 band) runs against the indexes actually declared on models. Escape hatch: `FIELDSEAL["CLIENT"]` (callable returning a pre-built client) for deployments that must own provider wiring, gated by system check E006 — its index registry must exactly match the model declarations, or startup fails.
- Migration/backfill: the adapter ships nothing beyond field defaults; the zero-downtime procedure and tooling live in `tools/backfill` (`docs/15-tooling.md`), following the dual-write shape of `docs/04` §11 (backfill MUST use `bulk_update`, never `queryset.update(F(...))`).

## 8. Test plan

- **Path matrix tests:** one integration test per row of §6, against Postgres and SQLite in CI (binary column behavior differs; both are supported targets).
- **Refusal tests:** every §3.3 lookup and every 🛑 row asserts the typed exception, not a generic error.
- **Ordering regression:** a model with index-before-encrypted declaration must fail E001; a model without the check bypassed must produce correct sibling values under `bulk_create`.
- **Candidate re-verification:** seed two plaintexts that collide at the configured truncation length (construct via brute force at small `b` in the test), assert the collision row is filtered out.
- **Permissive-mode metric:** plaintext read increments the signal exactly once per value.
- **Cross-language sharing test (the point of the project) — implemented 2026-08-26.** `adapters/django/tests/cross_produce.py` writes rows through the **real ORM path** (real `save()`, runtime CSPRNG, no test-mode injection), reads the raw column back through a database cursor, and emits a standard `fieldseal-vectors/cross/v1` document. **Every existing consumer reads it unmodified**, so the adapter joins the N×N matrix as one more producer — `django` is now a third value of the `cross-produce` matrix, and both core consumers take `cross-django.json` alongside the others.

  **What this covers that no core test can.** Three decisions between an application value and the stored column belong to the adapter: the **codec's rendering** (`IntegerField(45)` becoming `b"45"` is a choice, and a consumer expecting an integer encoding would decrypt successfully and read the wrong value), the **storage form** (`binary` versus `base64`), and **context assembly** from model declarations plus the tenant contextvar (a consumer reconstructing it differently gets `COMMITMENT_INVALID` — a decrypt-side error for a write-side configuration mismatch). A core round trip sees none of them.

  The local suite runs the producer and decrypts it with a client built **independently** from `vectors/keys/`, so a case passes only if the stored bytes are readable from the shared key material alone. The true cross-language leg needs Node and therefore runs in CI. Two runs must also disagree on every envelope, since a producer that had drifted onto the injection seam would otherwise pass everything (spec §4.4).

  **Still to do:** the *index* half — a blind index written by Django, derived identically by the TypeScript core. It is the more valuable assertion of the two, because a mismatched index is a silent lookup miss rather than an error, and it needs the `cross/v1` schema to carry the index declaration. Tracked as the next cross-language increment rather than half-done here.

## 9. Deliberate non-goals

No transparent `row_id` binding (v0), no query support beyond `exact`/`in`/`isnull`, no admin search integration, no automatic tenant inference from the request (explicit contextvar only), no support for `Encrypted` on relational fields (`ForeignKey` stays plaintext — spec §7.10), no Django < 5.2 support.

## 10. Unindexable values (docs/09 §7.2 — normative for this adapter)

`encrypt` does not normalize and `blind_index` does, so a value containing a code point the pinned Unicode version does not define **stores but cannot be fingerprinted**. Every `Encrypted*` field carrying an index therefore declares `on_unindexable`, and the adapter's behaviour follows from it. This section is the obligation `docs/09` §7.1 refers to; it is normative for this adapter, and it is the reason `refuse` is a default rather than the only option.

### 10.1 What the adapter does

| `on_unindexable` | Write path | Query path |
|---|---|---|
| `refuse` (default) | `blind_index` raises `INVALID_ARGUMENT`; the field raises `ValidationError` from `to_python`/`get_prep_value` so the failure arrives as a **form error on that field**, not a 500 | A lookup for such a value raises the same `ValidationError` — never returns an empty queryset |
| `bucket` | The sibling index column receives the column's reserved marker; the row saves | A lookup derives the same marker, matches the bucket, and §7.5 re-verification narrows — no adapter special-casing |

`refuse` MUST surface as a field-level `ValidationError`, not as a generic 500 or a silently dropped index. A `ModelForm` then renders it beside the offending input, which is the only place the person who typed the value can act on it.

**Where the refusal is raised is load-bearing, and was corrected at implementation (2026-08-26).** The index can only be derived in `pre_save`, which is the one field hook that receives the instance — and `pre_save` runs *inside* the INSERT, so a `ValidationError` raised there propagates out of `Model.save()`, whose `transaction.atomic(savepoint=False)` marks the connection for rollback. The caller then has their field error **and a transaction they cannot use**, which is not a form error in any sense that helps. The check therefore also lives in `Encrypted.validate()`, which `full_clean()` calls — so the `ModelForm` path fails before the database is touched, and `pre_save` remains the backstop for code calling `create()` directly. That second path still marks the transaction; it is Django's behaviour for every exception in `save()` rather than something this adapter chose, and it is documented in the package README rather than pretended away.

**One implementation note that costs an hour to rediscover:** `ValidationError` **discards `code` and `params` when its message is a dict**. The machine-readable half has to be carried by the inner error — `ValidationError({field: ValidationError(msg, code=..., params=...)})` — and a caller who builds the dict itself loses it with no warning that it did.

### 10.2 The message (normative in shape, not in wording)

"Unsupported character" fails every part of this. The message MUST:

1. **Name the specific character and where it is.** The user cannot act on "somewhere in this field".
2. **Put the fault on the system.** The value is not invalid — it is a name, and the system's tables are out of date. Wording that implies the user made a mistake is wrong on the facts.
3. **Offer a route that ends with the real value stored.** A refusal with no escape hatch is a dead end for the person on the other side of it, which is why `refuse` and `bucket` are specified as a pair: `bucket` is the operator-applied escape hatch, not an alternative philosophy.

```
We can't save this name yet. Our systems don't recognise the character 𠮷
(3rd character). This is a gap on our side, not a problem with your name —
it's a recently added character we haven't added support for yet.

[Save with a different spelling]   [Contact support — we can enter it manually]
```

The support path has to be real. "Contact support" is only honest if support can actually store the value, which means an operator can move that column to `bucket`, or store the row through a path that does not derive the index.

### 10.3 Choosing per column

The answer differs by column and a single rule is wrong somewhere:

- **A login email** — `refuse`. An account that exists and cannot be found by its own login is worse than a rejected signup, and the value is machine-shaped: a character outside the pin in an email address almost always means something upstream is broken.
- **A legal or display name** — `bucket`. Refusing a person's name is a hard failure for that person, and names are exactly where rare characters legitimately appear.

`bucket` requires `unindexable_override={"reason": ..., "approved_by": ..., "date": ...}`, refused at model-definition time (E-series check) if absent — the same ceremony spec §7.6 requires to relax the cardinality gate, and for the same reason: it is a per-column relaxation of a default-deny rule, so it should be a recorded act rather than a setting that gets copied.

### 10.4 What `bucket` costs, stated

The marker is a real index value derived under the column's own index key, so it is not distinguishable *as* the marker without that key. But the bucket is an equivalence class that can grow far past §7.4's expected `P × 2^(−b)`, so it is **distinguishable by frequency**: an observer who can read the index column sees one unusually popular value and can infer that those rows share "contains a character outside the pin". The class is also **growable by anyone who can write to the column**, which makes lookups against it progressively more expensive — bounded by re-verification cost, not by anything cryptographic. A column where either is unacceptable keeps `refuse`. The adapter documents both in its README rather than only here.
