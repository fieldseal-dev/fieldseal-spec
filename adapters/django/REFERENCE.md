# fieldseal-django reference

The detail behind [`README.md`](README.md): what every query path does today
and the test that proves it, why each refusal exists, and the adapter's known
gaps. The README is the place to start; this file is for when a behaviour
surprises you, or you are reviewing the adapter. The design it implements is
[`docs/12-adapter-django.md`](../../docs/12-adapter-django.md).

Everything here describes an experimental, unreviewed pre-1.0 release; the
README's warning applies to all of it.

## Declaring a column

The UUIDs are surrogates written literally in the source and captured into
migrations. They must never be derived from the app, model or field name:
spec §6.1 binds key derivation to them, so a rename would make every existing
row undecryptable. System check `fieldseal.E004` fails startup without them.

The index column is explicit rather than auto-injected because
`SQLInsertCompiler.as_sql` iterates fields in declaration order, and the
index's `pre_save` must run after the encrypted field's. Check
`fieldseal.E001` asserts the order at startup rather than trusting it.

### How values become bytes

The inner field decides which of spec §3.6's eight logical types the column
holds, and the plaintext is §3.6's canonical rendering of that type. That
rendering is the same one the Prisma adapter writes, and the `codec/` vectors
pin it:

| Inner field | Logical type | Rendering, e.g. |
|---|---|---|
| `CharField`, `TextField` and subclasses (`EmailField`, `SlugField`, `URLField`, …) | `string` | UTF-8 |
| `BinaryField` | `bytes` | unchanged |
| `IntegerField` family | `int` | `-42` |
| `DecimalField` | `decimal` | `1.5` |
| `FloatField` | `float` | `10000000000000000` (ECMAScript's form, not CPython's `1e+16`) |
| `BooleanField` | `boolean` | `true` |
| `DateField` | `date` | `2026-09-08` |
| `DateTimeField` | `datetime` | `2026-09-08T12:00:00.000000Z` |

**Any other inner field is refused by `Encrypted()` at declaration.** That
includes `UUIDField`, `TimeField`, `DurationField`, `JSONField` and
`GenericIPAddressField`. §3.6 pins no rendering for them, and a column rendered
by `str()` becomes a backfill the day another language reads it differently.
To encrypt one of these, store it as a `CharField` holding a rendering your
application owns.

**Three consequences you will see:**

- **A `Decimal` comes back without trailing zeros.** `Decimal("1.50")` is
  stored and read back as `Decimal("1.5")`. Rendering by value is what makes
  `filter(amount=Decimal("1.50"))` find a row written as `Decimal("1.5")`:
  equal values are one plaintext, so one blind-index value. Before §3.6 they
  were two, and the lookup missed. A `float` given to a `DecimalField` is
  refused rather than rounded.
- **A naive `datetime` is refused on write**, whatever `USE_TZ` says, instead
  of being assumed to be in the default time zone. Values are read back as
  aware UTC datetimes.
- **Reads are strict.** A row whose decrypted bytes are not the canonical
  rendering raises `FieldsealNotSupported` instead of being coerced. This
  includes rows written by this adapter before §3.6, which wrote booleans as
  `True`, datetimes as `2026-09-08 12:00:00+00:00`, and floats in CPython's
  form. Nothing had been released at the time, so no deployment holds such
  rows.

## Supplying your own client

The adapter builds the `Fieldseal` client itself, in `AppConfig.ready()`,
assembling the index registry from the model declarations. That is not a
convenience: the core's §7.4 truncation band and §7.6 cardinality gate run at
client construction, and this is the only arrangement where they see the
columns that actually exist. `FIELDSEAL["CLIENT"]` overrides it, and
`fieldseal.E006` then checks the supplied client's registry against the model
declarations — an exact match in both directions, comparing the validated
form, because a client carrying an index the models do not declare stores
values for that column under rules no model states and nothing raises. The
validated form includes the index's declared suite (spec §7.2, #213), so a
client whose index has the same parameters but a different `suite_id` is an
E006 mismatch: it would store different bytes for every row.

## Declaring the index's suite

Every `BlindIndex` states `suite_id=`, for example `BlindIndex(suite_id=0xFF01,
projected_population=100_000)`. It is required, keyword-only and has no default,
and the adapter never fills it from `FIELDSEAL["WRITE_SUITE"]`: the index
context's `suite_id` is the suite the index is declared under, not the suite
envelopes are written under (spec §7.2), because a stored index value carries
no header to say which suite produced it. Omitting it, or passing `None`, is
refused when the registry is assembled and reported by `fieldseal.E003` with
the model field's name; the Python default is `None`, meaning "not stated",
only so that a migration written before the suite existed still imports. A
bool or an unregistered suite is refused by the core when the client is built
and reported by `fieldseal.E003` with the model field's name; the adapter does
not re-check the value (AD-1).

The suite is fixed for the life of the index (spec §7.8), and changing
`WRITE_SUITE` no longer affects any blind index. It need not be the write suite
or appear in `ALLOWED_SUITES`. `BlindIndex.deconstruct()` always emits a stated
suite, so a migration carries the suite the index was created under.

**Upgrading from a release without it:** add `suite_id=` to every
`BlindIndex(...)` in models. Already-generated migration files load unchanged,
and the next `makemigrations` records the suite in an `AlterField`. Stored
index bytes do not change when the declared suite equals the write suite that
was in use (spec §7.2, *Compatibility*).

`cross_produce.py` emits the `fieldseal-vectors/cross/v3` document, in which
each index declaration carries `suite_id` read off the client's validated
registry; `tests/test_declared_suite.py` covers the rules above, including a
column declared under `0xFF02` against a write suite of `0xFF01` end to end.

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
| `bulk_update()` of an indexed column | ✅ the index is derived per instance and written with it | `TestBulkUpdate::test_the_index_follows_the_column` |
| `QuerySet.update(field=value)` | ✅ encrypts | `test_plain_update_encrypts` |
| `QuerySet.update(field=value)` of an indexed column | ✅ the index is derived and written with it | `TestUpdate::test_the_index_follows_the_column` |
| `update(field=Value(...))` on an indexed column; the column and its index in one `update()` | 🛑 raises `FieldsealNotSupported` | `test_an_expression_is_refused_on_an_indexed_column`, `test_the_column_and_its_index_in_one_call_are_refused` |
| A `Value(...)` you build yourself, in `update()` or as an instance attribute in `bulk_update()`, on any encrypted column | 🛑 raises `FieldsealNotSupported` before the statement runs; it would have stored the literal as plaintext | `test_a_caller_built_value_is_refused_rather_than_stored_as_plaintext`, `test_bulk_update_refuses_an_expression_attribute_on_an_indexed_column` |
| `save()` on an instance loaded with `only()` / `defer()` without the index column | 🛑 raises `FieldsealNotSupported`, naming the deferred load | `test_a_deferred_load_is_named_in_the_refusal` |
| Two index columns over one encrypted column | ✅ `update()` and `bulk_update()` write both; `save(update_fields=...)` requires both | `test_update_writes_both_index_columns`, `test_bulk_update_writes_both_index_columns`, `test_save_with_update_fields_must_name_both` |
| `save(update_fields=[...])` naming an indexed column without its index column | 🛑 raises `FieldsealNotSupported`; name both | `test_the_column_without_its_index_is_refused`, `test_naming_both_writes_both` |
| `bulk_create(update_conflicts=True, update_fields=[...])` | ✅ the index column is added to `update_fields` with its column | `test_the_conflict_update_writes_the_index_with_the_column` |
| `update()`, `bulk_update()` or a `bulk_create` upsert of an indexed column through `Model._base_manager`, or any manager that is not `FieldsealManager` | 🛑 raises `FieldsealNotSupported` while the statement is compiled when the index would be left stale: the index column missing, set to the `Case` a plain `bulk_update` builds from the instance's stale attribute, or only one of the two in an upsert's `update_fields`. `save()` and an upsert naming both columns pass, and `save()` is the remedy where no `FieldsealManager` exists, as in a data migration. Nothing is written for a single table; under multi-table inheritance the child table's columns are written first, so use `atomic()`. Inside `atomic()`, give the call its own savepoint to keep the transaction usable (#240) | `TestPlainManager` in `test_index_on_partial_writes.py`; `test_index_check_review.py` |
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
| `get()` | ✅ materializes the whole bucket — Django's `LIMIT 21` sample could hide the match past the window | `test_get_finds_a_match_behind_a_full_window_of_collisions` |
| `iterator()` / `aiterator()` | ✅ verified, still streaming — both bypass `_fetch_all` by design | `test_iterator_yields_only_verified_rows`, `test_aiterator_…` |
| `filter(field=None)`, `__isnull`, `exclude(field=None)` | ✅ served exactly — `IS [NOT] NULL` on the envelope column, no index touched | `TestNullSemantics` |
| Case variant / canonical-equivalent spelling | ✅ matches — equality is the normalizer's (G19) | `TestNormalizedEquality` |
| Plain-AND `Q` over an encrypted column | ✅ records the obligation, verifies like a keyword | `TestPlainAndQ` |
| Slicing / pagination / `qs[i]` on a verified queryset | 🛑 refused — LIMIT precedes verification (§7.5) | `test_slicing_refuses`, `test_int_indexing_refuses` |
| `earliest()` / `latest()` | 🛑 refused — `LIMIT 1` before verification, `first()`'s failure renamed | `test_earliest_and_latest_refuse` |
| `update()`, `delete()` on a verified queryset | 🛑 refused — would write to collision rows | `test_sql_answered_paths_refuse` |
| `aggregate()`, `values()`, `values_list()`, `only()`, `defer()` | 🛑 refused — answered from SQL, or drop the column verification needs | same |
| `exclude(field=...)` | 🛑 refused on **every** queryset (G24) — false negatives are unrecoverable, so `.candidates()` does not lift it | `test_exclude_refuses`, `TestCandidatesDoesNotLiftNegation` |
| `Q` with `OR` over an encrypted column | 🛑 refused — cannot decide a candidate; `.candidates()` lifts it | `test_or_through_q_refuses`, `test_or_through_q_on_candidates_works` |
| `Q` negated (`~Q`) or `XOR` over an encrypted column | 🛑 refused on **every** queryset (G24) — a widened bucket drops rows from both | `test_negation_still_refuses`, `TestCandidatesDoesNotLiftNegation` |
| Subquery embedding (`__in=qs`, `Subquery`, `Exists`) | 🛑 refused — the outer query would receive unverified candidates. Two layers: `resolve_expression` for the bare `__in=qs`, and an expression walk for `Exists`/`Subquery`, which keep `qs.query` and never reach it — refused wherever the wrapper appears (positional `filter()`/`exclude()` argument, `Q` child, keyword operand, `annotate()`/`alias()`) | `test_a_verifying_queryset_refuses_to_become_a_subquery`, `test_every_expression_route_refuses` |
| `union()` / `intersection()` / `difference()` | 🛑 refused on either side — obligations cannot span operands. `.candidates()` lifts the first two and not `difference()`, which subtracts a bucket | `test_combinators_refuse_on_either_side`, `test_union_and_intersection_still_lift` |
| Relation traversal (`filter(rel__enc=...)`, forward or reverse) | 🛑 refused at `filter()` time **and** at compile time — the second layer holds for plain-manager models too. A *negated* traversal is refused as a negation, checked first: the compile-time layer passes by design when the column's owner is the querying model | `TestRelationTraversal`, `TestNegationIsAPositionNotAnOwner` |
| A `.candidates()` queryset **embedded** in a subtractive position — `exclude(pk__in=…)`, `~Q(…__in=…)`, `difference(…)`, `annotate(Exists(…)).filter(alias=False)` | 🛑 refused (G24) — the outer predicate names no encrypted column and still subtracts the whole bucket. The positive `filter(…__in=qs.candidates())` the refusal messages recommend is unaffected | `TestABucketEmbeddedInASubtractivePosition` |
| `.candidates()` | ✅ bucket semantics, unverified, every *verification* refusal lifted (`Q` under `OR` included). Three exceptions: negation (G24) — wherever it stands, including as the operand of an outer one — the cross-model traversal (embed the owner's `.candidates()` instead), and the G20 family | `TestCandidatesOptOut`, `TestCandidatesLiftsFilterTimeRefusals`, `TestCandidatesDoesNotLiftNegation` |
| `order_by()` over an encrypted column — direct, relation path, or expression | 🛑 refused on **every** queryset (G20) — sorts envelope bytes; `.candidates()` does not lift it | `TestOrderBy` |
| `earliest()`/`latest()` naming one (or via `Meta.get_latest_by`) | 🛑 refused (G20) — the same ordering through a different door | `TestEarliestLatest` |
| Aggregate/function expressions over one (`Min`, `Sum`, `Count`, `Length`, …) | 🛑 refused (G20) — measured: `Min("age")` over {30, 40} returned **40**, decrypted cleanly | `TestAggregates` |
| `values(enc).annotate(<aggregate>)` grouping / `distinct` over an encrypted projection | 🛑 refused (G20) — one group per row; dedup removes nothing | `TestGroupingAndDistinct` |
| Bare `F("enc")` annotation · `order_by("enc_bidx")` sibling ordering · bare `distinct()` on full rows | ✅ allowed — exact select-and-decrypt; deterministic documented-meaningless tiebreaker; full-row distinct is pk-keyed and cannot dedupe wrongly, only no-op | `TestAggregates`, `TestOrderBy`, `TestGroupingAndDistinct` |
| `Meta.ordering`/`get_latest_by` naming one · admin sortable encrypted column | 🛑 **E009** (Error) / ⚠️ **W005** (Warning) — the compiler applies these where no queryset refusal can see them | `TestE009`, `TestW005` |
| Verifying manager auto-installed | ✅ when the model declares no manager | `test_the_manager_is_installed_without_being_asked_for` |
| Hand-written manager | 🛑 E008 — not overwritten, reported | `test_a_hand_written_manager_is_not_replaced_but_is_reported` |
| **`filter(field_bidx=...)`** | 🛑 **refused — cannot re-verify from a field hook** | `test_exact_on_the_index_column_refuses_naming_the_collision_rule` |
| `contains`, `startswith`, `gt`, `range`, `regex`, `iexact`, … | 🛑 raise (spec §7.10 lists the fallback for each) | `test_refused_lookups_raise_rather_than_return_nothing` |
| `.extra()`, `RawSQL()`, `cursor.execute()` params | 🛑 **cannot intercept — plaintext hazard** | — see below |
| `django.core.cache` of model instances | ⚠️ holds plaintext (spec §10.2) | — |
| `on_unindexable="refuse"` | ✅ field-level `ValidationError`, §10.2 wording | `TestRefuse`, `TestTheMessage` |
| `on_unindexable="bucket"` | ✅ row saves, stays findable by its own value | `TestBucket` |
| Two different unindexable values | ✅ do not match each other (§7.5 does the work) | `test_two_different_unindexable_values_do_not_match_each_other` |
| An `AlterField` that leaves an `Encrypted` column as it is (an index's suite, the inner field, `column_uuid`), or an `EncryptedIndex` column (its `source`, on a rename) | ✅ no SQL on SQLite and PostgreSQL (measured, Django 5.2.19 and 6.1.3); a change to `storage`, `null`, `unique` or `db_column` is still altered ([#283](https://github.com/fieldseal-dev/fieldseal-spec/issues/283)). ⚠️ A changed `column_uuid`, inner logical type, `tenant_bound` or `storage` is refused by `migrate` since 2026-11-19, on every backend ([#288](https://github.com/fieldseal-dev/fieldseal-spec/issues/288)), see the next row but one; a change that keeps the logical type (`max_length`, `EmailField` to `CharField`) and a change to `index` or `unindexable_noun` still pass | `test_a_change_that_leaves_the_column_is_not_altered`, `test_renaming_the_indexed_field_does_not_alter_its_index_column`, `test_migrate_issues_no_sql_for_an_unchanged_column`, `test_a_rebuild_keeps_each_legacy_values_storage_class` |
| A plain `AlterField` that changes an `Encrypted` column's type to or from `bytea`, on PostgreSQL | 🛑 `migrate` refuses the plan before any DDL: Django's cast would rewrite or refuse the legacy text, or write bytes as hex text, forwards or on rollback, through squashed and merged graphs ([#252](https://github.com/fieldseal-dev/fieldseal-spec/issues/252)) | `test_migrate_refuses_a_plain_alter_field_into_bytea_before_any_ddl`, `test_migrate_refuses_a_bytea_column_into_base64`, `test_rolling_back_a_merged_branch_is_refused`, `test_rolling_back_to_a_migration_a_squash_replaced` |
| An `AlterField` between two `Encrypted` declarations that changes the `column_uuid`, the inner field's spec §3.6 logical type, `tenant_bound` or `storage` | 🛑 `migrate` refuses the plan before any DDL, on every backend, forwards or unapplied, and under `--fake`; the message names the app, migration, model and field and the old and new value. A `SeparateDatabaseAndState` whose `state_operations` carry the `AlterField` passes, as the operator's statement that the values were re-encrypted another way; the two-column shape (`docs/12` §7) is the other route ([#288](https://github.com/fieldseal-dev/fieldseal-spec/issues/288), 2026-11-19). A fresh database, test databases included, runs the whole history and so refuses a historical change of this kind although the table is empty; wrap it in a `SeparateDatabaseAndState` with the `AlterField` in `state_operations`, or squash (the optimizer folds it into the `CreateModel`; pinned for that case). The refusal guards `migrate` only: a declaration shipped without running `migrate`, or without a migration, is not stopped. `EncryptedIndex` and `BlindIndex` changes are not refused ([#303](https://github.com/fieldseal-dev/fieldseal-spec/issues/303); `docs/12` §6) | `test_migrate_refuses_the_change_before_any_ddl`, `test_migrate_refuses_unapplying_the_change`, `test_migrate_fake_is_refused_too`, `test_storage_base64_to_binary_is_refused_too`, `test_the_escape_hatch_state_operations_let_the_change_through`, `test_a_fresh_database_is_refused_for_a_history_with_an_identity_change`, `test_a_value_written_under_one_tenant_bound_setting_does_not_read_under_the_other` |
| `ConvertToEncrypted` on PostgreSQL | ✅ a `CharField`/`TextField` value becomes its UTF-8 bytes, and back; 🛑 any other inner type | `test_convert_stores_the_values_utf8_bytes_and_undoes_it`, `test_convert_refuses_a_non_string_column_on_postgres` |
| `manage.py fieldseal_gen_uuids` | ✅ prints surrogates; never edits source | `tests/test_gen_uuids.py` |
| `manage.py fieldseal_warm` | ✅ primes data **and** index keys (spec §5.2) | `tests/test_warm.py` |
| `manage.py fieldseal_backfill` (`init`, `encrypt`, `resume`, `abandon`) | ✅ `tools/backfill/PROCEDURE.md` v2, scenarios BF-01 to BF-10, BF-14, BF-16 to BF-27 (since [#244](https://github.com/fieldseal-dev/fieldseal-spec/issues/244): BF-23 to BF-26, tenant-bound columns, and BF-27, the in-place conversion acknowledgement; since [#281](https://github.com/fieldseal-dev/fieldseal-spec/issues/281): BF-21, a resume across a changed declared suite, and BF-22, a new run after an abandoned one, refused when an earlier run converted values under other index declarations); two-column shape for every column, in place for `binary` storage, including SQLite legacy values in the storage class `AlterField` leaves ([#251](https://github.com/fieldseal-dev/fieldseal-spec/issues/251)), and for `base64` storage, where legacy text reads back as stored and a non-string column converts only §3.6 canonical text ([#245](https://github.com/fieldseal-dev/fieldseal-spec/issues/245)); on Postgres, in place on a `binary` column needs the column converted by `ConvertToEncrypted` (string inner fields only; every other type uses two columns, [#252](https://github.com/fieldseal-dev/fieldseal-spec/issues/252)), and a new in-place run on Postgres, `binary` or `base64`, on a table with rows, needs `--acknowledge-in-place-conversion` (PROCEDURE §6.1, §9 item 6) | `tests/test_backfill.py` (`test_bfNN_…`) |
| `fieldseal_backfill` on a tenant-bound column | ✅ with `--tenant FIELD`, a column of the same row: each value is written under its own row's tenant, rendered as PROCEDURE §5.5 says (an integer or UUID key as `str()` of it), never under one the process had bound; a NULL or empty tenant, or one stored in another storage class than the field's type, is `CONTEXT_UNAVAILABLE`; a tenant that is not in the row (a schema or database per tenant) cannot be backfilled ([#244](https://github.com/fieldseal-dev/fieldseal-spec/issues/244)). All four §5.5 types end to end (int, uuid, text, binary) | `test_bf23_…` to `test_bf26_…`, `test_tenant_rendering_of_each_type`, `test_an_empty_tenant_is_no_tenant`, `test_uuid_text_is_32_hex_or_canonical_and_nothing_else` |
| `fieldseal_backfill` `rotate`, `verify` | ❌ not built: `rotate` and BF-11, BF-12, BF-13, BF-15k are blocked on [#241](https://github.com/fieldseal-dev/fieldseal-spec/issues/241); `verify` (BF-15) is next | — |
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
`first()`, `last()` and `get()` are implemented against verified rows (Django's
`get()` samples a `LIMIT 21` window of candidates; ours reads the whole
bucket), and `iterator()`/`aiterator()` filter the stream as it passes;
slicing, `qs[i]`, `earliest()`/`latest()`, `update()`, `delete()`,
`aggregate()`, the projections, subquery embedding and the set combinators are
**refused**, and so is `exclude()` — a filter's false positives are
recoverable, an exclusion's false negatives are not. NULL is the exception
that needs none of this: `filter(field=None)` and `__isnull` compile to
`IS [NOT] NULL` on the envelope column itself, which is exact. `.candidates()`
opts out of the rest and hands you bucket semantics, documented as
unverified.

**`.candidates()` does not lift negation** (G24, [#100](https://github.com/fieldseal-dev/fieldseal-spec/issues/100), spec §10.2):
`exclude()`, `~Q`, and `XOR`, which is negation once expanded. Bucket
semantics are a coherent thing to accept for a filter, where they hand you
*more* rows than the answer and you reach it by dropping some; they are not
for an exclusion, where they hand you fewer and the missing rows are not in
what you were handed. The hatch lifted `exclude()` until that issue closed,
and the refusal message recommended it.

**`filter()` is not the only door, and the rules above do not live behind
it** ([#118](https://github.com/fieldseal-dev/fieldseal-spec/issues/118)).
`complex_filter(Q)` calls `query.add_q` directly, and `Model._base_manager`
is a plain `Manager` with no verifying queryset anywhere above it — Django
builds it that way on purpose. Both reached the blind index unrefused and
unverified, and Django walks both itself, for `limit_choices_to`. The
queryset override closes the first; the second is closed one layer down, in
the lookup: **an encrypted equality compiles only for a query whose rows a
verifying queryset will re-verify** — or one whose caller took §7.5 on with
`.candidates()` — so `Patient._base_manager.filter(email=v)` raises, and so
does the correlated `Exists(...)` it can be rewritten as. `_base_manager`
still answers primary keys, `IS [NOT] NULL` and unfiltered reads, which is
what Django's own FK validation and cascade deletes need from it. If you hold
a plain queryset and want the rows, go through `Model.objects` — or
`Model.objects.filter(...).candidates()`, and take on §7.5 yourself.

The one shape that stays served from a plain manager is a `.candidates()`
bucket used as a *subtractive* operand — `exclude(pk__in=…candidates())`, or
the `exclude(Exists(…candidates()))` spelling. Reading the position needs the
queryset, because the lookup is handed the operand without it, and a plain
manager has no queryset of ours to read it from. `Model.objects` refuses
both.

**A second refusal family does not depend on filtering at all** (G20,
[#80](https://github.com/fieldseal-dev/fieldseal-spec/issues/80)): SQL that
*computes on envelope bytes* — `order_by()`, `earliest()`/`latest()`,
`distinct`, grouping, aggregate and function expressions over an encrypted
column — is refused on every queryset, and `.candidates()` does **not** lift
it, because there is nothing meaningful to accept: measured before the
refusals were written, `Min("age")` over `{30, 40}` returned `40` (the
byte-wise minimum *envelope*, decrypted cleanly and presented as the
minimum), and grouping returned one group per row under keys that print
identically. A bare `F("field")` annotation stays allowed — it only selects,
and the converter decrypts what comes back.

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

### Counting plaintext reads

In `permissive` and `readonly` a value that is not an envelope is returned as
it is (spec §10.3). The core counts those reads for the whole client in
`get_client().plaintext_reads`; the adapter counts them per model and field,
so that when the cut-over to `strict` waits on a count of zero
(`tools/backfill/PROCEDURE.md` §8), a non-zero count names the column:

```python
from django.dispatch import receiver
from fieldseal_django.signals import (
    plaintext_read,
    plaintext_read_counts,
    plaintext_read_receiver_failures,
)

@receiver(plaintext_read)
def count_plaintext(sender, field, **kwargs):
    metrics.increment("fieldseal.plaintext_read",
                      tags={"model": sender._meta.label, "field": field})

plaintext_read_counts()  # {("clinic.Patient", "email"): 3, ...}
plaintext_read_receiver_failures()  # {"metrics.hooks.count_plaintext": 3}
```

The signal's `sender` is the concrete model that owns the field
(`field.model`; for a field inherited from an abstract base, the subclass)
and `field` is the field's name. It never carries the value. `plaintext_read_counts()` is a
snapshot since the client was built, and a field with no plaintext read is
absent from it. The counts belong to the client, as its
`plaintext_reads` does: a rebuilt client starts both at zero.

Both count reads, not rows: a legacy value read twice counts twice. A value
that is counted and then refused (`FieldsealNotSupported`, because the inner
field cannot read it) still counts, as it does in the core, because it is a
row still to migrate. A read the core refuses (`NOT_CIPHERTEXT` in `strict`,
`UNKNOWN_FORMAT_VERSION`) does not count. `fieldseal_backfill`'s in-place
reads count too, so choose a window for the cut-over that does not overlap a
backfill run. A receiver that raises does not break the read, and the count
has already been taken. Its **first** failure for the client is logged on the
`fieldseal_django` logger at ERROR with the traceback; later failures of that
receiver are counted, not logged (a receiver that is down fails on every
read, and a traceback per read is unbounded, #295). That is the only log:
Django's own per-failure log on `django.dispatch` is switched off for this
signal (a private `Signal` subclass overriding `_log_robust_failure`; a test
fails if Django renames it), which also keeps a receiver with no
`__qualname__`, such as a `functools.partial`, from breaking the read.
"First" is per receiver object while it lives (held weakly, so a freed
receiver is forgotten): two instances of one class are logged once each.
`plaintext_read_receiver_failures()` returns `{receiver name: failures}` for
the current client, the logged first failure included. The name is
`"{module}.{qualname}"` of the receiver function (of the function a
`functools.partial` wraps), or of the receiver's type for a callable
instance; never its `repr`, which can carry a secret or raise. Receivers that
share a name are summed under it. A receiver that has not failed is absent.
Like the counts it is per client and per process: a rebuilt client logs a
failing receiver again. A receiver that raises does not break the read for
synchronous receivers and for `async def` receivers called outside a running
event loop; from a thread with a running loop, an `async def` receiver makes
Django's own `send_robust` raise `RuntimeError` (AsyncToSync; reproduced on
Django 6.1.3), which is not caught.

**The counts are per process**, like the core's. A `manage.py shell` opened
to check the gate has its own client and reads `{}`, and each worker of a
multi-process server counts its own reads and loses them when it is
recycled. For the cut-over, export the signal to a shared metrics backend,
as above, and read the count there. In the two-column backfill shape the
encrypted column only ever holds NULL or envelopes, so its count stays at
zero and says nothing about that shape's progress.

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
