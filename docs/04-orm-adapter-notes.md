# ORM Adapter Notes

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the per-ORM engineering detail behind the conformance-level matrix in the spec (§10). Written to be read by whoever implements each adapter.

Versions verified August 2026: Django **6.1** (5.2 LTS) · SQLAlchemy **2.0.51** / 2.1.0b3 · Prisma **7.9.1** · TypeORM **1.1.0** · Hibernate **7.4.5** · EF Core **10** · GORM **v1.31.2** · Rails **8.1.x** · Sequelize **v7**.

Throughout: **W** = write path · **R** = read path · **Q** = query/WHERE path.

---

## The universal capability set

Everything all seven ORMs provide, and no more:

- per-column scalar transform on W (single-row and ORM-managed multi-row insert)
- per-column scalar transform on R (entity hydration)
- a stable declaration point for "column X is encrypted"
- the ability to add an ordinary extra column that the migration tool emits DDL for
- the ability to run **synchronous, pure** code in the value path
- errors raised in the transform propagate and abort the operation

**Not universal:** transform firing on *all* write paths · transform firing on WHERE parameters · sibling-field access · async · query rewriting.

This is why the core API is synchronous and why AAD row-binding is an optional conformance level.

---

## The primary-key ordering problem (affects every adapter)

With database-generated identity keys, the primary key is `NULL` or a placeholder at the moment the value transform runs:

| ORM | Hook | PK available at INSERT? |
|---|---|---|
| Django | `pre_save` during `SQLInsertCompiler` | ❌ `obj.pk is None` |
| SQLAlchemy | `before_insert` / `before_flush` | ❌ `target.id is None` |
| EF Core | `SavingChanges` | ❌ temporary value |
| GORM | `Value(ctx, field, dst, …)` | ❌ populated from `RETURNING` afterwards |
| Prisma | `$allOperations` | ❌ extension runs before the query |
| Hibernate | `Interceptor.onPersist` | ✅ **with `SEQUENCE`, `TABLE`, or assigned/UUID generators**; ❌ with `IDENTITY` |

**General solution: client-generated UUIDv7 primary keys.** Any deployment enabling L3-row binding should adopt them. Hibernate is the sole exception, and only with the right generator.

---

## 1. Django 6.1

**Hooks.** `Field` subclass with `from_db_value(value, expression, connection)` (R), `get_prep_value` → `get_db_prep_value` → `get_db_prep_save` (W and Q), `pre_save(model_instance, add)` (W only, **receives the instance**), `deconstruct()` for migrations. Query rewriting via `Field.register_lookup(MyLookup)` with `Lookup.as_sql(compiler, connection)`. Shadow-column injection via `contribute_to_class(cls, name)` → `cls.add_to_class(...)`.

**Coverage** (verified against `django/db/models/sql/compiler.py` @ `stable/6.1.x`):

| Path | `pre_save` | `get_db_prep_save` | `from_db_value` |
|---|---|---|---|
| `Model.save()` | ✅ | ✅ | — |
| `bulk_create()` | ✅ | ✅ | — |
| `QuerySet.update()` | ❌ | ✅ | — |
| `bulk_update()` | ❌ | ✅ but via `Value(attr, output_field=field)` inside `Case/When`; `get_db_prep_save` short-circuits on expressions | — |
| `filter(email="x")` | — | ✅ via `FieldGetDbPrepValueMixin.get_db_prep_lookup` → `get_db_prep_value(v, connection, prepared=True)` | — |
| `.values()` / aggregates | — | — | ✅ documented |
| `raw()` | — | — | ✅ — Django is the **only** ORM here that decrypts raw SQL *results* |
| `.extra()`, `RawSQL()`, `cursor.execute()` | ❌ | ❌ | ❌ |

**Critical detail:** at SQL-compile time the lookup path calls `get_db_prep_value(..., prepared=True)`, which does **not** re-run `get_prep_value` (for standard lookups with `prepare_rhs=True` it already ran once, earlier, via `Lookup.get_prep_lookup`). Implement the transform in `get_db_prep_value` so both the save path and the lookup path hit it; treat `get_prep_value`-only placement as broken. Base `Lookup.get_db_prep_lookup` returns `("%s", (value,))` with **no conversion at all** — custom lookups that don't mix in `FieldGetDbPrepValueMixin` bypass field prep entirely.

**Query rewriting.** The clean route is a registered `Exact` lookup whose `as_sql` builds a `Col` for the sibling index field rather than string-replacing the column name:

```python
bidx_col = self.lhs.output_field.model._meta.get_field("email_bidx").get_col(self.lhs.alias)
sql, params = compiler.compile(bidx_col)
```

This composes with `AND`/`OR`, `Q`, joins, and subqueries because it happens at compile time.

**Shadow-column ordering constraint (verified).** `SQLInsertCompiler.as_sql` iterates `for field in fields: for obj in objs:` over `opts.local_concrete_fields` in declaration order. The index field's `pre_save` must run *after* the encrypted field's — so **declare the index field after the encrypted field**. Fragile but deterministic; the adapter should assert this at model-check time.

**Gotchas.** `.only()`/`.defer()` deferred loading triggers a second query per instance → per-row decrypt · `django.core.cache` layers caching model instances persist **plaintext** to Redis/memcached · `unique=True` on an encrypted column is useless (random nonce) — put it on the index column · `F()` expressions on an encrypted column are silently wrong · Django admin's `search_fields` generates `icontains` and will silently return nothing · `value_to_string()` must be overridden or `dumpdata` misbehaves.

**Ordering and grouping have no field hook (verified; G20).** Django resolves `order_by()` names and `Meta.ordering` to a plain `Col` — `SQLCompiler.find_ordering_name` / `_order_by_pairs` — with no per-field extension point in the path, and `GROUP BY` is derived from the select list the same way. So the spec §10.2 throw for ordering/grouping/`DISTINCT`/aggregates over a ciphertext column can only be implemented at the queryset layer (`order_by`, `earliest`/`latest`, `distinct`, `annotate`/`alias`/`aggregate`, `values` under `DISTINCT`), backed by startup checks for the two declaration doors the compiler applies directly (`Meta.ordering`/`get_latest_by` → E009; admin sortable columns → W005). The residue this leaves: a *plain-manager* model ordering through a relation onto another model's encrypted column is not reachable — unlike the equality traversal, which the lookup layer closes for every queryset — and is documented in the same class as raw SQL.

**Async.** All field hooks are synchronous. Django's async ORM is `sync_to_async` over the sync ORM, so a blocking KMS call in `from_db_value` occupies a thread-pool thread **per row**, and a blocking call in `get_db_prep_save` holds a pooled connection inside the transaction. **DEK cache is mandatory, not optional.**

---

## 2. SQLAlchemy 2.x

**Hooks.** `TypeDecorator` with `process_bind_param` (W+Q), `process_result_value` (R), `cache_ok`. `hybrid_property` + `@x.inplace.comparator` returning a custom `Comparator` — the query-rewrite hook. ORM events `before_flush`, mapper `before_insert/before_update`, `SessionEvents.do_orm_execute`. Core events `before_execute`, `before_cursor_execute`.

**This is the strongest transparent-crypto hook of any ORM surveyed.** `TypeDecorator` sits at the Core type layer, so it applies to ORM flush, `session.execute(insert(User), [dicts])` (bulk/`insertmanyvalues`), `executemany`, `session.execute(update(...))`, **and WHERE clauses** — `User.email == "x"` produces a `BindParameter` typed from the column, so `process_bind_param` fires. Deterministic-encryption equality filters work with zero query rewriting. *(Caveat under this spec: the registry contains no deterministic suite, so parameter conversion through the encrypting type never matches stored randomized ciphertext. The capability is exercised via the index-typed property — spec §10 L2 (a) — or the `Comparator` rewrite below.)*

**Not covered.** ORM mapper events do **not** fire on bulk paths (docs: "these events apply only to the session flush operation, and not to the ORM-level INSERT/UPDATE/DELETE functionality") — use `do_orm_execute`. `text()` only converts if types are attached via `.bindparams(bindparam("x", type_=EncType))`. `conn.exec_driver_sql()` bypasses everything.

**Query rewriting.**

```python
class BidxComparator(Comparator[str]):
    def __eq__(self, other):
        return self.__clause_element__() == blind_index(other)

class User(Base):
    email_ct: Mapped[bytes]
    email_bidx: Mapped[str]

    @hybrid_property
    def email(self) -> str: return decrypt(self.email_ct)

    @email.inplace.comparator
    @classmethod
    def _email_cmp(cls): return BidxComparator(cls.email_bidx)
```

`User.email == "x"` now emits `email_bidx = ?`. Every other operator can be individually allowed or made to raise — which is exactly what spec §10.2 requires.

**⚠️ `cache_ok` is a security concern, not just a performance one.** If the type holds a key ID or a dict, the compiled-statement cache key is wrong. Docs require hashable attributes matching `__init__` parameter names. Getting this wrong causes **cross-tenant key reuse from the statement cache** — a real security bug. The adapter must get this right and should have a test for it.

**Async.** `process_bind_param`/`process_result_value` are strictly synchronous and, under `AsyncEngine`, execute inside the greenlet bridging async↔sync. Awaiting a KMS client there raises `MissingGreenlet: greenlet_spawn has not been called`. There is an unsupported escape hatch (`sqlalchemy.util.await_only`); it was not verified from inside a type processor and should not be relied on.

**Gotchas.** In-place mutations are not detected ("in-place changes to values will not be detected and will not be flushed") — encrypting a dict/list payload requires `sqlalchemy.ext.mutable` · identity map holds plaintext; `expire_on_commit=False` extends that lifetime · `UniqueConstraint` on ciphertext is useless with a random nonce.

**Backfill.** Better than Django's: `session.execute(update(User), [dicts])` goes through the type layer, so the backfill encrypts on that path, unlike Django's `.update()`.

---

## 3. Prisma 7.x

**Hooks.** Client Extensions (GA since 4.16). The `query` component — `{ query: { $allModels: { async $allOperations({ model, operation, args, query }) {...} } } }` — is the only component that can touch writes and filters; `args` is mutable. The `result` component is read-side only and adds *virtual* fields. `$use` middleware is deprecated.

**Coverage.** `$allOperations` covers every model operation including `createMany`, `updateMany`, `upsert`, `findMany`, `count`, `aggregate`, `groupBy`. Raw queries appear with `model === undefined` and give an opaque SQL template — unusable. **`select`/`include` cannot be mutated** (docs: "you cannot mutate `include` or `select` because that would change the expected output type and break type safety"), so the ciphertext column cannot be transparently added to a projection that omitted it. `result.compute` fields are unusable in `where` or `orderBy`, so the `result` component cannot help with query rewriting.

**⚠️ The correctness cliff.** Query rewriting is JSON-path string surgery on an untyped args tree. From `prisma-field-encryption`'s `src/encryption.ts`, only `where.field`, `where.field.equals`, `where.field.not`, `connect.field`, and `cursor.field` are rewritten. Consequently:

- `where.field.in: [...]` — **not** rewritten (the visitor's path ends in an array index). The value gets *encrypted* instead and the query returns **zero rows, silently, with no error**.
- `contains:` / `startsWith:` — same failure mode.
- `orderBy` on an encrypted field — deleted from the query with a `console.error`.

**Spec §10.2 requires the adapter to throw on all of these**, which is a change from what `prisma-field-encryption` does today. This is the single most important behavioral difference between a conformant Prisma adapter and the existing library.

**Async.** Best in class. `$allOperations` is `async`; KMS can be awaited directly, and no database connection is held (the extension runs before the query engine acquires one).

**Schema.** Prisma has no schema-generation extension point, so the encrypted-field annotation must be a `///` doc comment read back from the DMMF at runtime. Prisma 7's Rust-free client changed DMMF availability — plan for a `dmmf` config option.

---

## 4. TypeORM 1.1.0 — the hard case

**Hook.** `ValueTransformer { to(value: any): any; from(value: any): any }` set as `@Column({ transformer })`. Plus `@EventSubscriber()` subscribers and entity listener decorators.

**Coverage** (verified by tracing `ApplyValueTransformers` call sites): `InsertQueryBuilder.ts:1535` (covers `save()`, `insert()`, bulk) · `UpdateQueryBuilder.ts:571` (SET values) · `SelectQueryBuilder.ts:~4419` (**find-options WHERE only**) · `FindOperator.ts:150` (`In()`, `Not()`, …) · `RawSqlResultsToEntityTransformer.ts` (read path).

**Not covered:** `qb.where("user.email = :email", { email })` string conditions · `getRawMany()`/`getRawOne()` · `manager.query()` · `.returning()` · relation-key comparisons ([#10365](https://github.com/typeorm/typeorm/issues/10365)).

**⚠️ The killer.** `SubjectChangedColumnsComputer.ts:101` applies `transformTo` for dirty-checking. With non-deterministic encryption the transform output differs every time, so **every `save()` marks every encrypted column dirty** and writes it.

**No sibling access.** `to(value: any): any` receives nothing but the scalar — no column metadata, no entity, no context. This is the hardest limit in the survey. AAD binding via transformer is impossible; a subscriber's `beforeInsert(event.entity)` works but then does not cover QueryBuilder `insert()`/`update()`. An AsyncLocalStorage/CLS-carried tenant context read inside `to()` works for tenant AAD, not row AAD.

**No query-rewrite extension point at all.**

**Verdict.** L1 with documented carve-outs, plus L2 (a) only. Transparent blind-index rewriting is **not implementable** (no predicate-rewrite hook), but the index-typed property works: declare the index column as its own `@Column({ transformer })` whose `to()` derives the blind index, and query it explicitly — `repo.find({ where: { emailBidx: plaintext } })` converts the parameter through the find-options/`FindOperator` path. Under this spec's randomized-only registry, the dirty-check consequence stands: **every `save()` rewrites every encrypted column with a fresh envelope** — document it, and lint-ban `save()` loops on hot paths. (Projects outside this spec often reach for deterministic AES-SIV here instead; the v0.1 registry deliberately contains no deterministic suite — spec §13.6.)

---

## 5. Hibernate 7.x / JPA 3.2

**Four hook layers:**

1. **`AttributeConverter<X,Y>`** — simplest, least capable.
2. **`UserType<J>`** — `nullSafeGet`, `nullSafeSet(…, SharedSessionContractImplementor session)`, plus `equals`, `disassemble`/`assemble`. **`CompositeUserType` maps one Java property to two columns** — the only first-class one-property→N-columns mapping in the survey, and the architecturally correct home for (ciphertext, blind index).
3. **`@ColumnTransformer(read=…, write=…)`** — SQL-level, applies to HQL/criteria WHERE clauses. **The only mechanism in the survey giving server-side query-integrated decryption** — and it requires the key to reach the database, which defeats the threat model. Do not use it.
4. **`org.hibernate.Interceptor`** — `onPersist(entity, id, state[], propertyNames, types)` where "the interceptor may modify the `state`, which will be used for the SQL `INSERT`." **The cleanest sibling-access hook in the survey.**

**Prefer `UserType` over `AttributeConverter`, for two concrete reasons:**

- **Second-level cache.** `@Cache` regions store the disassembled entity state. If the converter produces plaintext on read, the L2 cache stores **plaintext**, potentially in a distributed Infinispan/Redis grid. `UserType.disassemble()` lets you keep ciphertext in the L2 cache; `AttributeConverter` gives no such control.
- **Dirty checking.** Hibernate compares via `Type.isDirty`/`UserType.equals`. Non-deterministic encryption inside a converter makes `equals` compare ciphertexts → spurious updates. `UserType.equals` lets you fix this; `AttributeConverter` does not.

**AttributeConverter restrictions:** may not be applied to `@Id`, `@Version`, relationship attributes, or (JPA-explicit) `@Enumerated` attributes. Collections need `@Convert(attributeName=…)` and this has regressed before.

**Hibernate is the only ORM where L3-row is cleanly achievable** — with `SEQUENCE`, `TABLE`, or assigned/UUID generators, the id is already allocated before the INSERT and is passed to `onPersist`.

**Query rewriting** is the weak spot: no per-operator comparator hook exists. Options in descending cleanliness: `CompositeUserType` with explicit `where e.email.bidx = :p` · `@FilterDef`/`@Filter` (adds predicates, cannot rewrite) · `StatementInspector` (regex on generated SQL — and the parameter values aren't visible to it, so you can't compute the index there).

**Pooling.** `convertToDatabaseColumn` runs while a JDBC connection is checked out and a transaction is open. A 20 ms KMS round-trip per row during a flush of 1,000 rows holds the connection for 20 seconds → pool exhaustion. Caffeine/Guava DEK cache with async refresh outside the transaction is mandatory. Hibernate Reactive is worse: the converter is still sync and blocks the Vert.x event loop.

**Also note:** Envers writes the converted value into `_AUD` tables — usually desirable, but the audit table needs the same key lifetime, and this is a crypto-shredding surface.

---

## 6. EF Core 10

**Hooks.** `ValueConverter<TModel,TProvider>` (expression trees, not delegates) · `ValueComparer<T>` · `ISaveChangesInterceptor` · `IDbCommandInterceptor` · `IMaterializationInterceptor` · `IQueryExpressionInterceptor` · **shadow properties** (`modelBuilder.Entity<User>().Property<string>("EmailBidx")`) — **EF Core is the only ORM here with a first-class shadow-property concept, and it is best in class for the index column.**

**Documented limitations that shape the design, verbatim:**

- "There is currently no way to spread a conversion of one property to multiple columns or vice-versa" ([#13947](https://github.com/dotnet/efcore/issues/13947)) — **kills the one-property→ciphertext+index mapping.**
- "**Value conversions cannot reference the current DbContext instance**" ([#12205](https://github.com/dotnet/efcore/issues/12205)) — **kills per-request tenant/key resolution inside the converter**, forcing `AsyncLocal` or a static service locator.
- "Parameters using value-converted types cannot currently be used in raw SQL APIs."
- "`null` cannot be converted" — so a null-vs-empty-string distinction leaks and you cannot encrypt the fact that a value is null.

**Consequence:** three hooks do one job. Converter for the value path (sync), `SaveChangesInterceptor` for sibling access and index population (async-capable), `IQueryExpressionInterceptor` for query rewriting, `IMaterializationInterceptor` (sync-only) for anything the converter can't do on read.

**Query rewriting.** `IQueryExpressionInterceptor.QueryCompilationStarting` with an `ExpressionVisitor` rewriting `u.Email == c` into `EF.Property<string>(u, "EmailBidx") == Bidx(c)` before translation. This is the correct supported hook and the most work — you are writing a LINQ expression-tree rewriter.

**Gotchas.** `ValueComparer` is **mandatory** for `byte[]`/mutable ciphertext or change tracking uses reference equality; with non-deterministic encryption, define the comparer over the *plaintext* model type · `EFCoreSecondLevelCacheInterceptor` (very common) caches materialized entities → **plaintext in Redis** · compiled queries capture the converter closure at model-build time, so **key rotation requires rebuilding the model** unless an ambient key cache is used.

---

## 7. GORM v1.31.x

**Hooks.** `SerializerInterface` with `Scan(ctx, field, dst reflect.Value, dbValue)` and `Value(ctx, field, dst reflect.Value, fieldValue)`, registered via `schema.RegisterSerializer("fieldseal", …)` and applied with `gorm:"serializer:fieldseal"`. Plus hooks (`BeforeSave`, `BeforeCreate`, `AfterFind`) and the plugin/callback API.

**GORM wins on sibling access.** `Value(ctx, field, dst, fieldValue)` receives **`dst`, the `reflect.Value` of the whole struct**, plus `ctx`. A serializer can read `tenant_id`, other columns, and request-scoped values off the context — all three inputs AAD binding needs, **with no side channels**. Same on the read side.

**⚠️ The silent plaintext hole.** Verified from `callbacks/update.go:~225`:

| Path | Serializer fires |
|---|---|
| `Create(&user)`, `Create(&[]User{...})`, `CreateInBatches` | ✅ |
| `Save(&user)` / `Updates(&User{...})` (struct) | ✅ |
| **`Updates(map[string]interface{}{...})`** | ❌ — **writes plaintext** |
| **`Update("email", v)`** | ❌ — same map path |
| `Find`, `First`, `Take` into a struct/slice | ✅ |
| `db.Raw("...").Scan(&users)` | ✅ — GORM decrypts raw-SQL results into structs |
| `Where("email = ?", v)` / `Where(&User{Email:v})` | ❌ |
| `Pluck`, `Rows()`, `Scan(&map)` | ❌ |

The adapter **must** intercept or reject map-based `Updates`. Spec §10.2 makes this normative.

**Query rewriting.** `db.Callback().Query().Before("gorm:query")` gives structured access to `stmt.Clauses["WHERE"]` as `clause.Where{Exprs: []clause.Expression{clause.Eq{Column, Value}, …}}`. Walking that tree and rewriting `clause.Eq{Column: "email"}` → `clause.Eq{Column: "email_bidx", Value: bidx(v)}` before SQL generation is genuinely clean — better than TypeORM (impossible) and Hibernate (regex), comparable to Django. Caveat: `db.Where("email = ?", v)` produces an opaque `clause.Expr{SQL: ...}` that would have to be parsed; reject it instead.

**Async.** Fits best of any ORM. `Value`/`Scan` take a `context.Context` and can block on a KMS RPC with the caller's deadline and cancellation. The connection-hold concern still applies; use a `singleflight` + TTL cache.

---

## 8. Rails 8 Active Record Encryption — what to steal

Not a target adapter (Ruby is out of the initial scope) but the most mature implementation in existence and worth reading before writing anything.

**It is a type decorator, not a callback.** `encrypts :email` calls `encrypt_attribute` → `decorate_attributes([name]) { |name, cast_type| EncryptedAttributeType.new(scheme:, cast_type:, default:) }`, where `EncryptedAttributeType < ActiveModel::Type::Value` implements `serialize`, `deserialize`, `cast`, `changed_in_place?`. Because it composes over the *existing* cast type, `encrypts` works on integer and JSON columns too. **Adopt this shape.**

**⚠️ Rails does not bind AAD.** `cipher/aes256_gcm.rb` literally does `cipher.auth_data = ""` on decrypt. The reference implementation punted on row/tenant binding because `ActiveModel::Type` has no access to the record. **This is the decisive evidence behind spec §6.4** — AAD row-binding cannot be a mandatory conformance requirement for a type-decorator-shaped design.

**Query support is narrower than it looks.** `ExtendedDeterministicQueries.install_support` **monkeypatches** `Relation#where`, `#exists?`, `#scope_for_create`, and `Base.find_by`, expanding `email: "x"` into `email: ["<ct-current>", AdditionalValue("<ct-previous>"), …]`. The source comment is candid: `@TODO Experimental. Support for every kind of query is pending`. Not `joins`, not `order`, not `LIKE`, not arbitrary Arel.

**Worth stealing:**

- The message envelope with headers (`{p: payload, h: headers}`).
- `previous_schemes` as a first-class list — this is the rotation mechanism.
- `support_unencrypted_data` / permissive-read and `extend_queries` as explicit, defaulted-off migration flags.
- The key-provider interface shape (`encryption_key`, `decryption_keys(encrypted_message)`).
- `ignore_case: true` auto-creating a second column `original_email` via `preserve_original_encrypted`, and **raising `Errors::Configuration` at boot if the column is missing** — a shipped, working shadow-column pattern with a boot-time check.
- The honest scoping of query support.

**Worth avoiding:** using `Marshal` for payload serialization. Rails' first version did, creating an **RCE vulnerability** caught only while writing it up for upstream. Use a non-code-executing format.

---

## 9. Sequelize v7 (deferred)

Weakest coverage of the JS ORMs. Documented hard limit: "Static model methods do not interact with the instance of the model, and therefore will ignore any getters or setters defined for the model" — so `Model.bulkCreate()` (unless `individualHooks: true`), `Model.update()`, and `Model.increment()` bypass setters, and `findAll({raw: true})` bypasses getters. Virtual attributes cannot appear in `where`.

The right layer is a custom `DataTypes` subclass with `toBindableValue`/parsers, which sits below the static/bulk methods — analogous to SQLAlchemy's `TypeDecorator`. That coverage matrix was **not verified** and should be tested before committing to an adapter.

---

## 10. Architectural boundary

```
┌──────────────────────────────────────────────────────────────┐
│ CORE (per language, identical spec + test vectors)           │
│                                                              │
│  encrypt(pt, ctx) -> bytes                          [SYNC]   │
│  decrypt(ct, ctx) -> bytes                          [SYNC]   │
│  blind_index(pt, ctx) -> bytes                      [SYNC]   │
│  is_ciphertext(b) -> bool                           [SYNC]   │
│  rotate(ct, ctx) -> bytes                           [SYNC]   │
│  warm(contexts) -> None                        [ASYNC OK]    │
│                                                              │
│  KeyProvider: encryption_key(ctx),                           │
│               decryption_keys(header)                        │
│  Envelope + suite registry + previous-schemes chain          │
│  Modes: strict | permissive | readonly                       │
└──────────────────────────────────────────────────────────────┘
                            ▲
          ── the ONLY calls an adapter may make ──
                            │
┌──────────────────────────────────────────────────────────────┐
│ ADAPTER (per ORM, ~300–800 LOC, ZERO cryptography)           │
│                                                              │
│  1. Declaration surface                                      │
│     Django    EncryptedField(...)                            │
│     SQLA      EncryptedType(TypeDecorator) + Comparator      │
│     Prisma    /// @encrypted doc-comment → DMMF              │
│     TypeORM   @Column({ transformer })                       │
│     Hibernate @Type(UserType) / CompositeUserType            │
│     EF Core   HasConversion + shadow property + interceptors │
│     GORM      gorm:"serializer:fieldseal"                    │
│                                                              │
│  2. FieldContext assembly — the adapter's real job           │
│     table/column statically; tenant from the ORM's per-op    │
│     context (GORM dst+ctx, Hibernate state[], Prisma args,   │
│     EF ChangeTracker) or from ambient CLS                    │
│                                                              │
│  3. Query rewriting where supported; explicit THROW where    │
│     not (spec §10.2)                                         │
│                                                              │
│  4. A published coverage matrix                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 11. Zero-downtime backfill (common shape)

1. **Migration:** add `col_ct` and `col_bidx` as nullable columns alongside `col`. `AddField` only; no lock beyond the DDL.
2. **Deploy dual-write:** read prefers `col_ct` and falls back to `col`; write both. Core in `permissive` read mode.
3. **Batched backfill:** iterate with a stable cursor, chunked, resumable, rate-limited. **Must go through the encrypting path** — Django's `queryset.update(F(...))` will not encrypt; `bulk_update` will. SQLAlchemy's `session.execute(update(User), [dicts])` will.
4. **Deploy ciphertext-only read.** Switch core to `strict` mode. Watch the plaintext-read metric go to zero.
5. **Migration:** drop `col`.

`prisma-field-encryption`'s generator (cursor-field-based, with `?mode=readonly` and multi-key decryption) and Rails' `bin/rails db:encrypt:all` are the only shipped backfill tooling in any surveyed library. Both are worth reading.

**⚠️ Crypto-shredding caveat.** Per NIST SP 800-88r2 §3.2.2, cryptographic erase requires that "no sensitive data has previously been stored on the ISM in plaintext form." Retrofitting onto an existing table permanently voids crypto-shredding claims for every pre-existing backup. Document this at migration time, not after.
