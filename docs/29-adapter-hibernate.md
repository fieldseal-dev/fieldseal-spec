# Hibernate Adapter Technical Specification

**Date:** 2026-09-29 · **Status:** Draft 1, written before the code (`docs/26` §2.1, WS-N) and updated as built. **Built 2026-09-29**: everything below except the backfill frontend (§9), green on H2 and Postgres, with a cross-job producer leg · **Purpose:** the engineering design for `adapters/hibernate` (artifact `fieldseal-hibernate`), targeting **Hibernate ORM 7.4** (7.4.11.Final, the latest 7.x release on 2026-09-29; 8.0 is at Beta3) on the Java core of `docs/27`. It is the first Phase 2 adapter. `docs/04` §5 is verified against Hibernate's own source in §1 before any level is claimed here, as `docs/26` §6 requires, and corrected where it is wrong.

**Conformance target (spec §10.1):** L0 (the core's) · L1 ✅ · L2 (a) ✅ with mandatory re-verification · L3 tenant ✅ from the session's tenant identifier · L3-row ❌ not in v0 (§4) · L4 ❌ (spec §10.1: Hibernate cannot await in the value path).

**Hard rule (spec §11.3, AD-1):** zero cryptography in this package. It calls `encrypt`, `decrypt`, `blindIndex`, `isCiphertext` and `warm` on the core's `Fieldseal`, the core's normalizer for spec §7.5's comparison (`IndexDeclaration.Normalizer.normalize`, public for exactly that), and `Fieldseal.firstUnassigned` for §10's message. CI greps `src/main` for crypto imports.

**What this document does not cover:** the backfill frontend `docs/26` §4 requires of every Phase 2 adapter. It is built against `tools/backfill/PROCEDURE.md` unchanged, which WS-R has not written yet, so it cannot be built now, and WS-N does not close without it (`docs/26` §5 item 4). §9 says what exists meanwhile.

---

## 1. `docs/04` §5 checked against Hibernate 7.4.11

Read from the `hibernate-core-7.4.11.Final` sources jar, and where a claim is about behaviour rather than a signature, measured with the adapter's own test suite on H2 and Postgres. Each line is *confirmed*, *corrected*, or *not checked* with the reason.

| `docs/04` §5 claim | Result |
|---|---|
| `Interceptor.onPersist(entity, id, state[], propertyNames, types)`, where "the interceptor may modify the `state`, which will be used for the SQL `INSERT`" | **Confirmed**, verbatim, in `org.hibernate.Interceptor`. `onSave` is deprecated since 6.6 and `onPersist` delegates to it by default |
| The id is allocated before the INSERT with `SEQUENCE`, `TABLE`, assigned or UUID generators, and not with `IDENTITY` | **Confirmed by measurement**, at the event-listener layer this adapter uses (`PreInsertEvent.getId()`): a UUID and a sequence value are present; `IDENTITY` gives `null` |
| `UserType` has `nullSafeGet`, `nullSafeSet`, `equals`, `disassemble`/`assemble` | **Confirmed**, with a change of signature: in 7.x both value methods take `WrapperOptions` (which carries the session), and the `SharedSessionContractImplementor` overloads are deprecated for removal |
| `CompositeUserType` maps one property to several columns | **Confirmed** that it exists (`org.hibernate.usertype.CompositeUserType`). Not used: §3 says why |
| `@ColumnTransformer` gives server-side, query-integrated decryption and needs the key in the database | **Not checked**; this adapter does not use it, for the reason `docs/04` gives |
| "Non-deterministic encryption inside a converter makes `equals` compare ciphertexts → spurious updates" | **Corrected: false on 7.4.11.** Measured with an `AttributeConverter` that encrypts under a fresh nonce on every call: `persist` then two flushes issues one `INSERT`, and a load then a flush issues no `UPDATE`. Hibernate compares converted attributes on their domain values, not on what the converter produced. The reason this adapter uses a `UserType` anyway is a different one, in §2: a converter cannot tell a write from a query parameter |
| The second-level cache stores disassembled state, and `UserType.disassemble()` is where to keep ciphertext in it | **Confirmed** that the insert action builds its cache entry from the insert's state array (`EntityInsertAction`). Not relied on: v0 refuses second-level caching of an entity with an encrypted attribute (§5, `FS-H006`), because `disassemble(J)` and `assemble(Serializable, Object)` receive no session, so a tenant-bound column could not be decrypted or encrypted there |
| `AttributeConverter` may not be applied to `@Id`, `@Version`, relationships or `@Enumerated` attributes | **Not checked**; this adapter declares no converter |
| Query rewriting: no per-operator comparator hook; options are an explicit `CompositeUserType` path, `@Filter`, or `StatementInspector` regex, and `StatementInspector` cannot see parameter values | **Confirmed** for `StatementInspector` (`inspect(String sql)` receives SQL text only). **Incomplete** as a list: `hibernate.query.sqm.translator` (`QuerySettings.SEMANTIC_QUERY_TRANSLATOR`) takes an `SqmTranslatorFactory`, which receives every HQL and Criteria statement as a typed semantic tree (SQM) before SQL is generated. Measured: both HQL and Criteria reach it; `Session.find` and association loads do not. This adapter uses it for **refusals only** (§3.3). Whether it could carry a transparent rewrite, L2 (b), is not tested, and spec §10.1's "(b) not available" for Hibernate is not changed by this document |
| Pooling: a KMS round trip inside `convertToDatabaseColumn` holds a connection inside an open transaction | **Not measured**; the core's design already keeps KMS calls out of the value path (`warm`, spec §11.2), so the adapter inherits the fix rather than needing one |
| Hibernate Reactive blocks the Vert.x event loop; Envers writes converted values into `_AUD` tables | **Not checked**: neither is supported by v0 (§9) |

## 2. Declaration surface and value path

```java
@Entity
@FieldsealTable("018f3c2e-7a1b-7c3d-8e4f-000000000001")     // REQUIRED on an entity with encrypted attributes
public class Patient {
    @Id UUID id;                                             // any generator: the id is not bound in v0 (§4)

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000002")
    String email;                                            // the logical type comes from the Java type (§2.2)

    @BlindIndex(source = "email", id = "exact", idf = Idf.HMAC_SHA512,
                normalize = Normalizer.NFC_CASEFOLD_V1, truncateBits = 15, projectedPopulation = 100_000)
    byte[] emailIndex;                                       // the sibling column, declared explicitly

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000003", tenantBound = true)
    String note;
}
```

- **Surrogates in code** (spec §6.1), as in `docs/12` §1.1: the table and column UUIDs are literals in the source, never derived from entity or column names, so a rename changes nothing.
- **`@Encrypted` is a Hibernate `@Type` meta-annotation**, so the attribute is mapped by the adapter's `UserType`, constructed with the annotation and Hibernate's `UserTypeCreationContext`. The type reads the attribute's Java type from the creation context, and the integrator refuses an unmapped one when the session factory is built (FS-H009; spec §3.6: at declaration).
- **The index sibling is a `byte[]` attribute** holding spec §7.11's raw index bytes, `ceil(b/8)` long. Explicit, for `docs/12` §1.2's reasons: the DDL is visible, and a query names it.

### 2.1 Where encryption happens, and why not in the type

`nullSafeSet` is called for **both** a write and a query parameter, with nothing to tell them apart. A type that encrypted there would encrypt `where p.email = :e` with a fresh nonce and match nothing, silently: the Prisma failure spec §10.2 names, one ORM over. An `AttributeConverter` has the same problem and no way out of it.

So the adapter splits the job:

1. **An event listener seals on write.** `PreInsertEventListener` and `PreUpdateEventListener` receive the state array the SQL statement binds. For each encrypted attribute the listener renders the value (§2.2), encrypts it under the column's context, and replaces the state entry with a `Sealed` value that holds the plaintext and the envelope. It derives each blind index from the same rendered bytes and writes it to the sibling's state entry **and** to the entity.
2. **The type binds only what was sealed.** `nullSafeSet` binds a `Sealed` value's envelope, binds `NULL` for `null`, and **refuses anything else**: a plain value at an encrypted column's JDBC binding is a query parameter or a write path the listener did not see, and either way binding it would write plaintext or mis-serve a query. This is the adapter's backstop, below every entry point, and it is why an unintercepted write path fails loudly instead of degrading. *As built:* no configured path reaches it today, because the listener seals every write it sees and the walker (§3.3), which FS-H005 makes mandatory, refuses a query shape before a parameter is bound. So it is tested directly (`BindingGuardTest`), and its bite check turns that test red; end to end it is defence in depth, stated as such rather than counted as a second refusal.
3. **The type decrypts on read.** `nullSafeGet` decrypts under the column's context and parses (§2.2). Projections (`select p.email from Patient p`) therefore decrypt as entity loads do.

Measured, and pinned by `HibernateBehaviourTest` so a Hibernate upgrade that changes it goes red:
- The state array the pre-insert listener receives is the one the `INSERT` binds and the one kept as the dirty-checking snapshot (`EntityInsertAction`: `preInsert()`, then `insert(…, getState(), …)`, then `entry.postInsert(getState())`), and the entity keeps its plaintext.
- `persist` then a second flush issues one `INSERT` and no `UPDATE`: the type's `equals` compares a `Sealed` value by its plaintext.
- A changed value issues one `UPDATE`, with a fresh envelope, and a further flush issues none.
- `StatelessSession.insert` and `Session.merge` go through the listener; JDBC batching (`hibernate.jdbc.batch_size`) still batches.

**Every `UPDATE` re-encrypts every encrypted column of the entity.** Hibernate's default update writes every column, from the entity's current state, which holds plaintext. That is a fresh nonce on every write, which spec §3.1 requires, at the cost of an AES-GCM operation per column per update. A blind index is **not** re-derived when its source did not change (Argon2id costs 10–100 ms, spec §7.3): the listener restores the loaded index bytes instead, which also undoes any assignment the application made to the sibling.

### 2.2 The codec (spec §3.6)

The attribute's Java type fixes the logical type, at metadata build:

| Java type | Logical type | Notes |
|---|---|---|
| `String` | `string` | An unpaired surrogate is refused; read with a strict UTF-8 decoder |
| `byte[]` | `bytes` | |
| `long`/`Long`, `int`/`Integer`, `short`/`Short`, `BigInteger` | `int` | A read beyond the attribute's range is refused, never truncated |
| `BigDecimal` | `decimal` | Canonical by value: `1.50` is written `1.5`, and read back as `1.5` |
| `double`/`Double` | `float` | ECMAScript `Number::toString` from the JDK's shortest-repr digits (`Double.toString` since JDK 19); `-0` kept |
| `boolean`/`Boolean` | `boolean` | |
| `LocalDate` | `date` | Years 1–9999 |
| `Instant`, `OffsetDateTime` | `datetime` | Rendered in UTC with six fractional digits; a value with a nonzero digit below the microsecond is **refused, not truncated**; an `OffsetDateTime` reads back at `UTC` |

Refused at declaration: `float`/`Float` (binary32 is not in the vocabulary, and a binary64 read back into one would round), `LocalDateTime` (naive, spec §3.6), `ZonedDateTime`, `LocalTime`, `UUID`, enums, `char`, and every other type. An application that needs one stores a `String` it renders itself, as spec §3.6 says.

The codec is the function both the write path and the index path call, and the `codec/` family runs through it (§8). *As built:* `float` is not `Double.toString`, which since JDK 19 may print two digits where one round-trips (the smallest subnormal is `4.9E-324` there and `5e-324` in ECMAScript); the codec finds the fewest round-tripping digits itself, and the closest of them. Checked once at authoring time, not in CI, against Node 24.16.0's `String(x)` on 220,000 doubles (random bit patterns, a decade-spread sample and the edge values): no disagreement, and every rendering parsed back to the same bits. `BigDecimal` cannot hold NaN or ±Infinity, so the two `decimal` write vectors for them hand the codec the literal's text, which it refuses as a value of the wrong type; `CodecVectorsTest` says so. The platform holds `calendar-date`, `microsecond-instants` and `naive-datetimes`, so four vectors are skipped for a capability, the same four as Django's.

## 3. Query path

### 3.1 L2 (a): the finder, and why raw HQL over an index is refused

Spec §10.1 gives Hibernate L2 (a): the index is its own property, queried explicitly. Spec §7.5 makes the answer a *filter*: the rows an index returns are candidates, and a row whose value differs but collides under §7.4's truncation must be dropped. HQL cannot do that, because the database answers it. So the adapter's query surface is a finder that runs the index query and re-verifies what comes back:

```java
List<Patient> hits = FieldsealQueries.of(session, Patient.class)
        .whereIndex("emailIndex", "ada@example.com")   // derives the index from the plaintext
        .where("status", Status.ACTIVE)                // an ordinary column, compared in SQL
        .list();                                       // verified: every row's email normalizes equal
```

- **What it runs** is a Criteria query with the derived index bytes as an ordinary parameter, `AND`ed with the ordinary equalities. `whereIndexIn(attr, values)` is spec §7.10's membership form (one `IN` over the N index values).
- **What it returns** is re-verified: each candidate's decrypted source value is compared with the queried value under the index's own normalizer (spec §7.5, G19), through the core's `Normalizer.normalize`, never a reimplementation. A refused value falls back to its raw bytes, as the core documents.
- **The surface is conjunctive on purpose.** Under `AND`, every returned row must satisfy each index term, so per-term verification is exact (`docs/12` §3.2). There is no `OR`, no negation and no pagination: `docs/12` §3.2's table gives the reasons, and none of them is Django's alone.
- **`count()`, `first()`, `exists()`** materialize and verify; the bucket bounds the cost (spec §7.4).
- **`.candidates()`** returns the unverified bucket, documented as such: spec §10.2's escape hatch. It lifts nothing else, because the finder builds no negation for it to lift.

**Raw HQL or Criteria naming an index attribute in a predicate is refused** (§3.3), because nothing re-verifies what it returns. The finder's own query passes because the refusal walker (§3.3) runs inside the finder's scope, which it marks; the finder also turns off query-plan caching for its query, so no cached plan can carry the mark to a query outside it.

### 3.2 Why not `CompositeUserType`

`docs/04` §5 calls `CompositeUserType` "the architecturally correct home for (ciphertext, blind index)". It is a type-safe surface for `where p.email.index = :p`, but the parameter would bind through the index sub-attribute's type, which has the same write-or-query blindness as §2.1, and it would still return an unverified bucket. The explicit sibling plus the finder gives the same explicit surface, keeps the index and the envelope derived in one place (the listener), and puts §7.5 in the only place it can run.

### 3.3 Refusals (spec §10.2: throw, never degrade)

Two layers, deliberately one below the other, as `docs/12` §3.2 argues for Django: an entry point list is the failure mode.

**At the JDBC binding (§2.1, item 2).** Any plain value bound to an encrypted column raises `FieldsealNotSupportedException`. That covers, with no query analysis at all: `where p.email = :e`, `in (:list)`, HQL and Criteria `update … set email = :e`, `insert … values (…)`, `@NaturalId` lookups, and any write path the listener does not reach.

**Before SQL is generated.** A `SqmTranslatorFactory` wrapping Hibernate's own walks every HQL and Criteria statement's semantic tree and refuses, naming the attribute and the reason:

| Shape over an encrypted attribute `E` or an index attribute `I` | Behaviour | Why |
|---|---|---|
| `E` in any predicate but `is [not] null` — a comparison, `like`, `between`, `in`, including against a literal or another path | **refused** | A literal never reaches the binding: HQL renders it inline, and on Postgres an untyped literal compared with `bytea` is coerced and matches nothing. Measured on H2: a literal reaches the database |
| `E is null`, `E is not null`, under any negation | **served** | Spec §10.2's NULL-preservation invariant: exact, no bucket involved |
| `E` in `order by`, `group by`, `distinct` selection of the column, a subquery's selection, or as an argument to a function or aggregate | **refused** | Reads envelope bytes (spec §10.2, G20) |
| `count(E)`, plain and not distinct | **served** | Spec §10.2's carve-out: it reads null-ness only |
| `select E` | **served** | Decrypted by the type |
| `I` in any predicate, outside the finder's scope | **refused** | An unverified bucket (spec §7.5) |
| `I` under a negation, in or out of the finder | **refused** | Spec §10.2 (G24): an exclusion's false negatives are not recoverable. The finder never builds one; the refusal is for a query that does |
| `E` or `I` as the target of an HQL `update … set` or `insert` | **refused** | `I` has no binding guard, and its value must come from the listener, which a bulk mutation bypasses |
| `order by I` | **served** | Deterministic and meaningless, as `docs/12` §3.2 allows |

**Refused before either layer, by Hibernate itself** (measured, and pinned by `QueryRefusalTest.hibernatesOwnTypingRefusesStringFunctionsOverTheColumn`): `like`, `lower`, `upper`, `length`, `min` and `max` over an encrypted or index attribute. The column is `VARBINARY`, and Hibernate's own typing rejects a string or comparable function over it when the query is created, so the statement never reaches the walker. The walker is default-deny, so a Hibernate that stopped rejecting them would reach its refusal instead.

**What neither layer can reach**, documented rather than claimed: native SQL (`createNativeQuery`, `@SQLRestriction`, `@Formula`, `@SQLInsert`): its parameters and text never pass through the type's JDBC binding or through SQM. `StatementInspector` could see the text but not the parameters, so it is not a refusal layer either. The README lists this with the remediation.

## 4. Context assembly and modes

- **Table and column** come from `@FieldsealTable` and `@Encrypted`, fixed at metadata build.
- **Tenant (L3):** from the session's tenant identifier, `SharedSessionContractImplementor.getTenantIdentifierValue()`, the value Hibernate's own multi-tenancy sets (`SessionBuilder.tenantIdentifier(Object)`, or a `CurrentTenantIdentifierResolver`). It is the ORM's per-operation context, not a side channel, which is what spec §10.1's ✅ for Hibernate asks for. Measured: the identifier reaches the pre-insert listener even with no multi-tenancy strategy configured. A `String` becomes its UTF-8 bytes (as the Django adapter's contextvar does), a `byte[]` is used as is, and any other type is refused. A column declared `tenantBound = true` with no tenant on the session **fails closed** on read and on write, never falling back to a tenantless context.
- **Row (L3-row): not in v0.** The pre-insert listener has the id (§1), so binding it on write is easy. Reading is not: `nullSafeGet` has no id, so a row-bound column would have to be decrypted after hydration, which a projection never passes through. The design that works (a sealed placeholder opened in `Interceptor.onLoad`, and projections of row-bound columns refused) is recorded here for the increment that builds it.
- **Read mode** is the client's, fixed at construction (`docs/09` §2). `permissive` and `readonly` warn through the client's hook; the plaintext-read metric is the core's, and not built yet (`docs/27` §4).

### 4.1 Client construction

The adapter builds the `Fieldseal` client, because only it knows the declared indexes, and the core's construction-time validation (spec §7.4's band, §7.6's gate) must run against the indexes actually declared. The application passes a configurer under one setting:

```java
settings.put(FieldsealSettings.CLIENT, (FieldsealConfigurer) b -> b
        .keyProvider(keys).allowedSuites(Set.of(0xFF01)).writeSuite(0xFF01).readMode(ReadMode.STRICT));
settings.put(QuerySettings.SEMANTIC_QUERY_TRANSLATOR, FieldsealSqmTranslatorFactory.class.getName());
```

The adapter hands the configurer a builder that already carries the declared indexes and builds it. A prebuilt `Fieldseal` is accepted under the same key for a deployment that must own its wiring, and its `indexes()` must then equal the declared set **exactly** (`FS-H004`): `docs/12` §5's E006 argument, that only one direction of a mismatch is loud.

## 5. Startup checks

Run by the adapter's `Integrator` when the session factory is built; a failure is a `FieldsealConfigurationException` naming the entity and attribute. Ids are this adapter's own.

| Id | Condition |
|---|---|
| FS-H001 | An encrypted attribute on an entity with no `@FieldsealTable`, or a table or column UUID that is not a UUID, or two columns of one table with the same UUID |
| FS-H002 | An encrypted or index attribute that is the id, the version, a natural id, `unique`, or part of a unique constraint (spec §7.10, G12) |
| FS-H003 | `@BlindIndex` whose `source` is not an encrypted attribute of the same entity, or an index attribute that is not `byte[]`, or an index declaration the core refuses (spec §7.4, §7.6, `docs/09` §7.2); the core's reason is carried |
| FS-H004 | No `FieldsealSettings.CLIENT`, a value of the wrong type, or a prebuilt client whose index registry differs from the declared one |
| FS-H005 | `hibernate.query.sqm.translator` is not this adapter's factory: without it every §3.3 query refusal but the binding guard is absent, silently |
| FS-H006 | An entity with an encrypted attribute is second-level cacheable (§1: the cache would hold plaintext, or could not decrypt a tenant-bound column) |
| FS-H007 | An entity with a blind index uses `@DynamicUpdate`: the `UPDATE` would name only the columns Hibernate found dirty, and the index sibling is written by the listener after that decision, so the index would go stale — a silent lookup miss |
| FS-H008 | An encrypted or index attribute in an embeddable, an element collection, or an entity in an inheritance hierarchy (§9) |
| FS-H009 | An encrypted attribute whose Java type §2.2 does not map to a spec §3.6 logical type |

## 6. Coverage matrix (AD-2)

Published in the package README, with each row citing the tests that prove it; `scripts/coverage_report.py` fails if a cited test is missing or not green (`docs/14` §4, "generated from the published table").

| Path | Behaviour |
|---|---|
| `persist`, `merge`, flush of a changed entity, JDBC batching | ✅ encrypts; index derived |
| `StatelessSession.insert`, `update` | ✅ encrypts; index derived |
| `session.find`, association loads, HQL/Criteria entity results, projections | ✅ decrypts |
| `FieldsealQueries…whereIndex/whereIndexIn…list/count/first` | ✅ L2 (a), verified |
| `.candidates()` | ⚠️ unverified bucket, by request |
| HQL/Criteria predicate on an encrypted attribute (parameter or literal) | 🛑 refused |
| HQL/Criteria predicate on an index attribute | 🛑 refused |
| ordering, grouping, `distinct`, functions and aggregates over an encrypted attribute | 🛑 refused; plain `count(E)` served |
| HQL/Criteria `update`/`insert` targeting an encrypted or index attribute | 🛑 refused |
| `is [not] null` on an encrypted attribute | ✅ served exactly |
| native SQL, `@SQLRestriction`, `@Formula`, custom SQL | 🛑 **cannot intercept**: documented hazard |
| second-level cache | 🛑 refused at startup (FS-H006) |
| persistence context (first-level cache) | ⚠️ holds plaintext entities for the session's life (spec §10.2), documented |
| L3-row binding | ❌ not in v0 (§4) |

## 7. Warm-up and operations

The type and the listener call the core synchronously, inside the flush, while a JDBC connection is checked out. Under an envelope provider nothing in that path may block on the KMS (spec §11.2), so something must warm the cache first: `FieldsealHibernate.warm(sessionFactory, tenants)` builds the context for every declared column and index and calls the core's `warm`. As in `docs/12` §7, a tenant-bound column needs its tenants named, and a run that omits them names the columns it skipped.

## 8. Test plan

- **Path matrix:** one test per §6 row, on **H2 and Postgres** (`FIELDSEAL_TEST_DB=h2|postgres`); CI runs both.
- **Refusals:** every 🛑 row asserts `FieldsealNotSupportedException` (or the startup exception) by type, not a generic error.
- **Hibernate behaviour pins:** the §2.1 measurements, so an upgrade that changes one goes red.
- **Re-verification:** two plaintexts that collide at a small `b`, found by brute force in the test; the finder drops the collision and `.candidates()` returns it.
- **Codec:** the whole `codec/` family (`MANIFEST.adapter_files`) through the adapter's codec, hash- and status-checked, with the skip count asserted.
- **Cross-language:** `CrossProduce` writes rows through the real session path (runtime CSPRNG, no test mode), reads the columns back over JDBC, and emits a `cross/v2` document with envelope and index cases. The local test decrypts it with a client built independently from `vectors/keys/`; CI adds `hibernate` to `CROSS_PRODUCERS`, so every core consumes it. *As built:* 13 envelope and 6 index cases; before the first push, the Python, TypeScript and Java consumers each passed all 19 locally.
- **Coverage report:** `scripts/coverage_report.py` parses §6's table from the package README and scores each row against the JUnit results; a row naming a test that did not run, or claiming behaviour with none, fails it. Both failure modes were seen to fire before it was committed.
- **Bite checks:** `scripts/bite_checks.py`, the Java core's runner with this adapter's list, not run in CI. As built: 20 mutations, 18 turn their named tests red, and 2 change nothing as stated: re-deriving an unchanged source's index (the same bytes; only Argon2id's cost would show it), and letting the finder's query plan be cached (Criteria plans are not cached by default, so the finder's query is translated on every run either way; the call is kept so that enabling that cache cannot carry the scope to another query).

## 9. Deliberate non-goals (v0)

No L3-row binding (§4); no transparent rewrite; no `OR`, negation or pagination in the finder; no second-level caching of encrypted entities; no encrypted attributes in embeddables, element collections or inheritance hierarchies; no Hibernate Reactive; no Envers; no `@DynamicUpdate` on an indexed entity; Hibernate 7.4 only. **The backfill frontend** is not built: it implements `tools/backfill/PROCEDURE.md`, which WS-R has not written, and `docs/26` §5 item 4 makes it part of WS-N's definition of done. Until it exists, a migration writes through the listener with ordinary `merge`/flush in batches, which encrypts; an HQL bulk `update` is refused (§3.3), which is the `docs/04` §11 rule that a backfill must go through the encrypting path, enforced.

## 10. Unindexable values (`docs/09` §7.2 — normative for this adapter)

As `docs/12` §10, with Hibernate's shapes:

| `onUnindexable` | Write | Finder |
|---|---|---|
| `REFUSE` (default) | The listener raises `FieldsealUnindexableException` before the statement is bound, naming the attribute, the character and its position in code points (from `Fieldseal.firstUnassigned`), with the message shape of `docs/12` §10.2. It propagates out of the flush like any exception there | A lookup for such a value raises the same exception; it never returns an empty list |
| `BUCKET` | The core returns the column's reserved marker; the row is written | The core derives the same marker; re-verification narrows |

`BUCKET` requires `unindexableOverride` with a reason, an approver and a date, refused at startup through the core's declaration validation (FS-H003) if absent. Its cost is `docs/12` §10.4's, and the README states it.
