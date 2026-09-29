# fieldseal-hibernate

Transparent field-level encryption for Hibernate ORM 7.4, over the Fieldseal Java core (`core/java`). Pre-alpha: nothing here is frozen, released as stable, or offered for production use (PRD §8, Gate 0b). The design, and the reasons behind every rule below, are in [`docs/29-adapter-hibernate.md`](../../docs/29-adapter-hibernate.md).

**Conformance (spec §10):** L1 ✅ · L2 (a) ✅, re-verified · L3 ✅ (the session's tenant identifier) · L3-row ❌ not built · L4 ❌ (Hibernate cannot await in the value path). The adapter contains no cryptographic code (spec §11.3); every operation is the core's.

## Declaring columns

```java
@Entity
@FieldsealTable("018f3c2e-7a1b-7c3d-8e4f-000000000001")
public class Patient {
    @Id UUID id;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000002")
    String email;

    @BlindIndex(source = "email", idf = Idf.HMAC_SHA512, normalize = Normalizer.NFC_CASEFOLD_V1,
                truncateBits = 15, projectedPopulation = 100_000)
    byte[] emailIndex;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000003", tenantBound = true)
    String note;
}
```

- **The UUIDs are literals, and they never change.** They identify the table and the column inside every envelope, so renaming the entity or the column changes nothing. Generate them once (`uuidgen`) and paste them in.
- **The Java type decides the plaintext encoding** (spec §3.6): `String`, `byte[]`, `long`/`int`/`short` and their boxes, `BigInteger`, `BigDecimal`, `double`, `boolean`, `LocalDate`, `Instant` and `OffsetDateTime`. Anything else is refused when the session factory starts. A `BigDecimal` is stored canonically (`1.50` reads back as `1.5`); an `OffsetDateTime` reads back at UTC; an `Instant` with a digit below the microsecond is refused, never truncated.
- **Columns are `VARBINARY`** (`bytea` on Postgres), 32,600 bytes by default. An envelope adds about a hundred bytes to the value; `@Column(length = …)` sets another size.
- **A blind index is its own `byte[]` attribute**, which the adapter writes. Do not assign it: the adapter restores it on the next flush.

## Configuring the session factory

```java
Map<String, Object> settings = new HashMap<>();
FieldsealSettings.apply(settings, (FieldsealConfigurer) b -> b
        .keyProvider(keys)                     // from dev.fieldseal.core.KeyProviders
        .allowedSuites(Set.of(0xFF01))
        .writeSuite(0xFF01)
        .readMode(ReadMode.STRICT)
        .armProvisionalSuites(true));          // spec §4.8: 0xFF01 is provisional
```

`FieldsealSettings.apply` sets two things: the client configuration (`dev.fieldseal.hibernate.client`), and this adapter's query translator (`hibernate.query.sqm.translator`), which the adapter's query refusals need. The adapter builds the client itself, with every index your entities declare, so that the core checks each declaration's truncation and cardinality when the session factory starts. A prebuilt `Fieldseal` is accepted instead, if its indexes match the declared ones exactly.

**Warm the key cache before the first request** under an envelope key provider: nothing in a flush may call the KMS (spec §11.2). `FieldsealHibernate.warm(sessionFactory, tenants)` warms every declared column and index, and lists the tenant-bound ones it skipped because you named no tenants.

## Finding rows by an encrypted value

```java
List<Patient> hits = FieldsealQueries.of(session, Patient.class)
        .whereIndex("emailIndex", "Ada@Example.com")   // matches ada@example.com
        .where("status", "active")
        .list();
```

A blind index is a filter, not an answer: it deliberately matches some rows whose value is different (spec §7.4). The finder decrypts what the index returns and drops those rows, so what `list()`, `count()`, `first()` and `exists()` return is exact. `whereIndexIn` matches any of several values. `.candidates()` returns the unfiltered match set, if you will filter it yourself.

**HQL and Criteria cannot compare an encrypted column, and are refused if they try.** Every envelope is randomized, so `where p.email = :e` would match nothing. `is null`, `is not null`, a plain `count(p.email)` and `select p.email` are served.

## Coverage matrix

Every row cites the tests that prove it. `scripts/coverage_report.py` reads this table and the JUnit results, and fails if a cited test is missing or not green.

| Path | Behaviour | Test |
|---|---|---|
| `persist`, flush of a changed entity | ✅ encrypts; index derived from the same bytes | `ValuePathTest.theColumnHoldsAnEnvelopeOverTheCanonicalRendering`, `ValuePathTest.theIndexSiblingIsTheCoresDerivation`, `ValuePathTest.aChangedSourceRederivesTheIndex` |
| every write, including an `UPDATE` of an unchanged value | ✅ a fresh envelope | `ValuePathTest.everyWriteIsAFreshEnvelope` |
| a second flush with nothing changed | ✅ no `UPDATE` | `HibernateBehaviourTest.persistThenFlushTwiceIssuesOneInsertAndNoUpdate`, `HibernateBehaviourTest.loadThenFlushIssuesNoUpdate`, `HibernateBehaviourTest.aChangedValueIssuesOneUpdateAndThenNone` |
| `merge`, JDBC batching, `IDENTITY` keys | ✅ encrypts | `HibernateBehaviourTest.mergeOfADetachedEntityGoesThroughTheListener`, `HibernateBehaviourTest.batchedInsertsStayBatched`, `HibernateBehaviourTest.identityInsertSeals` |
| `StatelessSession.insert`, `update` | ✅ encrypts | `HibernateBehaviourTest.statelessInsertAndUpdateGoThroughTheListener` |
| `find`, entity queries, projections | ✅ decrypts | `ValuePathTest.everySupportedTypeRoundTrips`, `ValuePathTest.aProjectionDecrypts` |
| `NULL`, and the empty string | ✅ `NULL` stays `NULL` in both columns; `""` is a value | `ValuePathTest.nullIsNullAndTheEmptyStringIsAValue` |
| an assignment to an index attribute | ✅ undone on flush | `ValuePathTest.anAssignedSiblingIsRestored` |
| a value spec §3.6 does not admit | 🛑 refused | `ValuePathTest.aNanosecondInstantIsRefusedNotTruncated`, `ValuePathTest.anUnpairedSurrogateIsRefused`, `CodecVectorsTest.codec` |
| a tenant-bound column | ✅ bound to the session's tenant identifier; 🛑 refused with none, or with one that is not a `String` or `byte[]` | `ValuePathTest.aTenantBoundColumnBindsTheSessionsTenant`, `ValuePathTest.aTenantBoundColumnWithNoTenantFailsClosedOnWrite`, `ValuePathTest.aTenantBoundColumnWithNoTenantFailsClosedOnRead`, `ValuePathTest.aTenantBoundColumnReadUnderAnotherTenantIsRefused`, `ValuePathTest.aTenantThatIsNotAStringOrBytesIsRefused` |
| `FieldsealQueries…list/count/first/exists` | ✅ exact: collisions dropped | `FinderTest.aCollidingRowIsDroppedByVerification`, `FinderTest.countFirstAndExistsAreVerified`, `FinderTest.anOrdinaryEqualityIsAndedInSql`, `FinderTest.theNormalizerDecidesEquality`, `FinderTest.aStatelessSessionCanUseTheFinder`, `FinderTest.aTenantBoundIndexIsDerivedUnderTheSessionsTenant` |
| `whereIndexIn` | ✅ membership, verified per value | `FinderTest.membershipIsVerifiedPerValue` |
| `.candidates()` | ⚠️ the unfiltered match set, by request | `FinderTest.candidatesReturnTheBucket` |
| a value the index cannot fingerprint | 🛑 refused on write and on lookup (`REFUSE`); ✅ stored and found (`BUCKET`) | `FinderTest.refuseRaisesOnWriteNamingTheCharacter`, `FinderTest.refuseRaisesOnLookupRatherThanReturningNothing`, `FinderTest.bucketStoresTheMarkerAndVerificationNarrows` |
| HQL/Criteria comparison of an encrypted attribute, parameter or literal | 🛑 refused | `QueryRefusalTest.aParameterOnAnEncryptedColumnIsRefused`, `QueryRefusalTest.encryptedAttributeShapesAreRefused`, `QueryRefusalTest.aCriteriaPredicateOnAnEncryptedAttributeIsRefused`, `BindingGuardTest.aPlainValueIsRefusedAndNothingIsBound` |
| ordering, grouping, `distinct`, functions and aggregates over an encrypted attribute | 🛑 refused | `QueryRefusalTest.encryptedAttributeShapesAreRefused`, `QueryRefusalTest.aCriteriaOrderingOnAnEncryptedAttributeIsRefused`, `QueryRefusalTest.hibernatesOwnTypingRefusesStringFunctionsOverTheColumn` |
| `is [not] null`, plain `count(x)`, `select x` | ✅ served, exactly | `QueryRefusalTest.servedShapesAreServed`, `QueryRefusalTest.countOverAnEncryptedColumnIsExact` |
| HQL/Criteria predicate on an index attribute | 🛑 refused outside the finder, and under negation anywhere | `QueryRefusalTest.indexAttributeShapesAreRefusedOutsideTheFinder`, `QueryRefusalTest.aCriteriaPredicateOnAnIndexIsRefused`, `QueryRefusalTest.negationAndNonEqualityAreRefusedEvenInScope`, `FinderTest.theScopeDoesNotOutliveTheFindersQuery` |
| HQL/Criteria `update`, `insert`, `delete` touching an encrypted or index attribute | 🛑 refused | `QueryRefusalTest.mutationShapesAreRefused`, `QueryRefusalTest.anUpdateWithAParameterIsRefused`, `QueryRefusalTest.anInsertIsRefused` |
| HQL/Criteria mutations of plain columns | ✅ served | `QueryRefusalTest.aMutationOnPlainColumnsIsServed` |
| native SQL, `@SQLRestriction`, `@Formula`, custom SQL | 🛑 **cannot be intercepted**: parameters are never encrypted, and a comparison silently matches nothing. Use the ORM paths above, or call the core yourself | `QueryRefusalTest.aNativeQueryParameterIsNotIntercepted` |
| second-level cache | 🛑 an entity with an encrypted attribute cannot be cacheable (FS-H006) | `StartupChecksTest.fsH006` |
| the persistence context (first-level cache) | ⚠️ holds decrypted entities for the session's life (spec §10.2) | `HibernateBehaviourTest.persistThenFlushTwiceIssuesOneInsertAndNoUpdate` |
| `FieldsealHibernate.warm` | ✅ warms every declared column and index; names the tenant-bound ones it skipped for want of a tenant | `WarmTest` |
| mappings the adapter refuses at startup | 🛑 FS-H001 to FS-H009 (docs/29 §5) | `StartupChecksTest` |
| rows another language can read | ✅ the cross job: every core decrypts and re-derives what this adapter wrote | `CrossProduceTest` |
| row-id binding (L3-row) | ❌ not built (docs/29 §4) | — |

## Unindexable values

A value containing a character the pinned Unicode tables (17.0.0) do not define can be encrypted but not fingerprinted by `NFC_CASEFOLD_V1`. With `onUnindexable = REFUSE` (the default) the write fails with `FieldsealUnindexableException`, which names the character and its position so you can tell the user; it is a gap in the system's tables, not a fault in the value. With `onUnindexable = BUCKET` the row is stored under the column's reserved index value and is still found, at a cost: those rows are visible as one unusually frequent index value, and anyone who can write to the column can make that bucket, and so every lookup against it, larger. `BUCKET` requires `unindexableOverride` with a reason, an approver and a date. See `docs/12` §10 for choosing per column.

## Limits of this version

No row-id binding; no transparent query rewriting (you name the index); no `OR`, negation or pagination in the finder; no second-level caching of entities with encrypted attributes; no encrypted attributes in embeddables, element collections or inheritance hierarchies; no `@DynamicUpdate` on an entity with a blind index; no Hibernate Reactive or Envers. **Migrating an existing plaintext column** (`docs/15` §1) needs the backfill tool's `PROCEDURE.md`, which is not written yet; until it is, write rows through ordinary `merge` and flush in batches, which encrypts. An HQL bulk `update` is refused.

And the limits no adapter removes: the application process holds the keys, so a compromise of it is out of scope; storage grows by about a hundred bytes per value; and the key service is in the read path's availability (spec §2, §3.3, §5).

## Building and testing

JDK 21. The core is built from this checkout (`includeBuild("../../core/java")`), never a published one.

```
./gradlew build                                   # H2
FIELDSEAL_TEST_DB=postgres ./gradlew test         # Postgres at 127.0.0.1:5432 (PG* variables)
./gradlew -q crossProduce --args="--out cross-hibernate.json"
python scripts/coverage_report.py                 # after a test run: the docs/14 §4 report
python scripts/bite_checks.py                     # the mutation checks (not in CI; ~10 min)
```
