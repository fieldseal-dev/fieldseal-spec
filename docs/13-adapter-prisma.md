# Prisma Adapter Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the engineering design for `adapters/prisma` (package `@fieldseal/prisma`), targeting Prisma 7.x. Built on the analysis in `docs/04-orm-adapter-notes.md` §3; the single most important behavioral difference from the existing `prisma-field-encryption` library is the **mandatory throw list** (§4 below) — spec §10.2 requires throwing where that library silently mis-encrypts or drops.

**Conformance target (spec §10.1):** L0 ✅ · L1 ✅ · L2 (b) ⚠️ with mandatory throws · L3 partial (tenant via args/ALS) ⚠️ · L3-row ❌ · L4 ✅ (`$allOperations` is async — best-in-class KMS integration).

**Built as of 2026-08-27:** L0, L1 and L2(b). L2 is served at the two `where` sites §2.0 identifies and refused everywhere the database answers first, which is narrower than the Django adapter's L2 — §2.0 states why, and §6 does not claim parity. L4 and the cross-language producer are the next increment.

**Hard rule:** zero cryptography; only the core's published operations from `@fieldseal/core`. (Seven, not the five this line long claimed: `encrypt`, `decrypt`, `blindIndex`, `isCiphertext`, `rotate`, `unindexableMarker`, and the async `warm` — `unindexableMarker` is the one §9's `bucket` row needs.)

---

## 1. Declaration surface

Prisma has no schema extension point, so declaration is `///` doc comments, read by a **build-time generator** (see the DMMF bullet below — the runtime route this document originally specified does not exist in Prisma 7):

```prisma
generator fieldseal {
  provider = "fieldseal-prisma-generator"
  output   = "../src/generated"
}

/// @fieldseal(table_uuid: "018f3c2e-…")
model Patient {
  id        String @id @default(uuid())
  /// @fieldseal(encrypted, column_uuid: "018f3c2e-…")
  email     Bytes
  /// @fieldseal(index: "email", index_id: "exact", idf: "argon2id",
  ///            normalize: "nfc-casefold-v1", truncate_bits: 15, projected_population: 100000)
  emailBidx Bytes?

  @@index([emailBidx])
}
```

The sibling is `Bytes?` and the model-level annotation sits *above* `model`, which is
where Prisma's parser attaches model documentation.

- **Column type:** `Bytes` (→ `bytea`) is the default and recommendation (spec §3.3). `String` columns with base64 are supported for migration compatibility with `prisma-field-encryption` deployments, gated behind an explicit `storage: "base64"` annotation and the documented 33% overhead warning. This choice covers the *envelope* column only: the blind-index sibling is governed by spec §7.11, where `Bytes` of length exactly `⌈b/8⌉` is a MUST and base64 is not among the alternatives — an index column may be raw bytes or lowercase hex, nothing else, because its bytes are compared rather than round-tripped.
- **Declarations reach the adapter through a build-time generator, not at runtime.** This paragraph previously described reading the `///` comments "from the DMMF at runtime", with a `dmmf` constructor option as the fallback. **That is not possible in Prisma 7** — measured against 7.10.0 on 2026-08-27, and the flag is resolved as *corrected*, not confirmed:
  - `Prisma.dmmf` no longer exists. The generated namespace exports `DMMF` as a **type** only, so the previous design would have read `undefined` without failing.
  - The client's private `_runtimeDataModel` carries the model and relation graph — `{name, kind, type, relationName}` — and **no `documentation` field** on any model or field. The annotations are simply not in it.
  - They survive at runtime only inside `_engineConfig.inlineSchema`, the raw schema text, which is equally private.

  So the two things this adapter needs live in two different places, and neither has a public route. The declarations are therefore read where they *are* available and the route is supported: the package ships a **Prisma generator** (`fieldseal-prisma-generator`), which Prisma spawns at `prisma generate` and hands the full DMMF — documentation *and* relation graph, from Prisma's own parser. It emits one frozen field map that the extension imports.

  Two consequences, both improvements on the original design. A malformed declaration fails **`prisma generate`** rather than the first request, which is the Prisma analogue of Django's startup system checks and is what "never a runtime skip" was reaching for. And the declarations arrive together with the relation graph §2.1's visitor walks, from one source rather than two. An explicit `fieldMap` option remains the escape hatch the `dmmf` option used to be.

- **Prisma 7 removed `url` from the schema's `datasource` block.** Connection configuration moves to `prisma.config.ts`, and the client takes a **driver adapter** in its constructor. Every schema example in this document and in `docs/04` §3 predates that change.

- **A multi-line `///` declaration arrives as one string with embedded newlines**, the `/// ` prefix stripped, so the annotation grammar must handle continuation lines — the example above already spans three.

- **Logical type (`as:`).** The Prisma column type is the **storage** type — `Bytes` because it holds an envelope — so it cannot also declare what the value *is*. Django never needed this: `Encrypted(models.EmailField())` composes an inner field carrying the logical type, and Prisma has no equivalent. Each encrypted column therefore declares `as: "string" | "bytes" | "int" | "float" | "boolean" | "datetime"`, defaulting to `string`. `docs/14` §3 already names this as the adapter decision no core test can see ("an `IntegerField` is not self-evidently `b"42"`"), which is why the cross-language producer must exercise every declared type rather than only text.

- **The index sibling MUST be declared optional** (`emailBidx Bytes?`). Prisma's generated `create` input requires every non-optional column, so a required sibling would force callers to supply the one value the adapter refuses to accept from them — index bytes are derived. A NULL value also has no index, so the column must accept NULL regardless. The generator refuses a required sibling.
- The index sibling is a plain (non-unique) `@@index` column: `truncate_bits` must sit inside the §7.4 band (9–15 bits for P = 100,000), which **mandates collisions** — a `@unique` sibling would reject legitimate distinct emails, which spec §7.10 now forbids outright (G12 resolved 2026-08-09), and the index is a filter, never an answer (spec §7.5).
- Annotation parsing happens once at **`prisma generate`**, producing a frozen per-model **field map**: `{ model → { encrypted, indexes, relations, tableUuid } }`, emitted as a committed module the extension imports. **Every model in the schema is emitted, declared or not** — an undeclared model still carries the relation edges the visitor walks (a write can reach an encrypted column *through* it), and a model absent from the map is refused at runtime as staleness rather than passed through, because an unmapped model is a bypass around the pipeline for every declared model it relates to. A malformed annotation fails the generate, never a runtime skip — strictly better than the construction-time error this originally specified, because a schema that cannot be declared correctly never produces a client. The parsed declarations feed core-client construction (§2), where the §7.6 cardinality gate applies: a declared index whose `projected_population` is below 2¹⁰ fails construction unless the extension options carry the explicit, logged `cardinalityOverride` declaration spec §7.6 requires — the override lives in code reviewed by humans, never in a schema comment.

## 2. Extension architecture

One Prisma Client Extension with a single **top-level** `query.$allOperations` component (the only component that can touch writes and filters — `docs/04` §3).

**Top-level, not under `$allModels`** — measured against Prisma 7.10.0 on 2026-08-27, and it is the difference between seeing raw operations and not. `query.$allModels.$allOperations` wraps model operations only; `$queryRaw` and `$executeRaw` are client-level and never reach it, so pipeline step 1 below is unreachable from there and `strictRaw` would silently do nothing:

```ts
export function fieldsealExtension(opts: {
  keyProvider: KeyProvider;        // the extension CONSTRUCTS the core client itself (mirrors the
  readMode?: ReadMode;             // Django adapter, docs/12 §7): only the extension sees the parsed
  allowedSuites: number[];         // schema annotations, so only it can hand the core the complete
  writeSuite: number;              // IndexDeclaration registry that construction-time validation
  cache?: CachePolicy;             // forwarded to EnvelopeKeyProvider, never to the client:
                                   // `docs/09` §2 refuses a `cache` key on Fieldseal itself
  cardinalityOverride?: { table: string; field: string; reason: string;
                          approvedBy: string; date: string }[];   // spec §7.6 logged override
  fieldMap: FieldMap;              // the generator's output; replaces the `dmmf` option,
                                   // which had nothing to read in Prisma 7
  tenant?: (args, model, operation) => Uint8Array | null;   // or AsyncLocalStorage accessor
  strictRaw?: boolean;             // default false: raw ops pass through with a warning hook
}): PrismaExtension
```

There is no `client` option: a pre-built core client cannot contain declarations parsed from the schema, and a split registry (some indexes in the client, some in the extension) is a configuration drift with no way to notice it. **This decision is unchanged by G18 but its justification is narrower than it was.** It previously read as though verifying a supplied client were impossible; it is not, as of `docs/09` §2's *Configuration reflection* clause — `Fieldseal.indexes` reports the validated registry and the Django adapter's E006 now checks exactly that. Removing the option here remains the right call for a different reason: this extension always parses the schema, so a supplied client would be a second source for declarations that already have one, and no deployment need is served by it. That is a design choice, not a constraint. Worth recording that until 2026-08-26 it *was* a constraint in this language and not merely in this adapter: the TypeScript core's configuration lives behind a `#`-private field on a frozen instance, so an extension had no way to read a supplied client's registry well or badly, while the Python adapter could at least have reached into `_indexes`.

Pipeline per operation:

```
1. model === undefined (raw ops)  → passthrough (+ warning hook) or throw if strictRaw
2. look up field map; nothing encrypted on this model → passthrough
3. ANALYSE pass: walk args once — refuse the forbidden shapes (§4) and plan the
   rewrites. One walk, so a refusal and a rewrite can never disagree about what
   a `where` site is.
4. WRITE pass: walk data/create/update/upsert trees, encrypt declared fields,
   derive + set sibling index fields
5. WHERE pass: rewrite equality/in predicates on encrypted fields onto sibling
   index fields (blind_index of the plaintext parameter), recording one §7.5
   obligation per rewrite
6. await query(args)              // async — KMS warm-up can await here (L4)
7. READ pass: decrypt declared fields in the result tree (recursively, since
   include nests relations)
8. RE-VERIFY pass: discharge the obligations — decrypt-and-compare and drop
   collision rows (spec §7.5 — the index is a filter, never an answer)
```

### 2.0 Which `where` sites step 8 can reach (measured, 2026-08-27)

Steps 5 and 8 are one feature, and the question that decides its scope is the
Django LIMIT audit's (`docs/07` §7) asked of Prisma: **who answers this query
before §7.5 runs?** Measured against 7.10.0 (local audit
`internal/prisma-l2-audit-2026-08-27.md`, **not in the repo** — `internal/` is
gitignored; the durable evidence is the test suite, which pins every number
cited here in `tests/prisma-private-api.test.ts`, `tests/l2.test.ts` and
`tests/l2-refusals.test.ts`): exactly **two** `where` sites in
Prisma's surface select rows that come back to the extension:

1. the top-level `where` of **`findMany`**, and
2. a relation `where` under **`include`/`select`**, whose matched rows arrive
   nested inside their parents (at any depth; a to-one hop may sit in the path
   even though a to-one's own `where` is not a filter).

Everywhere else the database computes the answer and only the answer comes back:
`count` → a number, `aggregate` → an object, `groupBy` → groups, `updateMany` /
`deleteMany` → a count, `update` / `delete` / `upsert` → the row they chose,
relation filters → the *parent* rows, `_count` → a number. Spec §10.2 settles
all of them in one clause: an adapter that cannot guarantee the rewrite, *"or a
filter path its interception surface does not reach"*, MUST reject.

**The `findFirst` LIMIT hazard (pinned, 2026-08-27; resolved as *refuse*).**
`findFirst` reaches the extension carrying **only `where`** — Prisma applies the
`LIMIT 1` *below* the extension, invisibly in `args`. So an index-rewritten
`findFirst` has the database return **one candidate** before the §7.5 re-verify
pass can run: a §7.4 collision comes back as a wrong row, and a true match that
sorted behind it comes back as `null`. This paragraph previously said the
adapter MUST rewrite it "as an over-fetch (`findMany` + verify + first) or
refuse". **The over-fetch is not available**, measured the same day:

```
prisma.patient.findFirst({ where: …, take: 3 })
→ Input error. The 'findFirst' operation cannot be used with a 'take'
  argument that isn't 1 or -1
```

and an extension cannot turn one operation into another — `query` is bound to
the operation it was invoked for, and a `query` component has no client handle.
So `findFirst`/`findFirstOrThrow` over a rewritten predicate is **refused**, and
the refusal names `findMany` as the shape to run instead. Both halves are pinned
in `tests/prisma-private-api.test.ts`.

**Consequence for the coverage claim, stated plainly:** this adapter's L2 is
narrower than the Django adapter's. Django serves `count()`, `exists()`, `get()`
and `first()` by materializing the bucket inside its own `QuerySet`; a Prisma
extension cannot, so those are refusals here. The matrix in §6 says so rather
than implying parity.

**The hazards that travel with a rewritten filter.** `take`, `skip`, `cursor`
and `distinct` are applied by the database to the candidate set *before* §7.5
shrinks it, so each is refused at the level carrying the obligation — and only
at that level: a `take` on the parent of a *nested* obligation is served,
because dropping child rows cannot change which parents matched. `distinct` is
measured rather than assumed: `findMany({ distinct: ["plainName"] })` over four
rows returned three, so the dedup had already run and the row it discarded
cannot be recovered by dropping the one it kept.

**An encrypted term under `OR` or `NOT`** is refused for the Django reason: a
returned row may be present because the *other* branch matched, so a failed
check is not a sound reason to drop it, and deciding correctly would mean
evaluating the whole predicate in application code. `AND` is fine — every
returned row satisfies every term.

**§7.5 needs the column it verifies against**, and three things take it away: a
`select` that does not name it, a query-level `omit`, and a **client-level**
`omit` passed to `new PrismaClient({ omit: … })`. The third is invisible in
`args` (measured: the operation arrives as a bare `{ where }` and the row simply
comes back without the key), so the check runs on the **returned row** rather
than on the arguments — that catches all three and fails closed on the one that
cannot be predicted.

### 2.2 The §7.5 opt-out: `candidateScope(fn)`

Django's escape hatch is a queryset method (`docs/12` §3.2, decision C). Prisma
has nothing to chain — an operation is one call with a plain arguments object —
so the scope is a callback, in the same shape and for the same reason as
`tenantScope`: an `AsyncLocalStorage` survives `await`.

```ts
const approximate = await candidateScope(() =>
  prisma.patient.count({ where: { email: v } }),
);
```

Inside it nothing is recorded, step 8 does not run, and every shape §2.0 refuses
is served over the §7.4 bucket. Django's rule on what an escape hatch lifts
holds here: it hands over the *verification* family, **not** the G20 family,
because bucket semantics are a meaningful thing for a caller to accept and
ciphertext order has no semantics to accept.

Three decisions worth recording:

- **It lifts mutations too** — `deleteMany` inside the scope deletes the whole
  bucket. That is parity with Django, whose `.candidates().delete()` does the
  same today; refusing here would be a silent divergence between two shipped
  adapters, which is the failure G23 was filed about. The consequence is
  measured in the test suite and stated in the README, not softened.
- **It does not lift `not`/`notIn`.** Django's `.candidates()` does lift its
  `exclude()` analogue, and the difference is deliberate: there the rewrite
  happens in the field layer whether the queryset verifies or not, so lifting it
  costs nothing, while here the rewrite is the adapter's own and spec §7.10 has
  a row for membership and none for negated membership. Serving it inside the
  scope would be deciding **G21 ([#87](https://github.com/fieldseal-dev/fieldseal-spec/issues/87))** by engineering judgment.
- **It must await inside the scope.** A Prisma client method returns a lazy
  promise that dispatches nothing until something calls `.then`, so a
  synchronous `storage.run(true, fn)` would exit the scope before the query ran
  and re-verify anyway — an opt-out that silently does nothing, which is worse
  than not having one. Found by the first draft doing exactly that; the
  "measures why" tests fail if it regresses.

### 2.1 The args-tree visitor — typed, not string-surgery

`docs/04` §3 calls the existing library's JSON-path approach "the correctness cliff." This adapter's visitor is **schema-driven**: it walks the args tree *guided by the DMMF model graph* (which relation fields exist, which scalars are encrypted), so nested `create`/`connectOrCreate`/`upsert`/nested `update` under relation keys are visited by construction rather than by path-pattern luck. Every leaf it cannot classify against the schema is a **hard error**, not a passthrough — unknown arg shapes fail closed.

Write-tree coverage (each an explicit visitor case + test): `create.data`, `createMany.data[]`, `update.data`, `updateMany.data`, `upsert.create/update`, nested relation writes (`data.<rel>.create|createMany|update|upsert|connectOrCreate.create`), and `set`/`unset` forms on supported field types.

Where-tree coverage: `where.<field>` shorthand equality, `where.<field>.equals`, `.not` (scalar form), `AND`/`OR`/`NOT` arrays recursively, relation filters (`some`/`every`/`none`/`is`/`isNot` — **and the unwrapped to-one form**, where the target's where sits directly under the relation key) recursively, **the filters nested relation writes carry** (`update`/`updateMany`/`upsert`/`connectOrCreate` `where`, `deleteMany`'s payload, and the `connect`/`disconnect`/`delete`/`set` unique inputs — walked exactly as the top-level where is, because the write pass encrypts their payloads and must never touch their filters), `cursor.<field>` (rejected — cursor on randomized ciphertext is meaningless; see §4), and `findUnique.where` naming an encrypted or index field (rejected — Prisma requires a unique column there, and neither randomized ciphertext nor a collision-mandated truncated index can be unique, which §7.10 now states normatively per G12; the shape to run instead is `findMany` with equality + re-verify, and take the first row).

**Walked is not the same as rewritten, and this list previously conflated them.** Every shape above is *visited*; §2.0 decides which of them can be *served*. The two the earlier draft got wrong:

- **Relation filters are not rewritten** (`some`/`every`/`none`/`is`/`isNot` and the unwrapped to-one form). The rewrite would land in a join or subquery the database resolves, and only the *parent* rows come back — §7.5 re-verification needs the encrypted column's decrypted value, which lives on the other model. They are refused, with the join to run instead named in the message: query the owning model directly (keeping the column in the projection, or there is nothing to verify against) and filter by the resulting ids. Django refused the same analogue for the same reason (`docs/12`, `_refuse_traversal`), and spec §10.2 requires it rather than permitting it — *"a filter path its interception surface does not reach"* MUST be rejected. This closes the open item the plan carried as "the relation-filter case still needs deciding": it is settled by §10.2's existing text, not by a new spec decision, so no gap issue was filed.
- **`.not` is not rewritten either**, and neither is `notIn` — see the §4 table and **G21 ([#87](https://github.com/fieldseal-dev/fieldseal-spec/issues/87))**, now closed in favour of the refusal this adapter already shipped, with spec §7.10 and §10.2 stating the rule generally. **Whether `candidateScope()` may lift it is a separate open question, G24 [#100](https://github.com/fieldseal-dev/fieldseal-spec/issues/100)** — this adapter says no and Django's `.candidates()` says yes, which G21's closure surfaced and deliberately did not settle. The exclusion drops rows §7.5 never sees, and a filter's false positives are recoverable where an exclusion's false negatives are not.

## 3. Read path

Decryption happens on the awaited result (step 7), not via `result.compute` — computed fields cannot be used in `where`/`orderBy` and cannot replace stored values (`docs/04` §3). The visitor mirrors `include` nesting using the DMMF relation graph. Because `select`/`include` cannot be mutated by extensions (`docs/04` §3, Prisma docs verbatim), there is no hidden-column problem for values (ciphertext lives in the field's own column), but **sibling index columns appear in results**: the read pass strips `*Bidx` fields from returned objects unless `exposeIndexColumns: true`, so application code never accidentally depends on index bytes.

**Re-verification compares under spec §7.5's rule (G19 [#78](https://github.com/fieldseal-dev/fieldseal-spec/issues/78), resolved 2026-08-26):** `normalize(stored)` against `normalize(queried)` under the index's declared normalizer, on the normalizer's output bytes — using the core's public `normalize`, never a reimplementation. The extension MUST document the consequence §7.5 states: on a non-`identity` column an equality filter is equality under that normalizer (a query for `ada@example.com` can return `Ada@Example.com`), and no second, differently-folded equality may be offered — which is the reason `mode: "insensitive"` is on the §4 rejection list rather than being mapped onto the index.

Read modes: core modes apply as-is; `permissive` fires the extension's `onPlaintextRead` hook with model/field (never the value) per spec §10.3.

## 4. The mandatory throw list (spec §10.2 — normative for this adapter)

Rationale per case is the verified failure mode in `docs/04` §3: un-rewritten filter shapes get the *value encrypted instead*, silently returning zero rows. The rule: **nothing on this list may silently degrade, and nothing may be downgraded to a warning.** Two rows have an explicitly specified alternative to throwing — `in:` upgrades to an index rewrite when an index is declared, which spec §10.2 explicitly permits as of G13 (see the note below the table; the permission is `in:` only, never `notIn:` — G21), and raw ops (whose SQL the extension cannot inspect) default to passthrough + warning hook with `strictRaw` opting into the throw. Every other row throws `FieldsealNotSupported` unconditionally, with the field name, the shape, and the honest fallback from spec §7.10.

| Shape on an encrypted field | Why |
|---|---|
| `in:` with **no declared index** | Not rewritable — throw. With a declared index this upgrades to a rewrite (below) |
| `notIn:`, and the scalar `.not`, **with or without a declared index** | Unconditional throw. This row read `in:`/`notIn:` together until G21 [#87](https://github.com/fieldseal-dev/fieldseal-spec/issues/87) closed: spec §7.10 has no row for negated membership and §10.2's permission is scoped to `in:`, so this document was extending a permission the specification never granted, on a citation that did not cover it. The adapter shipped the refusal from the start — the table was the thing that was wrong |
| `contains:`, `startsWith:`, `endsWith:`, `search:` | No substring/prefix over ciphertext (spec §7.1; prefix only via a declared §7.9 index, out of v0 scope) |
| `lt/lte/gt/gte:` | No order over ciphertext (spec §4.7) |
| `mode: "insensitive"` | Case folding is the normalizer's job, not the query's |
| `orderBy` naming an encrypted field | The existing library deletes it with a `console.error` — this adapter throws (spec §10.2 named this case for Prisma from the start; G20 ([#80](https://github.com/fieldseal-dev/fieldseal-spec/issues/80)) generalized it to every ORM, alongside grouping, `DISTINCT` and aggregates over ciphertext — the extension's visitor must refuse those shapes too) |
| `distinct`, `groupBy.by`, `having` on an encrypted field | Grouping by randomized ciphertext is meaningless (index-column grouping with the §7.10 collision caveat is the documented alternative) |
| `aggregate` (`_min`/`_max`/`_sum`/`_avg`) on an encrypted field | Spec §7.10 — the shapes that read envelope bytes. Plain `_count: { field: true }` is deliberately **not** here: it reads null-ness alone and is served, exact under §10.2's NULL-preservation invariant (G23, [#89](https://github.com/fieldseal-dev/fieldseal-spec/issues/89)) |
| `cursor` on an encrypted field | Pagination on ciphertext is incorrect (spec §7.5) |
| Raw ops (`$queryRaw`, `$executeRaw`) when `strictRaw: true` | Parameters are never encrypted by any ORM (spec §10.2); default is passthrough + warning hook, strict deployments opt into throwing |
| `findUnique` naming an encrypted or index field | Neither can be unique (spec §7.10, G12); the shape to run is `findMany` + equality + re-verify, and take the first row. Structural, so `candidateScope` does not lift it |
| `where.<encrypted>` with **no declared index** | Equality without an index cannot be served (randomized suite) — throw with "declare a blind index or filter after fetch". Not lifted by `candidateScope`: there is nothing to rewrite onto |

**The L2 rows — refused because the answer is computed before §7.5 can run** (§2.0 has the measurements; all of these are lifted by `candidateScope`, which is what it is for):

| Shape carrying a rewritten equality | Why |
|---|---|
| `findFirst` / `findFirstOrThrow` | The `LIMIT 1` is applied below the extension and cannot be widened (`take` must be 1 or -1) — the database returns one candidate |
| `count`, `aggregate`, `groupBy` | Answered over the §7.4 bucket; an extension cannot turn them into a row fetch. Measured: 2 where the verified answer is 1 |
| `updateMany`, `deleteMany`, `update`, `delete`, `upsert` | The statement acts on rows that never come back. Measured: `deleteMany` removed 2 of 2, one of them holding a different value |
| `take` / `skip` / `cursor` / `distinct` **at the level carrying the obligation** | Applied to the candidate set before §7.5 shrinks it. A `take` on the *parent* of a nested obligation is served |
| An encrypted term under `OR` / `NOT` | A returned row may be there because the other branch matched; §7.5 cannot attribute it |
| Relation filters (`some`/`every`/`none`/`is`/`isNot`, unwrapped to-one) | Resolved as a join or subquery; only the parent rows come back (§2.1) |
| `_count` whose relation filter names an encrypted field | Computed in the database |
| A projection that drops the column being verified (`select`, query `omit`, client-level `omit`) | §7.5 has nothing to compare. Checked on the **result**, because the client-level form never appears in `args` |

`in:` with a declared index is rewritten to `emailBidx: { in: [bidx(v1), bidx(v2), …] }` — membership is exactly what spec §7.10 supports ("N indexes OR'd"), and it is the one shape the existing library breaks on that this adapter upgrades rather than merely rejects. **Conflict resolved (G13, issue #13, 2026-08-09):** §10.2's Prisma bullet now scopes its MUST — reject `in:` *unless* the adapter rewrites it to the declared blind index with §7.5 re-verification, and reject whenever the rewrite cannot be guaranteed (no declared index, or a filter path the interception surface does not reach). This adapter's rewrite is conformant to §10.2's letter as of that change, so the coverage matrix no longer carries it as a deviation. `contains:`/`startsWith:` stay unconditional rejections, and §10.2 now says explicitly that a §7.9 prefix index is queried through its own declared predicate rather than by rewriting `startsWith:` — do not add that rewrite here.

## 4.1 Declaration checks (the Django §5 analogue)

`docs/12` §5 gives Django a table of `Exxx`/`Wxxx` system checks that run at startup.
Prisma has no check framework, and this adapter answers the same need **one step
earlier**, at `prisma generate`, where a schema that cannot be declared correctly never
produces a client at all. Every problem in a schema is reported in one run, not the first
one found.

Deliberately **no `Exxx` identifiers.** Those are `django.core.checks` message ids, not
exception codes, and Django's own *runtime* refusals carry none either. Identity here is
the message, which must name the site (`Model.field`), the rule, and the fix.

| Refused at `prisma generate` | Why |
|---|---|
| No `table_uuid` on a model with an encrypted column | Spec §6.1 binds key derivation to the surrogate; it MUST NOT be derived from a name, because a rename would make every existing row undecryptable |
| Missing or malformed `column_uuid` | Same |
| An index naming a column that is not encrypted on the same model | An index sibling with no source indexes nothing |
| **Two index siblings over one column** | Spec §7.5 (G19): a column has exactly one equality, under its declared normalizer, and an adapter MUST NOT offer a second beside it |
| A **required** index sibling | Prisma's generated `create` input would force callers to supply a derived value the adapter refuses to accept from them |
| An index sibling that is not `Bytes` | Spec §7.11 — index bytes are compared, not round-tripped; base64 is not among the permitted representations |
| A `String` value column without `storage: "base64"`, or `base64` on a `Bytes` column | Raw envelope bytes are not text; base64 on `Bytes` pays the 33% overhead for nothing |
| An unknown `normalize`, `idf`, `as` or `on_unindexable` | The identifier **is** the definition: an implementation that does not know it cannot derive the same value |
| A half-specified Argon2 cost | A cost given in one dimension is not a cost |
| An unterminated or malformed `@fieldseal(...)` | Ignoring it would leave the column unencrypted with nothing raised |
| `@unique`/`@id` on an encrypted column or sibling, or membership in `@@unique`/`@@id` | Spec §7.10: a randomized envelope makes the constraint never fire; a §7.4-collision-mandated sibling makes it fire on legitimate distinct values — delayed data loss |

The gates that are **not** here are the ones that belong to the core and run at client
construction against the assembled registry: the §7.4 truncation band, the §7.6
cardinality gate, the Argon2id minima, and the §7.2 bucket ceremony. A second copy of a
gate is a copy that can disagree with the one that matters, and `docs/07` §7 records what
that costs — the Python core had drifted to enforcing *none* of its declaration-time
gates while `docs/10` §4 specified all of them, unnoticed because the adapter looked like
it was checking.

## 5. Tenant context and L4

- Tenant bytes come from either the `tenant` callback (inspecting args — e.g., a `tenantId` scalar present in the write) or an `AsyncLocalStorage` accessor set by request middleware. Both are documented side channels (spec §10 L3 ⚠️ for Prisma). Fail-closed rule as in the Django adapter: tenant-bound columns with no resolvable tenant throw, never silently encrypt tenantless.
- **L4 — built, 2026-08-31.** Because `$allOperations` is async and runs before a connection is acquired (`docs/04` §3), the adapter catches `KEY_UNAVAILABLE`, `await`s `client.warm(...)` for the contexts the operation named, and runs the pass again — the one adapter in Phase 1 that can do KMS acquisition in-path without holding a pooled connection. This is the flagship demonstration of why the core separates `warm` from the sync value path, and three details of the build are worth recording because none of them was in this design:
  - **No pre-flight check, and no cache-membership probe.** The design said "on cache miss", which reads as though the adapter can ask. It cannot, and should not: a §5.5 cache can evict between a probe and the use, and `KeyProvider.encryptionKey` used as a probe would advance the §5.5 use counter for a key nobody used (`docs/09` §8.3) — a probe that corrupts the accounting it probes. The miss *is* the signal, so the shape is catch-warm-retry rather than check-then-act.
  - **Which contexts to warm is answered by the passes, not by a second walk.** `context.ts` is the only place a `FieldContext` is constructed, so it reports every one it builds into a per-operation ledger, and the ledger is the warm set. That is what makes the index-key sibling arrive too: spec §5.2 makes it a sibling of the tenant DEK rather than a child, so a warm derived from value contexts alone would leave every indexed lookup stalled.
  - **Retrying a pass requires the failed attempt to have left nothing behind**, and the visitors mutate in place. Every mutation is journalled and rolled back before a retry (`src/journal.ts`); without it the retry reads the envelope the first attempt wrote as if it were the caller's value and encrypts it twice. Measured while building it (Prisma 7.10.0, 2026-08-31): **Prisma hands the extension a copy of the caller's arguments**, so this atomicity is an internal invariant of the pipeline and *not* a caller-facing promise that a refused write leaves the caller's own object alone.
  - **Termination is by strict progress, accounted per pass:** a further warm cycle runs only if the next attempt needs a context no previous cycle warmed. A miss on a context that was just warmed is raised rather than retried — blocking a query on repeated KMS round trips is the availability failure spec §8.1 warns about. The write pass and the read pass each keep their own ledger, because a §5.5 cache can evict between them (the write pass's own derivations advance the use counter) and a warm that saved the write pass says nothing about the read side's misses; a ledger shared across the passes made the read-pass retry depend on where the write-pass miss happened to land, and raised `KEY_UNAVAILABLE` for a row the database had already committed.

## 6. Coverage matrix (AD-2 deliverable, README + generated from tests)

| Path | Behavior |
|---|---|
| `create`, `createMany`, `update`, `updateMany`, `upsert`, nested writes | ✅ encrypts + index siblings |
| **`findMany`** with rewritable equality/`in` on indexed fields | ✅ rewritten + re-verified (the `in:` rewrite is conformant to §10.2 as of G13; no deviation remains) |
| A relation `where` under `include`/`select` | ✅ rewritten + re-verified in the nested rows, at any depth |
| `findFirst` / `count` with the same predicate | 🛑 refused — the database answers before §7.5 runs, and an extension cannot turn one operation into another. This row said `findMany/findFirst/count` until the L2 build measured it (§2.0); the correction is a narrowing of the claim, not of the requirement |
| `candidateScope(fn)` | ⚠️ serves all of the above at §7.4 bucket semantics, §7.5 handed to the caller (§2.2) |
| Backfill (`tools/backfill`, docs/15) | ✅ per-row `update`/batched `updateMany` **through the extension** — traverses the §2 pipeline. **Confirmed 2026-08-27**: `create` and `updateMany` issued on the extended client both traverse `$allOperations` in full. The obligation to state is that the backfill must hold the **extended** client — the base client bypasses the pipeline silently, which is the failure this row exists to prevent |
| **L4**: `KEY_UNAVAILABLE` → `await warm()` → retry the pass | ✅ on by default where the provider implements `warm`; `warmOnKeyMiss: false` keeps the stricter "no query ever blocks on the key service" property. The core's value path still performs no I/O, asserted by instrumenting the provider rather than by review |
| All §4 shapes | 🛑 throw |
| `delete`/`deleteMany` by encrypted field | 🛑 refused — the rows the statement removes never come back for §7.5 to check, and an over-deletion is not recoverable. Measured: the bucket held 2, one of them a different value. This row read "✅ via index rewrite where declared" before the L2 build; `candidateScope` is the way to take those semantics deliberately |
| **Cross-language**: a row written here, decrypted by another implementation | ✅ `tests/cross/produce.ts` → `cross-prisma.json`, consumed by the Python and TypeScript cores in the N×N job. Covers every `as:` rendering, both storage forms, the tenant-bound context and the empty string |
| Raw SQL | ⚠️ passthrough + warning (default) / 🛑 throw (`strictRaw`) |
| Result decryption incl. `include` nesting | ✅ |
| `groupBy` on non-encrypted fields of a model containing encrypted fields | ✅ untouched |
| Middleware-order hazard: other extensions registered *after* fieldseal see ciphertext | ⚠️ documented — fieldseal must be the **last** `$extends` so it runs closest to the engine. **Confirmed 2026-08-27**, and the mechanism is worth stating because "last" reading like "runs last" is exactly backwards: the extension registered **first** is **outermost**, so the one registered last sits innermost, closest to the engine. Pinned by `tests/prisma-private-api.test.ts` so a Prisma change cannot invert it quietly |

## 7. Test plan

- **Visitor conformance:** a test sweep — for every operation × every arg shape in §2.1 and §4, assert encrypt/rewrite/throw exactly as specified, against SQLite (fast matrix) and Postgres (Bytes/`bytea` fidelity) in CI. **Both legs built, 2026-08-31**, and measured on both before the CI wiring was written rather than after. Two notes worth keeping: a datasource `provider` must be a string literal, so the Postgres leg needs its own schema file — derived from `schema.prisma` by `tests/fixture/build.ts` and gitignored, because a second *committed* schema drifts apart exactly where the second backend was supposed to catch something — and the four raw-SQL sites the tests use to plant state the adapter could not have produced (a forged index value, a legacy plaintext row, a flipped tag byte) needed one `setColumn` helper, since SQLite binds `?` and Postgres binds `$n`.
- **Zero-silent-failure regression:** the three failure shapes documented from `prisma-field-encryption` (`in:`, `contains:`, `orderBy`) each get a test asserting a **throw**, guarding the single most important behavioral difference (`docs/04` §3).
- **Unknown-shape fail-closed:** feed the visitor an arg tree with a fabricated operator; assert hard error.
- **Re-verification:** constructed truncation collision must be filtered from results.
- **Cross-language sharing test — built, 2026-08-31.** `tests/cross/produce.ts` writes rows through the real extension, reads the raw columns back, and emits `fieldseal-vectors/cross/v1`; the N×N CI job has the Python core decrypt it. One thing the plan did not anticipate: Prisma is the adapter where the **codec** decision is largest, because its schema type is the *storage* type and the logical type is therefore an `as:` declaration that exists nowhere else. The producer exercises all six `as:` renderings and both storage forms rather than text plus an integer, and the test asserts each expected plaintext instead of round-tripping it — a consumer that decoded an integer differently would decrypt successfully and read the wrong value.
- **L4 test:** cold cache + fake KMS wrapper — operation succeeds with an awaited warm, and the sync core path is never observed doing I/O (assert via wrapper instrumentation).

## 8. Deliberate non-goals

No `row_id` binding (extension runs before the query; DB-generated IDs don't exist yet — `docs/04` PK table), no MongoDB connector support, no `middleware` (`$use`) compatibility (deprecated), no transparent support for `select`ing decrypted values into raw SQL, no Prisma < 7 support commitment until tested.

## 9. Unindexable values (docs/09 §7.2 — normative for this adapter)

**The message's character and position come from `firstUnassigned`, not from the core's error text** (G22, [#88](https://github.com/fieldseal-dev/fieldseal-spec/issues/88), closed 2026-08-31). The extension throws rather than renders, but the thrown `FieldsealUnindexable` carries what `docs/12` §10.2 needs, and until G22 closed it carried only half: the offset was recovered by a regex over the core's message that matched only the `identity`/bytes path, so on `nfc-casefold-v1` — the normalizer every indexed column here declares — `detail.offset` was always `null` and the rendered message named the character without saying where it was. Measured before the fix rather than reasoned about: `{"codePoint":"U+0378","offset":null}`. The offset is counted in **code points**, so an astral character ahead of the fault counts as one position, not two.

`encrypt` does not normalize and `blindIndex` does, so a value containing a code point the pinned Unicode version does not define **stores but cannot be fingerprinted**. Each indexed field declares `on_unindexable` in its `///` annotation (§1); the extension's behaviour follows from it. This is the obligation `docs/09` §7.1 refers to.

| `on_unindexable` | Write path | Query path |
|---|---|---|
| `refuse` (default) | `blindIndex` throws `INVALID_ARGUMENT`; the extension lets it propagate out of the operation, so the caller sees a rejected write | A `where` on such a value throws the same error — it MUST NOT be rewritten into a query that returns zero rows |
| `bucket` | The index column receives the field's reserved marker; the write succeeds | The same marker is derived for the operand, the bucket matches, and §7.5 re-verification narrows — the visitor needs no special case |

The query-path row is the one that matters here, and it is the §10.2 rule this adapter already lives under. This adapter's whole reason for existing is that `prisma-field-encryption` encrypts filter operands and silently returns nothing; swallowing an unindexable-value error and returning `[]` would be the same failure with a different cause. Under `refuse` the operation throws. Under `bucket` it returns the right rows.

**The message.** The extension throws; it does not render. But the thrown error MUST carry what a UI needs to build the message in `docs/12` §10.2 — the offending code point and its offset — because an error that says only "invalid input" forces the application to either show that to a person or guess. The three rules are the same: name the character and its position, put the fault on the system, and offer a route that ends with the real value stored.

**`bucket` requires the ceremony and carries the cost.** `unindexableOverride: { reason, approvedBy, date }` is required at extension construction, refused otherwise — the same shape spec §7.6 requires for a cardinality override. The bucket is an equivalence class distinguishable by frequency and growable by any writer; both are documented in the adapter README, not only here. See `docs/12` §10.4, which states the cost in full and applies verbatim.
