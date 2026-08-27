# Prisma Adapter Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the engineering design for `adapters/prisma` (package `@fieldseal/prisma`), targeting Prisma 7.x. Built on the analysis in `docs/04-orm-adapter-notes.md` §3; the single most important behavioral difference from the existing `prisma-field-encryption` library is the **mandatory throw list** (§4 below) — spec §10.2 requires throwing where that library silently mis-encrypts or drops.

**Conformance target (spec §10.1):** L0 ✅ · L1 ✅ · L2 (b) ⚠️ with mandatory throws · L3 partial (tenant via args/ALS) ⚠️ · L3-row ❌ · L4 ✅ (`$allOperations` is async — best-in-class KMS integration).

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
- Annotation parsing happens once at **`prisma generate`**, producing a frozen per-model **field map**: `{ model → { encrypted, indexes, relations, tableUuid } }`, emitted as a committed module the extension imports. A malformed annotation fails the generate, never a runtime skip — strictly better than the construction-time error this originally specified, because a schema that cannot be declared correctly never produces a client. The parsed declarations feed core-client construction (§2), where the §7.6 cardinality gate applies: a declared index whose `projected_population` is below 2¹⁰ fails construction unless the extension options carry the explicit, logged `cardinalityOverride` declaration spec §7.6 requires — the override lives in code reviewed by humans, never in a schema comment.

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
3. REJECT pass: walk args for forbidden shapes (§4) → throw FieldsealNotSupported
4. WRITE pass: walk data/create/update/upsert trees, encrypt declared fields,
   derive + set sibling index fields
5. WHERE pass: rewrite equality/not predicates on encrypted fields onto sibling
   index fields (blind_index of the plaintext parameter)
6. await query(args)              // async — KMS warm-up can await here (L4)
7. READ pass: decrypt declared fields in the result tree (recursively, since
   include nests relations)
8. RE-VERIFY pass: for any query that used an index rewrite, decrypt-and-compare
   and drop collision rows (spec §7.5 — the index is a filter, never an answer)
```

### 2.1 The args-tree visitor — typed, not string-surgery

`docs/04` §3 calls the existing library's JSON-path approach "the correctness cliff." This adapter's visitor is **schema-driven**: it walks the args tree *guided by the DMMF model graph* (which relation fields exist, which scalars are encrypted), so nested `create`/`connectOrCreate`/`upsert`/nested `update` under relation keys are visited by construction rather than by path-pattern luck. Every leaf it cannot classify against the schema is a **hard error**, not a passthrough — unknown arg shapes fail closed.

Write-tree coverage (each an explicit visitor case + test): `create.data`, `createMany.data[]`, `update.data`, `updateMany.data`, `upsert.create/update`, nested relation writes (`data.<rel>.create|createMany|update|upsert|connectOrCreate.create`), and `set`/`unset` forms on supported field types.

Where-tree coverage: `where.<field>` shorthand equality, `where.<field>.equals`, `.not` (scalar form), `AND`/`OR`/`NOT` arrays recursively, relation filters (`some`/`every`/`none`) recursively, `cursor.<field>` (rejected — cursor on randomized ciphertext is meaningless; see §4), and `findUnique.where` naming an encrypted or index field (rejected — Prisma requires a unique column there, and neither randomized ciphertext nor a collision-mandated truncated index can be unique, which §7.10 now states normatively per G12; the rewrite target is `findFirst` with equality + re-verify).

## 3. Read path

Decryption happens on the awaited result (step 7), not via `result.compute` — computed fields cannot be used in `where`/`orderBy` and cannot replace stored values (`docs/04` §3). The visitor mirrors `include` nesting using the DMMF relation graph. Because `select`/`include` cannot be mutated by extensions (`docs/04` §3, Prisma docs verbatim), there is no hidden-column problem for values (ciphertext lives in the field's own column), but **sibling index columns appear in results**: the read pass strips `*Bidx` fields from returned objects unless `exposeIndexColumns: true`, so application code never accidentally depends on index bytes.

**Re-verification compares under spec §7.5's rule (G19 [#78](https://github.com/fieldseal-dev/fieldseal-spec/issues/78), resolved 2026-08-26):** `normalize(stored)` against `normalize(queried)` under the index's declared normalizer, on the normalizer's output bytes — using the core's public `normalize`, never a reimplementation. The extension MUST document the consequence §7.5 states: on a non-`identity` column an equality filter is equality under that normalizer (a query for `ada@example.com` can return `Ada@Example.com`), and no second, differently-folded equality may be offered — which is the reason `mode: "insensitive"` is on the §4 rejection list rather than being mapped onto the index.

Read modes: core modes apply as-is; `permissive` fires the extension's `onPlaintextRead` hook with model/field (never the value) per spec §10.3.

## 4. The mandatory throw list (spec §10.2 — normative for this adapter)

Rationale per case is the verified failure mode in `docs/04` §3: un-rewritten filter shapes get the *value encrypted instead*, silently returning zero rows. The rule: **nothing on this list may silently degrade, and nothing may be downgraded to a warning.** Two rows have an explicitly specified alternative to throwing — `in:`/`notIn:` upgrades to an index rewrite when an index is declared, which spec §10.2 explicitly permits as of G13 (see the note below the table), and raw ops (whose SQL the extension cannot inspect) default to passthrough + warning hook with `strictRaw` opting into the throw. Every other row throws `FieldsealNotSupported` unconditionally, with the field name, the shape, and the honest fallback from spec §7.10.

| Shape on an encrypted field | Why |
|---|---|
| `in:` / `notIn:` with **no declared index** | Not rewritable — throw. With a declared index this upgrades to a rewrite (below) |
| `contains:`, `startsWith:`, `endsWith:`, `search:` | No substring/prefix over ciphertext (spec §7.1; prefix only via a declared §7.9 index, out of v0 scope) |
| `lt/lte/gt/gte:` | No order over ciphertext (spec §4.7) |
| `mode: "insensitive"` | Case folding is the normalizer's job, not the query's |
| `orderBy` naming an encrypted field | The existing library deletes it with a `console.error` — this adapter throws (spec §10.2 named this case for Prisma from the start; G20 ([#80](https://github.com/fieldseal-dev/fieldseal-spec/issues/80)) generalized it to every ORM, alongside grouping, `DISTINCT` and aggregates over ciphertext — the extension's visitor must refuse those shapes too) |
| `distinct`, `groupBy.by`, `having` on an encrypted field | Grouping by randomized ciphertext is meaningless (index-column grouping with the §7.10 collision caveat is the documented alternative) |
| `aggregate` (`_min`/`_max`/`_sum`/`_avg`) on an encrypted field | Spec §7.10 |
| `cursor` on an encrypted field | Pagination on ciphertext is incorrect (spec §7.5) |
| Raw ops (`$queryRaw`, `$executeRaw`) when `strictRaw: true` | Parameters are never encrypted by any ORM (spec §10.2); default is passthrough + warning hook, strict deployments opt into throwing |
| `findUnique` naming an encrypted or index field | Neither can be unique (spec §7.10, G12); rewrite target is `findFirst` + re-verify |
| `where.<encrypted>` with **no declared index** | Equality without an index cannot be served (randomized suite) — throw with "declare a blind index or filter after fetch" |

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

The gates that are **not** here are the ones that belong to the core and run at client
construction against the assembled registry: the §7.4 truncation band, the §7.6
cardinality gate, the Argon2id minima, and the §7.2 bucket ceremony. A second copy of a
gate is a copy that can disagree with the one that matters, and `docs/07` §7 records what
that costs — the Python core had drifted to enforcing *none* of its declaration-time
gates while `docs/10` §4 specified all of them, unnoticed because the adapter looked like
it was checking.

## 5. Tenant context and L4

- Tenant bytes come from either the `tenant` callback (inspecting args — e.g., a `tenantId` scalar present in the write) or an `AsyncLocalStorage` accessor set by request middleware. Both are documented side channels (spec §10 L3 ⚠️ for Prisma). Fail-closed rule as in the Django adapter: tenant-bound columns with no resolvable tenant throw, never silently encrypt tenantless.
- **L4:** because `$allOperations` is async and runs before a connection is acquired (`docs/04` §3), the adapter MAY `await client.warm([...contexts])` on cache miss before proceeding — the one adapter in Phase 1 that can do KMS acquisition in-path without holding a pooled connection. This is the flagship demonstration of why the core separates `warm` from the sync value path.

## 6. Coverage matrix (AD-2 deliverable, README + generated from tests)

| Path | Behavior |
|---|---|
| `create`, `createMany`, `update`, `updateMany`, `upsert`, nested writes | ✅ encrypts + index siblings |
| `findMany/findFirst/count` with rewritable equality/`in` on indexed fields | ✅ rewritten + re-verified (the `in:` rewrite is conformant to §10.2 as of G13; no deviation remains) |
| Backfill (`tools/backfill`, docs/15) | ✅ per-row `update`/batched `updateMany` **through the extension** — traverses the §2 pipeline. **Confirmed 2026-08-27**: `create` and `updateMany` issued on the extended client both traverse `$allOperations` in full. The obligation to state is that the backfill must hold the **extended** client — the base client bypasses the pipeline silently, which is the failure this row exists to prevent |
| All §4 shapes | 🛑 throw |
| `delete`/`deleteMany` by encrypted field | ✅ via index rewrite where declared; 🛑 otherwise |
| Raw SQL | ⚠️ passthrough + warning (default) / 🛑 throw (`strictRaw`) |
| Result decryption incl. `include` nesting | ✅ |
| `groupBy` on non-encrypted fields of a model containing encrypted fields | ✅ untouched |
| Middleware-order hazard: other extensions registered *after* fieldseal see ciphertext | ⚠️ documented — fieldseal must be the **last** `$extends` so it runs closest to the engine. **Confirmed 2026-08-27**, and the mechanism is worth stating because "last" reading like "runs last" is exactly backwards: the extension registered **first** is **outermost**, so the one registered last sits innermost, closest to the engine. Pinned by `tests/prisma-private-api.test.ts` so a Prisma change cannot invert it quietly |

## 7. Test plan

- **Visitor conformance:** a generated test sweep — for every operation × every arg shape in §2.1 and §4, assert encrypt/rewrite/throw exactly as specified, against SQLite (fast matrix) and Postgres (Bytes/`bytea` fidelity) in CI.
- **Zero-silent-failure regression:** the three failure shapes documented from `prisma-field-encryption` (`in:`, `contains:`, `orderBy`) each get a test asserting a **throw**, guarding the single most important behavioral difference (`docs/04` §3).
- **Unknown-shape fail-closed:** feed the visitor an arg tree with a fabricated operator; assert hard error.
- **Re-verification:** constructed truncation collision must be filtered from results.
- **Cross-language sharing test:** rows written through this adapter decrypt via the Python core and vice versa (same shape as the Django §8 test).
- **L4 test:** cold cache + fake KMS wrapper — operation succeeds with an awaited warm, and the sync core path is never observed doing I/O (assert via wrapper instrumentation).

## 8. Deliberate non-goals

No `row_id` binding (extension runs before the query; DB-generated IDs don't exist yet — `docs/04` PK table), no MongoDB connector support, no `middleware` (`$use`) compatibility (deprecated), no transparent support for `select`ing decrypted values into raw SQL, no Prisma < 7 support commitment until tested.

## 9. Unindexable values (docs/09 §7.2 — normative for this adapter)

`encrypt` does not normalize and `blindIndex` does, so a value containing a code point the pinned Unicode version does not define **stores but cannot be fingerprinted**. Each indexed field declares `on_unindexable` in its `///` annotation (§1); the extension's behaviour follows from it. This is the obligation `docs/09` §7.1 refers to.

| `on_unindexable` | Write path | Query path |
|---|---|---|
| `refuse` (default) | `blindIndex` throws `INVALID_ARGUMENT`; the extension lets it propagate out of the operation, so the caller sees a rejected write | A `where` on such a value throws the same error — it MUST NOT be rewritten into a query that returns zero rows |
| `bucket` | The index column receives the field's reserved marker; the write succeeds | The same marker is derived for the operand, the bucket matches, and §7.5 re-verification narrows — the visitor needs no special case |

The query-path row is the one that matters here, and it is the §10.2 rule this adapter already lives under. This adapter's whole reason for existing is that `prisma-field-encryption` encrypts filter operands and silently returns nothing; swallowing an unindexable-value error and returning `[]` would be the same failure with a different cause. Under `refuse` the operation throws. Under `bucket` it returns the right rows.

**The message.** The extension throws; it does not render. But the thrown error MUST carry what a UI needs to build the message in `docs/12` §10.2 — the offending code point and its offset — because an error that says only "invalid input" forces the application to either show that to a person or guess. The three rules are the same: name the character and its position, put the fault on the system, and offer a route that ends with the real value stored.

**`bucket` requires the ceremony and carries the cost.** `unindexableOverride: { reason, approvedBy, date }` is required at extension construction, refused otherwise — the same shape spec §7.6 requires for a cardinality override. The bucket is an equivalence class distinguishable by frequency and growable by any writer; both are documented in the adapter README, not only here. See `docs/12` §10.4, which states the cost in full and applies verbatim.
