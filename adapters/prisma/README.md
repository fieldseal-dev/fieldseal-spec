# @fieldseal/prisma

Transparent field-level encryption at rest for Prisma. Design:
[`docs/13-adapter-prisma.md`](../../docs/13-adapter-prisma.md).

**Status: L1 + L2(b), and not usable in production.** Values encrypt and decrypt
transparently, blind-index siblings are derived on write, and equality and
membership are rewritten onto the declared index with the spec §7.5
re-verification that makes the rewrite correct — but **only where the rows come
back to be checked**, which in Prisma is two places (see
[Querying an indexed column](#querying-an-indexed-column)). Everywhere the
database answers instead, the shape is refused rather than approximated.
Nothing here is frozen: the suite identifier is provisional (spec §4.8), Gate 0b
is open, and the project does not invite adoption.

**AD-1 (spec §11.3): this package contains no cryptography.** It calls the
core's published operations and nothing else. Installing it pulls in
`@fieldseal/core`, and that is where every cipher, KDF and random draw lives.
CI asserts this with a grep rather than trusting review — a tripwire, not a
proof: it matches `import`/`from` lines and would not catch a dynamic
`import()`.

Targets **Prisma 7.10.x**. Note that the `prisma` CLI's `latest` dist-tag
currently points at an `8.0.0-rc`, so pin both packages explicitly.

---

## Declaring a column

Prisma has no schema extension point, so declarations are `///` doc comments:

```prisma
generator fieldseal {
  provider = "fieldseal-prisma-generator"
  output   = "../src/generated"
}

/// @fieldseal(table_uuid: "018f3c2e-…")
model Patient {
  id        String  @id @default(uuid())
  /// @fieldseal(encrypted, column_uuid: "018f3c2e-…")
  email     Bytes
  /// @fieldseal(index: "email", index_id: "exact", idf: "hmac-sha512",
  ///            normalize: "nfc-casefold-v1", truncate_bits: 15,
  ///            projected_population: 100000)
  emailBidx Bytes?
  plainName String

  @@index([emailBidx])
}
```

The UUIDs are surrogates written literally in the schema. They must never be
derived from the model or field name: spec §6.1 binds key derivation to them,
so a rename would make every existing row undecryptable.

**The index sibling must be optional (`Bytes?`).** Prisma's generated `create`
input requires every non-optional column, so a required sibling would force
callers to supply the one value the adapter refuses to accept from them — it is
derived. A NULL value also has no index, so the column must accept NULL anyway.
The generator refuses a required sibling.

`truncate_bits` must sit inside the spec §7.4 band (9–15 bits at
P = 100,000), which **mandates collisions**. A `@unique` sibling is therefore
wrong and spec §7.10 forbids it outright.

### Why a generator, and not runtime introspection

`docs/13` §1 was written against reading the `///` comments "from the DMMF at
runtime". **That is not possible in Prisma 7.** Measured against 7.10.0 on
2026-08-27:

- `Prisma.dmmf` no longer exists — the generated namespace exports `DMMF` as a
  *type* only.
- The client's private `_runtimeDataModel` carries the model and relation graph
  but **no `documentation`**. The annotations are simply not in it.
- They survive only in the schema source text.

So the declarations are read where they *are* available and the route is
supported: at `prisma generate`, from `options.dmmf`, which Prisma's own parser
populates with documentation on every model and field. Two consequences, both
better than the original design:

- A malformed declaration **fails `prisma generate`**, not the first request —
  the Prisma analogue of Django's startup system checks.
- The declarations and the relation graph arrive together, from one source. The
  args-tree visitor needs both, and at runtime they live in different places.

The emitted file contains declarations only — no key material, nothing derived,
nothing secret. Commit it.

## Wiring it up

```ts
import { fieldsealExtension } from "@fieldseal/prisma";
import { fieldsealFieldMap } from "./generated/fieldseal-map.js";

const prisma = new PrismaClient({ adapter }).$extends(
  fieldsealExtension({
    fieldMap: fieldsealFieldMap,
    keyProvider,
    allowedSuites: [0xff01],
    writeSuite: 0xff01,
    readMode: "strict",
  }),
);
```

**Register fieldseal last.** The extension registered *first* is outermost, so
the one registered last sits closest to the engine — which is where this must
be, so every other extension sees plaintext rather than envelopes. "Last"
reading like "runs last" is exactly backwards, which is why it is spelled out;
`tests/prisma-private-api.test.ts` pins the ordering so a Prisma change cannot
invert it quietly.

There is no `client` option. This extension always builds the index registry
from the schema, so a supplied client would be a second source for declarations
that already have one.

## Tenant binding (spec §10, L3)

The extension runs before the query and never sees the record, so the tenant
arrives out of band — `AsyncLocalStorage`, or a callback over the arguments:

```ts
import { tenantScope } from "@fieldseal/prisma";

await tenantScope("tenant-a", async () => {
  await prisma.patient.create({ data: { email: "ada@example.com" } });
});
```

**An unresolvable tenant on a tenant-bound column refuses the write.** Falling
back to a tenantless context would store a row no correctly configured reader
can decrypt — and because spec §6.3 binds the context into the derived key, the
reader's error would be `COMMITMENT_INVALID`: a decrypt-side failure reported
for a write-side mistake, arbitrarily far from the cause. (`AAD_MISMATCH` never
fires on the `0xFF01` path, for the same reason.)

---

## Key acquisition in the value path (L4)

Every field hook in Django, SQLAlchemy, Hibernate and GORM is synchronous, so
`docs/09` §8.2 confines KMS unwrapping to `warm()` and forbids the value path
from blocking on the network. The consequence is exact: an
`EnvelopeKeyProvider` deployment whose cache is cold serves `KEY_UNAVAILABLE`
for **every** operation until something warms it — and in a sync adapter that
something is an operator, a management command, or a startup hook that guessed
the right tenants.

Prisma does not have to guess. `$allOperations` is `async` and runs **before
the query engine acquires a connection**, so on a `KEY_UNAVAILABLE` the
extension awaits `client.warm(…)` for the contexts this operation actually
named and runs the pass again. That is spec §10.1's L4, and it is why the matrix
marks it reachable for Prisma and for almost nothing else.

```ts
fieldsealExtension({ …, warmOnKeyMiss: true })  // the default
```

Three things worth being precise about:

- **The core's rule is not bent.** `encrypt`, `decrypt` and `blindIndex` are
  still synchronous and still refuse a cache miss. What changed is what the
  *adapter* does with the refusal — it awaits between two synchronous core
  calls. `tests/l4.test.ts` instruments the key provider and fails the run if an
  unwrap is ever observed from inside a synchronous core call, so a regression
  that "fixed" L4 by making the core block on the network would be caught.
- **It is reactive, not a pre-flight check.** There is no cache-membership
  probe, and there should not be one: a §5.5 cache can evict between the probe
  and the use, and `encryptionKey` used as a probe would advance the §5.5 use
  counter for a key nobody used. The miss is the signal.
- **It gives up rather than looping.** A cycle runs only if the next attempt
  needs a context no previous cycle warmed. A miss on a context that *was* just
  warmed means warming did not help (key destroyed, wrong tenant, an eviction
  faster than the operation), and the error is raised — blocking a query on
  repeated KMS round trips is the availability failure spec §8.1 warns about.

Set `warmOnKeyMiss: false` to keep the stricter property that no query ever
blocks on the key service. The option is inert either way unless the provider
implements `warm`, so `StaticKeyProvider` and `DerivedKeyProvider` deployments
are unaffected.

**Retrying a pass is only safe because the failed attempt leaves nothing
behind.** Every mutation the visitors make is journalled and rolled back before
a retry (`src/journal.ts`); without it the retry would read the envelope the
first attempt wrote as if it were the caller's value and encrypt it twice.

---

## Querying an indexed column

A declared index makes equality and membership serveable:

```ts
await prisma.patient.findMany({ where: { email: "ada@example.com" } });
await prisma.patient.findMany({ where: { email: { in: ["a@x.com", "b@x.com"] } } });
```

The predicate never reaches the database as written — the suite is randomized,
so comparing against ciphertext matches nothing. It is rewritten onto the
sibling (`emailBidx`), which is spec §7.10's supported membership shape and is
what spec §10.2 permits for Prisma as of G13.

### The index is a filter, never an answer

Spec §7.4 **mandates** collisions: the truncation band is chosen so that every
index value corresponds to at least two distinct plaintexts, because that
ambiguity is the privacy mechanism. So the database returns a *superset*, and
the adapter decrypts the candidates and drops the ones that do not hold the
value (spec §7.5) before you see them.

That is only possible where the rows come back. Measured against Prisma 7.10.0
(the classification, with the evidence, is
[`docs/13` §2.0](../../docs/13-adapter-prisma.md)), exactly **two** `where`
sites in Prisma's surface qualify:

1. the top-level `where` of **`findMany`**, and
2. a relation `where` under **`include` / `select`**, whose matched rows arrive
   nested inside their parents.

Everywhere else the database computes the answer and only the answer comes
back — `count`, `aggregate`, `groupBy`, `findFirst` (its `LIMIT 1` is applied
below the extension and cannot be widened: Prisma refuses a `take` on
`findFirst` that is not 1 or -1), `updateMany`, `deleteMany`, `update`,
`delete`, `upsert`, relation filters (`some`/`every`/`none`/`is`), `_count`,
and the filters nested writes carry. Those are **refused**, and each refusal
names what to run instead. `take`, `skip`, `cursor` and `distinct` are refused
*beside* a rewritten filter for the same reason: the database applies them to
the candidate set before re-verification shrinks it.

This is narrower than the Django adapter, which can serve `count()`,
`first()` and `get()` by materializing the bucket itself. A Prisma extension
cannot: `query` is bound to the operation it was called for, so an operation
whose result is a number cannot be turned into a row fetch.

**Pagination built directly on an indexed encrypted column is incorrect**
(spec §7.5). The correct pattern is over-fetch → decrypt → filter → paginate:
fetch the verified rows with `findMany` and slice them in application code.

### Equality is the index's own equality

**On a column whose declared normalizer is not `identity`, an equality lookup
is equality under that normalizer, not byte equality of the plaintext.** With
`nfc-casefold-v1`, a query for `ada@example.com` can return a row stored as
`Ada@Example.COM`. That is spec §7.5's rule (G19), and it is why
`mode: "insensitive"` is refused rather than mapped onto the index: the column
has exactly one equality, and no second, differently-folded one may be offered
beside it.

### `candidateScope` — the documented opt-out

When bucket semantics are what you want, say so:

```ts
import { candidateScope } from "@fieldseal/prisma";

const approx = await candidateScope(() =>
  prisma.patient.count({ where: { email: "ada@example.com" } }),
);
```

Inside the callback, §7.5 re-verification is **off** and every shape above is
served. What comes back is the raw candidate set: a superset of the answer, and
decrypt-and-compare becomes yours. `count` returns the bucket size; a
`take`-limited page can hold rows that do not match and miss ones that do; and
**`deleteMany` deletes the whole bucket, which is not recoverable** — the test
suite measures each of these rather than describing them. It mirrors the Django
adapter's `.candidates()`, which lifts the same family.

Three caveats:

- **The scope is the callback, not the next call.** Everything awaited inside
  it is unverified. The idiom is one operation per scope.
- **It must be awaited from `candidateScope` itself.** A Prisma client method
  returns a lazy promise that dispatches nothing until something awaits it, so
  a callback that merely *constructs* a promise and returns it unawaited would
  escape the scope. `candidateScope` awaits inside for exactly this reason.
  The boundary is dispatch, not construction — which also means a promise
  constructed *before* the scope but first awaited *inside* it dispatches
  inside and is served at bucket semantics (measured). Construct the operation
  inside the callback, and nowhere else.
- **It does not lift everything.** Ordering, grouping, `DISTINCT` and
  byte-reading aggregates over an encrypted column stay refused (G20) — bucket
  semantics are a meaningful thing to accept, ciphertext order is not. Nor does
  it lift `not`/`notIn` (spec §7.10 has no row for negated membership; G21
  [#87](https://github.com/fieldseal-dev/fieldseal-spec/issues/87) is open),
  equality on a column with no declared index, or `findUnique` on an encrypted
  column.

---

## Coverage matrix

What the code does **today**, each row verified by the test named in it — not
the target matrix in `docs/13` §6.

| Path | Behaviour | Test |
|---|---|---|
| `create`, `createMany`, `update`, `updateMany` | ✅ encrypts; index sibling derived | `round-trips the plaintext…`, `encrypts through createMany and updateMany` |
| Nested relation writes (`create`, `connectOrCreate`, `upsert`, nested `update`) | ✅ reached through the relation graph, not path patterns | `encrypts a nested relation write…` |
| **Filters inside nested writes** (`updateMany.where`, `deleteMany`, `upsert.where`, unique inputs) | 🛑 refused when they name an encrypted column — same walk as the top-level `where` | `refuses a nested updateMany.where…`, `refuses a nested deleteMany…` |
| Nested `deleteMany`/`connect`/`disconnect`/`delete`/`set` off encrypted columns | ✅ served — they write no ciphertext | `serves a nested deleteMany over plaintext columns…` |
| `undefined` in a payload | ✅ touches nothing — not the value, not the sibling (Prisma's "do not touch" contract) | `touches nothing: not the value, and not the sibling` |
| **A model with no declarations** (relations to declared ones) | ✅ in the map as a relation-only entry; writes, reads and filters through it traverse the pipeline | `reaching Patient through the undeclared Referral model` |
| A model missing from the field map — as the operation's model **or as a relation target** any walk reaches | 🛑 refused — a stale or edited map, never a passthrough; a skipped relation would write plaintext or return envelopes one hop down | `refuses an operation on a model the field map does not carry`, `refuses a nested write through a relation…` |
| Database holds an envelope, never plaintext | ✅ | `stores an envelope in the database…` |
| Repeated writes of one value | ✅ fresh nonce + `msg_seed` each time (spec §4.4) | `writes a different envelope every time…` |
| `update` re-encrypts | ✅ including the `{ set: … }` form | `re-encrypts on update…`, `accepts the { set: value } update form` |
| `update` with `increment`/arithmetic | 🛑 refused — the database would compute on an envelope | `refuses an arithmetic update…` |
| Reads, including `include` nesting | ✅ decrypts recursively | `encrypts a nested relation write…` |
| Non-ASCII values | ✅ round-trip byte-for-byte | `round-trips a non-ASCII value…` |
| Empty string | ✅ a value, not an absence | `treats the empty string as a value…` |
| `NULL` | ✅ stays NULL; its index is NULL too | `stays NULL rather than becoming an envelope` |
| `where: { field: null }`, `{ equals: null }`, `{ not: null }` | ✅ served — `IS [NOT] NULL` is exact over envelopes, because NULL stays NULL | `serves literal-NULL equality…` |
| Non-text logical types (`as: "int"`, `"datetime"`, `"boolean"`, `"float"`, `"bytes"`) | ✅ round-trip as their own type, incl. a bare `Date` | `every declared \`as:\` type round-trips as itself` |
| A value that does not match the declared `as:` | 🛑 refused rather than coerced | `refuses a value whose type does not match…` |
| `storage: "base64"` on a `String` column | ✅ ASCII in the column, ~33% overhead | `round-trips through a String column…` |
| Blind index written on insert | ✅ deterministic, case-folded, `ceil(b/8)` bytes | `is derived on write…`, `folds case…` |
| Index sibling in results | ✅ stripped unless `exposeIndexColumns` | `is stripped from returned objects…` |
| A hand-written index value | 🛑 refused — those bytes are derived | `refuses a hand-written index value` |
| Tenant-bound column, no tenant | ✅ refuses the write | `refuses the write when no tenant is resolvable` |
| Wrong tenant reading a row | ✅ raises — the binding is cryptographic, not a filter | `cannot be read under a different tenant…` |
| Tampered ciphertext | ✅ raises; never returns garbage | `raises rather than returning garbage` |
| **`findMany` equality / `in` on an indexed encrypted column** | ✅ rewritten onto the sibling + §7.5 re-verified | `finds the row by its plaintext value`, `rewrites \`in\` as spec §7.10 membership`, `returns only the true match when the bucket holds another row` |
| Equality on a column with **no declared index** | 🛑 refused — nothing to rewrite onto | `refuses on a column with no declared index…` |
| Equality under a **non-identity normalizer** | ⚠️ equality *under that normalizer* — a query for `ada@…` returns a row stored `Ada@Example.COM` (spec §7.5, G19) | `a query for the lowercase value returns the row stored mixed-case` |
| A relation `where` under `include`/`select` | ✅ rewritten + re-verified in the nested rows, at any depth incl. a to-one hop | `filters the nested rows and re-verifies them`, `verifies through a to-one hop in the path` |
| Bucketed unindexable values sharing one index value | ✅ separated by §7.5's raw-bytes fallback | `returns only the queried value, though both share one index value` |
| **`findFirst`/`findFirstOrThrow`** on a rewritten filter | 🛑 refused — the `LIMIT 1` is applied below the extension and cannot be widened (`take` must be 1 or -1) | `names findFirst's invisible LIMIT…`, `measures why findFirst is refused…` |
| **`count`, `aggregate`, `groupBy`** on a rewritten filter | 🛑 refused — the database answers over the §7.4 bucket; measured overcount 2 vs 1 | `measures why count is refused: it counts the bucket` |
| **`updateMany`, `deleteMany`, `update`, `delete`, `upsert`** on a rewritten filter | 🛑 refused — would write to or delete rows that do not match; measured `deleteMany` = 2 of 2 | `measures why deleteMany is refused…` |
| `take`, `skip`, `cursor`, `distinct` beside a rewritten filter | 🛑 refused — applied to the candidate set before §7.5 shrinks it; the page holds the collision and misses the match | `measures why \`take\` is refused…`, `refuses \`distinct\` even on a plaintext column` |
| A `take` on the **parent** of a nested obligation | ✅ served — dropping child rows cannot change which parents matched | `a \`take\` on the *parent* is fine…` |
| An encrypted term under `OR` / `NOT` | 🛑 refused — a returned row may be there for the other branch, so §7.5 cannot attribute it | `refuses \`OR\`…` |
| Relation filters (`some`/`every`/`none`/`is`, unwrapped to-one) naming an encrypted column | 🛑 refused — the rewrite lands in a join the database answers (spec §10.2: a path the surface does not reach) | `refuses the \`some\` form` (5-way sweep) |
| `_count` whose relation filter names an encrypted column | 🛑 refused — computed in the database | `refuses a \`_count\` whose relation filter…` |
| A projection that drops the column being verified (`select`, query `omit`, **client-level `omit`**) | 🛑 refused on the result — the client-level form never appears in `args` at all | `refuses a *client-level* omit…` |
| `candidateScope(fn)` | ⚠️ serves every row above at **bucket semantics**; §7.5 becomes the caller's | `candidateScope: what it hands over, and what it does not` (13 tests) |
| `candidateScope` over G20 shapes, `not`/`notIn`, an unindexed column, `findUnique` | 🛑 still refused | `does NOT lift the G20 family…`, `does NOT lift \`notIn\` or \`not\`…` |
| `contains`, `startsWith`, `endsWith`, `lt`/`gte`, `search` | 🛑 refused (spec §7.1, §4.7) | `refuses \`contains\`…` (8-way sweep) |
| `mode: "insensitive"` | 🛑 refused — the column has exactly one equality (G19) | `refuses \`mode: insensitive\`…` |
| `not`, `notIn` (non-null operands) | 🛑 refused — an exclusion's false negatives are unrecoverable | `explains notIn as an exclusion asymmetry…` |
| An unrecognised filter operator | 🛑 hard error — fails closed, never passed through | `fails closed on an operator it does not recognise` |
| Filtering the index sibling directly | 🛑 refused — cannot re-verify a filter it did not construct | `refuses a filter on the index sibling directly` |
| `findUnique` on an encrypted column or its sibling | 🛑 refused — neither can be unique (spec §7.10); use `findMany` + equality | `refuses findUnique on an encrypted column…` |
| `orderBy` over an encrypted column | 🛑 refused (G20) — sorts envelope bytes | `refuses orderBy…` |
| `distinct`, `groupBy.by`, `having` over one | 🛑 refused (G20) — one group per row, wrong counts | `refuses distinct…`, `refuses groupBy…` |
| `distinct` on the **index sibling** | ⚠️ served — deduplicates by index value, §7.4 collisions included: a filter-grade answer, not an exact one | `serves distinct on the index sibling…` |
| `_min`/`_max`/`_sum`/`_avg` over one | 🛑 refused (G20) — computes on bytes | `refuses aggregates…` |
| `_count` over an encrypted field | ✅ served — counts non-NULL rows, reads no bytes, exact under spec §10.2's NULL-preservation invariant (G23 [#89](https://github.com/fieldseal-dev/fieldseal-spec/issues/89), closed) | `serves _count over an encrypted field…` |
| `cursor` on an encrypted column | 🛑 refused — ciphertext has no stable total order | `refuses cursor pagination…` |
| Plaintext columns of the same model | ✅ untouched — filter, sort and group normally | `leaves filters on plaintext columns…`, `leaves orderBy and groupBy…` |
| `count()` over rows | ✅ counts rows, reads no bytes | `allows _count over rows…` |
| Raw SQL (`$queryRaw`, `$executeRaw`) | ⚠️ passthrough + hook (default) / 🛑 `strictRaw` | `passes through with a hook…`, `throws under strictRaw` |
| Malformed declaration | 🛑 fails `prisma generate` | `fails the generate on a malformed declaration…` |
| `@unique`/`@id`/`@@unique` on an encrypted column or sibling | 🛑 fails `prisma generate` (spec §7.10) — a unique sibling is delayed data loss under §7.4 collisions | `uniqueness refusals (spec §7.10)` |
| Legacy plaintext row on a base64 column | 🛑 strict raises NOT_CIPHERTEXT / ⚠️ permissive returns the actual value and fires `onPlaintextRead` | `a stored value that is not an envelope…` |
| Unindexable value, `on_unindexable: "refuse"` | 🛑 `FieldsealUnindexable` carrying the code point and offset | `refuse mode raises FieldsealUnindexable…` |
| Unindexable value, `on_unindexable: "bucket"` | ✅ real value stored; the §7.2 reserved marker's index derived | `bucket mode stores the real value…` |
| `on_unindexable: "bucket"` without the §7.2 ceremony | 🛑 refused at construction | fixture supplies it; see `helpers.ts` |
| **Cross-language: a row written here, read by another core** | ✅ `tests/cross/produce.ts` emits `fieldseal-vectors/cross/v1`; the N×N CI job has the Python core decrypt it | `decrypts every case from the shared key material alone`, `pins every \`as:\` rendering…` |
| `row_id` binding (L3-row) | ❌ not in v0 | — |
| **L4** — `KEY_UNAVAILABLE` → `await warm()` → retry the pass | ✅ on by default when the provider can warm; `warmOnKeyMiss: false` opts out | `is the difference between a cold deployment…`, `warms once per cold operation…`, `warms the index key too…` |
| The core's value path still does no I/O under L4 | ✅ asserted by instrumentation, not by review | `never unwraps from inside a synchronous core call…` |
| A pass that throws leaves the argument and result trees as it found them | ✅ journalled and rolled back, which is what makes the retry safe | `writes each column exactly once when the write pass is retried`, `decrypts each column exactly once…` |

Legend: ✅ intercepted correctly · ⚠️ works with a documented caveat ·
🛑 refuses rather than degrading · ❌ not implemented.

### Why refusals, and not best effort

`docs/04` §3 records what the existing `prisma-field-encryption` library does
with these shapes, verified against its source: only `where.field`,
`.equals`, `.not`, `connect.field` and `cursor.field` are rewritten. Everything
else — `in`, `contains`, `startsWith` — gets **the operand encrypted instead**,
and the query returns **zero rows, silently, with no error**. `orderBy` on an
encrypted field is deleted with a `console.error`.

Spec §10.2 requires an adapter to throw on all of it, and that is the single
most important behavioural difference between this adapter and that one.

The G20 family is worth separating out, because those shapes *do* return an
answer. The test suite measures them rather than asserting them from the spec:
`distinct` over two rows holding one value returns **two** rows; `groupBy`
returns **two groups of one** where the truth is one group of two. And on a
`storage: "base64"` column, `_min` returns the byte-wise minimum **envelope**,
handed back as the minimum value with nothing raised — silent and plausible,
which is what makes it the dangerous one.

One honest narrowing: on a `Bytes` column, Prisma's own deserializer throws on
an aggregate result, so that particular hazard is not silently reachable there
even without this adapter. The refusal is still right — it names the reason and
does not depend on a Prisma implementation detail — but the base64 case is where
it bites.

---

## Cross-language: what this adapter stores, read by another language

The project's central claim is that a value encrypted by one implementation is
decryptable by another. The core-level harness proves that for the cores. What
it cannot prove is that the bytes an *adapter* puts in a column are those bytes,
because the decisions between an application value and the stored column belong
to the adapter and to nothing the cores test — the codec's rendering, the
storage form, and how the context is assembled.

So `tests/cross/produce.ts` writes rows through the **real extension** (real
`create()`, runtime CSPRNG, no test-mode injection), reads the raw columns back
through `$queryRawUnsafe`, and emits the standard `fieldseal-vectors/cross/v1`
document that every existing consumer already reads:

```
npm run cross:produce -- --out ../../cross-prisma.json
```

CI adds it to the N×N matrix as one more producer, and the Python core decrypts
it. Prisma carries one decision the other adapters do not: its schema type is
the **storage** type, so the logical type is an `as:` declaration and its
rendering is an adapter choice — the producer exercises all six, plus the base64
storage form, and the test asserts the expected plaintext rather than merely
round-tripping it. A consumer that expected a platform integer encoding or a
locale-aware date would decrypt successfully and read the wrong value, which is
exactly the failure no round trip catches.

---

## Honest limitations

**Types describe the column, not the value.** An encrypted column is declared
`Bytes` because that is what holds the envelope, so Prisma generates
`Uint8Array` for it — while the value you write is a string, an int, or whatever
`as:` declares. **Writes to a `Bytes`-stored encrypted column do not typecheck
against the generated client and need a cast.** Two ways out today: declare the
column `String` with `storage: "base64"`, which typechecks naturally at ~33%
storage cost; or cast the logical value at the write site:

```ts
await prisma.patient.create({
  data: {
    email: "ada@example.com" as never, // Bytes column; the adapter encrypts the string
    plainName: "Ada",
  },
});
```

`as never` rather than `as unknown as Uint8Array`, so the cast reads as "the
generated type is wrong here" and nothing downstream believes the value is
bytes. A generator-emitted typed surface that fixes this properly is a
follow-up, recorded rather than pretended away.

**Storage overhead is real.** A 9-byte value becomes ~120 bytes binary or ~160
bytes base64. Across a 20-column, 100M-row table that is ~220 GB before index
bloat.

**The key service is a hard dependency in the read path.** External key stores
trade security for availability; a KMS outage affects every query touching an
encrypted field.

**Argon2id blind indexes cost 10–100 ms per query term**, and `blindIndex` is
**synchronous** — on Node that blocks the event loop for the duration. Spec
§11.1 permits an async companion and the core does not ship one in v0
(`docs/11` §2). Prefer `hmac-sha512` where the §7.3 domain class permits. This
is a product constraint, not tuning.

**Application caches hold plaintext** (spec §10.2, "All ORMs"). Any cache
sitting outside the extension stores decrypted values.

**Raw SQL parameters are never encrypted**, by any ORM surveyed. The extension
sees an opaque SQL template for `$queryRaw`/`$executeRaw` and cannot tell
whether it touches an encrypted column. `strictRaw: true` refuses them outright.

**Database query logs are in scope as sensitive artifacts.** Blind-index values
appear in logged statements; the ETH Zurich MongoDB QE analysis (USENIX '23)
recovered 40–100% of field values from logs alone, with no client queries.

**No protection against a compromised application process.** The keys are in
that process.

---

## Development

```bash
npm ci
npm run build                    # dist/, and the generator bin
npx prisma generate              # the fixture's Prisma client
node tests/fixture/build.ts      # the fixture's field map
npx prisma db push               # the fixture SQLite database
npm test                         # 209 tests
npm run typecheck
```

`@fieldseal/core` is a `file:` dependency on this repository's own core, so the
adapter is verified against the core it ships beside, not against a release.
`core/typescript` must be built first — its `dist/` is gitignored.
