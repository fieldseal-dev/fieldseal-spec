# @fieldseal/prisma

Transparent field-level encryption at rest for Prisma. Design:
[`docs/13-adapter-prisma.md`](../../docs/13-adapter-prisma.md).

**Status: L1, and not usable in production.** Values encrypt and decrypt
transparently and blind-index siblings are derived on write. The **L2 query
path is not in this release** — the index rewrite and the spec §7.5
re-verification that makes it correct land together, because a rewrite without
re-verification returns collision rows as matches. Until then, equality on an
encrypted column is **refused**, not approximated. Nothing here is frozen: the
suite identifier is provisional (spec §4.8), Gate 0b is open, and the project
does not invite adoption.

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

## Coverage matrix

What the code does **today**, each row verified by the test named in it — not
the target matrix in `docs/13` §6.

| Path | Behaviour | Test |
|---|---|---|
| `create`, `createMany`, `update`, `updateMany` | ✅ encrypts; index sibling derived | `round-trips the plaintext…`, `encrypts through createMany and updateMany` |
| Nested relation writes (`create`, `connectOrCreate`, `upsert`, nested `update`) | ✅ reached through the relation graph, not path patterns | `encrypts a nested relation write…` |
| Database holds an envelope, never plaintext | ✅ | `stores an envelope in the database…` |
| Repeated writes of one value | ✅ fresh nonce + `msg_seed` each time (spec §4.4) | `writes a different envelope every time…` |
| `update` re-encrypts | ✅ including the `{ set: … }` form | `re-encrypts on update…`, `accepts the { set: value } update form` |
| `update` with `increment`/arithmetic | 🛑 refused — the database would compute on an envelope | `refuses an arithmetic update…` |
| Reads, including `include` nesting | ✅ decrypts recursively | `encrypts a nested relation write…` |
| Non-ASCII values | ✅ round-trip byte-for-byte | `round-trips a non-ASCII value…` |
| Empty string | ✅ a value, not an absence | `treats the empty string as a value…` |
| `NULL` | ✅ stays NULL; its index is NULL too | `stays NULL rather than becoming an envelope` |
| Non-text logical types (`as: "int"`, …) | ✅ round-trip as their own type | `reads an explicit \`as\`` |
| A value that does not match the declared `as:` | 🛑 refused rather than coerced | `refuses a value whose type does not match…` |
| `storage: "base64"` on a `String` column | ✅ ASCII in the column, ~33% overhead | `round-trips through a String column…` |
| Blind index written on insert | ✅ deterministic, case-folded, `ceil(b/8)` bytes | `is derived on write…`, `folds case…` |
| Index sibling in results | ✅ stripped unless `exposeIndexColumns` | `is stripped from returned objects…` |
| A hand-written index value | 🛑 refused — those bytes are derived | `refuses a hand-written index value` |
| Tenant-bound column, no tenant | ✅ refuses the write | `refuses the write when no tenant is resolvable` |
| Wrong tenant reading a row | ✅ raises — the binding is cryptographic, not a filter | `cannot be read under a different tenant…` |
| Tampered ciphertext | ✅ raises; never returns garbage | `raises rather than returning garbage` |
| **`where` equality / `in` on an encrypted column** | 🛑 **refused in this release** — L2 rewrite + §7.5 re-verification land together | `refuses rather than comparing against a randomized envelope` |
| `contains`, `startsWith`, `endsWith`, `lt`/`gte`, `search` | 🛑 refused (spec §7.1, §4.7) | `refuses \`contains\`…` (8-way sweep) |
| `mode: "insensitive"` | 🛑 refused — the column has exactly one equality (G19) | `refuses \`mode: insensitive\`…` |
| `not`, `notIn` | 🛑 refused — an exclusion's false negatives are unrecoverable | `explains notIn as an exclusion asymmetry…` |
| An unrecognised filter operator | 🛑 hard error — fails closed, never passed through | `fails closed on an operator it does not recognise` |
| Filtering the index sibling directly | 🛑 refused — cannot re-verify a filter it did not construct | `refuses a filter on the index sibling directly` |
| `findUnique` on an encrypted column or its sibling | 🛑 refused — neither can be unique (spec §7.10) | `refuses findUnique on an encrypted column…` |
| `orderBy` over an encrypted column | 🛑 refused (G20) — sorts envelope bytes | `refuses orderBy…` |
| `distinct`, `groupBy.by`, `having` over one | 🛑 refused (G20) — one group per row, wrong counts | `refuses distinct…`, `refuses groupBy…` |
| `_min`/`_max`/`_sum`/`_avg` over one | 🛑 refused (G20) — computes on bytes | `refuses aggregates…` |
| `cursor` on an encrypted column | 🛑 refused — ciphertext has no stable total order | `refuses cursor pagination…` |
| Plaintext columns of the same model | ✅ untouched — filter, sort and group normally | `leaves filters on plaintext columns…`, `leaves orderBy and groupBy…` |
| `count()` over rows | ✅ counts rows, reads no bytes | `allows _count over rows…` |
| Raw SQL (`$queryRaw`, `$executeRaw`) | ⚠️ passthrough + hook (default) / 🛑 `strictRaw` | `passes through with a hook…`, `throws under strictRaw` |
| Malformed declaration | 🛑 fails `prisma generate` | `fails the generate on a malformed declaration…` |
| `on_unindexable: "bucket"` without the §7.2 ceremony | 🛑 refused at construction | fixture supplies it; see `helpers.ts` |
| **Cross-language: a row written here, read by another core** | ❌ not yet — the cross producer is the next increment | — |
| `row_id` binding (L3-row) | ❌ not in v0 | — |
| L4 (`warm()` in the value path) | ❌ next increment | — |

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

## Honest limitations

**Types describe the column, not the value.** An encrypted column is declared
`Bytes` because that is what holds the envelope, so Prisma generates
`Uint8Array` for it — while the value you write is a string, an int, or whatever
`as:` declares. **Writes to a `Bytes`-stored encrypted column do not typecheck
against the generated client and need a cast.** Two ways out today: declare the
column `String` with `storage: "base64"`, which typechecks naturally at ~33%
storage cost; or cast. A generator-emitted typed surface that fixes this
properly is a follow-up, recorded rather than pretended away.

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
npm test                         # 99 tests
npm run typecheck
```

`@fieldseal/core` is a `file:` dependency on this repository's own core, so the
adapter is verified against the core it ships beside, not against a release.
`core/typescript` must be built first — its `dist/` is gitignored.
