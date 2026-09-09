# patient-directory — one Postgres table, two languages

**This exists to prove one claim, not to be forked.** A row written through the
Django adapter is read, searched and matched by the Prisma adapter, and the
other way round, with a shared Postgres database as the only channel between
them. If you are looking for a starter template, this is not one: the model has
four columns, the keys are public test material, and the suite it writes under
is provisional.

**Status: a demonstration, and not usable in production.** Nothing here is
frozen — the suite identifier is provisional (spec §4.8), Gate 0b (independent
cryptographic review) is open, and the project does not invite adoption. The
key material comes from `vectors/keys/test-keys.json`, which says of itself:
*"No value here may ever be used outside a test."*

The design and the reasoning behind each decision are in
[`docs/20-demo-patient-directory.md`](../../docs/20-demo-patient-directory.md).

---

## What it asserts

Seven acts, each a separate process invocation, in the order they appear in the
narration. **The database is the only channel between the two stacks** — nothing
passes a value in memory from one to the other, and nothing reads a file the
other wrote, or the demo would be asserting something about its own memory
rather than about bytes in a column.

| Act | Step | What it proves |
|---|---|---|
| 1 | Django writes `ada@example.com` | the value path encrypts; the plaintext is not a substring of the column |
| 2 | Prisma reads that row | **the central claim**, at the layer people deploy |
| 3 | Prisma searches by email | the blind index Python derived is derivable by TypeScript — the failure that raises nothing |
| 4 | Prisma writes; Django reads and searches | the claim in the other direction, both halves |
| 5 | Both stacks write the same plaintext | headers identical, ciphertexts different, **blind indexes byte-equal** |
| 6 | Django `exclude(…)`; Prisma `count({where})` | adapters throw rather than degrade — and the capability difference between them is designed |
| 7 | Raw SQL through `psycopg` | what the DBA sees: no plaintext anywhere; the index is two bytes |

**Act 5 is the one worth the exercise.** Acts 1–2 restate what the N×N
`cross-produce` job already proves by moving a JSON document between
implementations. Act 5 is what no job covers: two independent writers, in two
languages, writing one value into one table, and the three things that must
then be true at once.

**Nothing asserts an exact ciphertext.** Every envelope carries a fresh nonce
and `msg_seed` (spec §3.1, §4.4), and the fixed-nonce affordance that would make
one reproducible is a test-mode-only facility an implementation must never
accept outside it. The assertions are structural: envelope *length*, the
19-byte header two writers must share, the inequality of two envelopes over one
plaintext, the byte-equality of two blind indexes, and the absence of the
plaintext as a substring.

## Running it

Postgres 17, Python 3.12+, Node 24.7+. From the repository root:

```
# the two stacks, from this checkout rather than from an index
pip install -e "./core/python[argon2]" -e "./adapters/django[dev]" "psycopg[binary]"
(cd core/typescript && npm ci && npm run build)
(cd adapters/prisma && npm ci && npm run build)

export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/fieldseal_demo

cd examples/patient-directory
(cd prisma && npm ci && npx prisma generate)     # Prisma only ever generates
(cd django && python manage.py migrate)          # Django owns the DDL

python check_declarations.py       # do the two stacks declare the same column?
python run_scenario.py             # the seven acts, with narration
python check_transcript.py transcript/
python check_schema_shape.py       # do they agree on the table's shape?
```

`python run_scenario.py --check` additionally diffs the narration against
`expected-narration.txt`. That is only meaningful because the narration is
deterministic: row ids are passed explicitly, envelope lengths are a function of
plaintext length, blind index values are a function of the key and the value,
and the envelope header is fixed by the suite and the key id. Nothing random is
printed. If a change makes the narration legitimately different,
`--write-expected` and commit the diff — the diff is the review artifact.

## The two declarations, and the checker between them

The same table is declared twice: in
[`django/directory/models.py`](django/directory/models.py) and in
[`prisma/schema.prisma`](prisma/schema.prisma). Two rules keep them honest.

**Django owns the DDL; Prisma only ever runs `prisma generate`.** The migration
is load-bearing for the crypto identity and not just for the table — spec §6.1
binds key derivation to `column_uuid`, and `Encrypted.deconstruct()` exists so
that identifier survives into a committed migration file. `prisma db push`
reaches a target state by dropping and recreating columns, which against a
table Django believes it owns is a data-loss path behind a friendly prompt.

**Prisma's names are canonical and Django wears the mapping.** The generated
field map has no representation of `@map`/`@@map`, so a mapping on the Prisma
side would be invisible to a program; Django exposes `db_table` and `column` on
every field. With no mapping in the schema, `(model, field)` **is**
`(table, column)`, which is what lets `check_declarations.py` compare physical
names without parsing the `.prisma` file.

`check_declarations.py` joins the two declarations on `column_uuid` — the
column's immutable identity under spec §6.1 — and compares everything else. It
is a **diagnostic, not the proof**: declaring the same UUID does not prove
either stack uses it. What it buys is that a drift fails with a message naming
the drifted parameter, instead of surfacing as `COMMITMENT_INVALID` forty lines
into the narration, or — for an index parameter — as nothing at all.

## Honest limitations

- **Three logical types, not six.** The shared model uses `string`, `int` and
  `bytes` only. `boolean` and `datetime` are excluded because they do **not**
  round-trip between these two adapters: Django's codec renders `True` as
  `b"True"` and Prisma's renders it as `b"true"`, and each side refuses the
  other's rendering rather than coercing it. `datetime` does round-trip today,
  but only because V8 accepts Django's `"…12:00:00+00:00"` form, which
  ECMA-262 §21.4.3.2 leaves implementation-defined. The root cause is a
  specification gap rather than an adapter bug — spec §3 pins the byte layer
  and nothing pins the logical-type-to-bytes rendering — so it is not fixed
  here; which rendering is right is a normative question. `check_declarations.py`
  refuses any other inner type, so the restriction is a tripwire rather than a
  comment.
- **`npm ci` here is not a supply-chain claim.** Both fieldseal packages are
  `file:` dependencies, and npm records those with `"link": true` and no
  integrity hash. What the lockfile pins is the resolution, not the bytes.
- **Every write to a `Bytes`-stored column needs a cast** on the Prisma side
  (`scenario.ts` says so where the casts are). An encrypted column is declared
  `Bytes` because that is what holds the envelope, so the generated client types
  it `Uint8Array` while the value written is a string. `storage: "base64"`
  avoids it at ~33% storage overhead (spec §3.3).
- **No L3 tenant binding and no L4.** Both are orthogonal to the claim, both
  adapter suites already cover them, and Django cannot do L4 at all — a demo
  using it would show an asymmetry that is a property of Django rather than of
  fieldseal.
- **No benchmark numbers.** If a timing prints, it prints with no claim
  attached; the benchmark programme is Phase 2 (`docs/07` §8).
- **The two stacks warn differently about the key provider.** The TypeScript
  core emits a `static-key-provider` warning on every client it builds; the
  Python core does not have an equivalent. The Prisma acts record theirs in the
  transcript and `check_transcript.py` requires it — which makes "this is not a
  production configuration" a checked fact rather than a sentence here.

## Development

```
python -m ruff check .                       # lint, from this directory
(cd prisma && npx tsc -p tsconfig.json --noEmit)
```

There is no `mypy` gate. The adapters are libraries and are held to
`--strict`; this is an application whose Python surface is almost entirely
Django's, and Django ships no `py.typed` — so the check would be comparing
`Any` with `Any`. The TypeScript half *is* checked, because Prisma's generated
client is typed and the check is therefore real.

The migration is excluded from `ruff` (see `ruff.toml`): it is written by
`makemigrations`, and what guards it is `makemigrations --check --dry-run` in
CI, which fails if it stops matching the models.

CI runs all of the above as the `demo` job in
[`.github/workflows/conformance.yml`](../../.github/workflows/conformance.yml),
against the same digest-pinned Postgres image the adapter jobs use, and uploads
the transcript as an artifact.
