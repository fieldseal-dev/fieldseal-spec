# The Patient-Directory Demonstration — two stacks, one Postgres table

**Date:** 2026-09-09 · **Status:** Draft 1 · **Purpose:** design and reasoning for the Phase 1 demonstration application (`docs/07` §2, WS-G): a Django frontend and a Prisma frontend over one shared Postgres schema, and a scripted scenario asserting that a row written by either stack reads, searches and matches from the other. The code is [`examples/patient-directory/`](../examples/patient-directory/).

This project is pre-alpha, the specification has not been independently reviewed, and nothing here is an invitation to adopt it. The demonstration uses public test key material and a **provisional** suite identifier (spec §4.8). It exists to make one claim checkable by a person; it is not a starter template.

---

## 1. Why a demo is an assertion and not a presentation

The plan for this workstream framed the demo as presentational — the CI cross jobs already prove the central claim row by row, and the demo makes it demonstrable to a human. That undersells it, and planning the demo proved so.

The existing N×N `cross-produce` / `cross-consume` jobs move a **JSON document** between implementations: a producer records `{plaintext, envelope, context}`, and a consumer decrypts the envelope and compares against the producer's own recorded plaintext. That is a real and load-bearing test, and it has a shape: **every producer grades its own homework at the logical-value layer.** Nothing in it asks whether the *other* adapter would have produced those bytes for that value, and nothing in this repository had ever pointed two adapters at one live database or compared the two declarations of the same column.

Planning that comparison found a live interoperability defect in ten minutes — the two adapters render `boolean` differently, and each refuses the other's rendering — which is now [G25](issues/G25-logical-type-byte-rendering.md) ([#123](https://github.com/fieldseal-dev/fieldseal-spec/issues/123)). §7 below says what the demo does about it.

## 2. What it asserts

Seven acts, each a separate process invocation. **The database is the only channel between the two stacks**: nothing passes a value in memory from one to the other and nothing reads a file the other wrote, or the demo would be asserting something about its own memory rather than about bytes in a column. Each act appends a JSON transcript entry; `check_transcript.py` asserts the shape of the whole run.

| Act | Step | What it proves |
|---|---|---|
| 1 | Django writes `ada@example.com` | the value path encrypts; the plaintext is not a substring of the column |
| 2 | Prisma reads that row | **the central claim**, at the layer people deploy |
| 3 | Prisma searches by email | the blind index Python derived is derivable by TypeScript — the failure that raises nothing |
| 4 | Prisma writes; Django reads and searches | the claim in the other direction, both halves |
| 5 | Both stacks write the same plaintext | headers identical, ciphertexts different, **blind indexes byte-equal** |
| 6 | Django `exclude(…)`; Prisma `count({where})` | adapters throw rather than degrade, and the capability difference between them is designed |
| 7 | Raw SQL through `psycopg` | what the DBA sees: no plaintext anywhere; the index is two bytes |

**Act 5 is the one worth the exercise.** Acts 1–2 restate what `cross-produce` already proves through a document. Act 5 is what no job covers: two independent writers, in two languages, writing one value into one table, with three things that must then be true at once — the 19-byte envelope header identical (same format version, same suite, same key id), the envelopes themselves different (a fresh nonce and `msg_seed` per write, spec §4.4), and the two blind indexes byte-equal. The whole architecture in one act: what is shared is shared, what must vary varies, and what makes cross-stack lookup work is the one derived value that agrees.

**Act 6 shows a real capability difference and says it is designed.** Django serves `filter(email=…).count()` because a manager can materialize the §7.4 candidate bucket and re-verify it (spec §7.5) before counting. The Prisma extension refuses the same call, because `query` is bound to the operation it was called for and an operation whose result is a number cannot be turned into a row fetch. Both stacks refuse negation, for the reason G24 settled: a filter's false positives are recoverable and an exclusion's false negatives are not.

### 2.1 Nothing asserts an exact ciphertext

Every envelope carries a fresh nonce and `msg_seed` (spec §3.1, §4.4), and the fixed-nonce affordance that would make one reproducible is a test-mode-only facility an implementation must never accept outside it. So the assertions are structural: envelope *length* (spec §3.1 fixes suite `0xFF01`'s overhead at 111 bytes, so length is a function of the plaintext's length and nothing else); the 19-byte header two writers must share; the inequality of two envelopes over one plaintext; the byte-equality of two blind indexes; and the absence of the plaintext as a substring. Randomness appears as lengths and inequalities, never compared against a literal.

That is also what makes the narration reproducible, and `run_scenario.py --check` diffs the whole of it against a committed `expected-narration.txt`, in the shape of the `vectors-reproducible` and `ucd-gen --check` jobs.

## 3. The shared schema — one table, two declarations

**Django owns the DDL. Prisma only ever runs `prisma generate`.** Three reasons, strongest first:

1. **The migration is load-bearing for the crypto identity, not just for the table.** Spec §6.1 binds key derivation to `column_uuid`, and `Encrypted.deconstruct()` exists precisely so that identifier survives into a committed migration file — which is what makes a rename safe. The Django adapter's own test suite builds its schema straight from the models through `pytest-django` and never runs the migration machinery that every real deployment hits first; this demo is therefore also the first exercise of it.
2. `prisma db push` is a prototyping tool: it reaches a target state by dropping and recreating columns. Pointed at a database Django believes it owns, that is a data-loss path behind a friendly prompt.
3. The asymmetry is real. Django *must* believe it owns the table — its alternatives are `--fake-initial`, a lie it then cannot detect, or nothing — while Prisma is perfectly happy not to.

Hand-written SQL is the worst of the three: `makemigrations` would still be required, so there would be *three* declarations of one schema.

**Prisma's names are canonical and Django wears the mapping** (`db_table`, `db_column`), with no `@map`/`@@map` anywhere. The reason is mechanical: the generated field map has no representation of a physical-name mapping, so a mapping on the Prisma side would be invisible to any program reading it, while Django exposes `db_table` and `column` on every field. With no mapping in the schema, `(model, field)` **is** `(table, column)` — which is what lets the checker in §4 compare physical names without parsing the `.prisma` file. The cost is mixed-case Postgres identifiers, which must be quoted in hand-written SQL; both ORMs always quote, and the demo's raw-SQL act quotes.

**The model is four columns**, one of them plaintext. A table where everything is encrypted hides the thing the demo is about — the encrypted columns have to look different from an ordinary one in act 7, and there has to be an ordinary one to look different from.

Deliberate omissions, each for a reason: no `boolean` or `datetime` column (§7); no `unique` (Django emits `ALTER TABLE … ADD CONSTRAINT` where Prisma emits `CREATE UNIQUE INDEX` — identical in `pg_indexes`, different in `information_schema.table_constraints`, and a demo needs no uniqueness); no timestamp column (Django emits `timestamptz`, Prisma `timestamptz(6)`, and timestamps make the narration non-deterministic — two problems, no value); no tenant-bound column (L3 is orthogonal to the claim and both adapter suites cover it); and no `@default(uuid())` on the Prisma id, because both stacks pass ids explicitly, which removes the one assumption §5's comparison would otherwise rest on.

## 4. The identifier tripwire

`check_declarations.py` compares the two declarations, **joined on `column_uuid`** — spec §6.1's immutable column identity — with every other field as a comparison rather than a key.

The failure it prevents has no error message worth reading. A `column_uuid` that differs between the two declarations surfaces as `COMMITMENT_INVALID` on read: a decrypt-side error for a write-side configuration mistake, raised arbitrarily far from the cause. An *index* declaration that differs is worse — it raises nothing at all. The row is stored, it is decryptable, and it simply stops being findable by the other stack.

| Divergence | Consequence, named in the failure message |
|---|---|
| same `column_uuid`, different `table_uuid` | undecryptable rows |
| same `column_uuid`, different index declaration | silent lookup miss, naming the parameter |
| `column_uuid` on one side only | one stack cannot see a column the other writes |
| same `column_uuid`, different physical `(table, column)` | two stacks pointed at different columns while claiming one identity |

**Both sides are resolved rather than as-written.** Prisma's side is the field map its generator emitted at `prisma generate`; Django's is a runtime dump through the adapter's own accessors. An `ast` parse of `models.py` would be exactly the mistake the Django adapter's E006 check names in its own rationale: comparing as-declared inputs lets two declarations that agree textually and differ operationally register as a match.

**What it is not:** a *diagnostic*, not the proof. Declaring the same UUID does not prove either stack uses it — the scenario proves that, by moving bytes through the database. The tripwire exists so that a drift fails with a message naming the drifted parameter instead of surfacing as `COMMITMENT_INVALID` forty lines into the narration.

## 5. Agreeing on the shape, not only the identifiers

`check_schema_shape.py` asks Prisma what DDL it would emit for its own schema and diffs that against the database Django's migration built.

**`prisma migrate diff` against the live database does not work as a gate, and the obvious form of it is a trap.** Pointed at the real database, Prisma sees `django_migrations`, which it does not declare, and reports a permanent diff. Declaring that table in the Prisma schema introduces a *second* permanent diff: Django 4.1+ emits `bigint GENERATED BY DEFAULT AS IDENTITY` where Prisma's `@default(autoincrement())` emits a sequence.

The workable form takes the diff `--from-empty`, materializes it into a scratch schema, and compares `information_schema.columns` between that and `public` on `(table_name, column_name, data_type, is_nullable, character_maximum_length, numeric_precision)`, plus `pg_indexes.indexdef` modulo the schema qualifier. §3's omissions exist partly to make that comparison clean: every one of those attribute columns is NULL on both sides, so there is no cell where two reasonable tools could legitimately differ. The demo's `INSTALLED_APPS` omits `contenttypes` and `auth` for the same reason — `django_migrations` is then the only table in the database Prisma does not declare, which is a fact small enough to state rather than a filter list.

## 6. CI

One `demo` job in `.github/workflows/conformance.yml`, bringing the conformance workflow to twelve. `examples/**` is added to both `paths:` filters — without it a change touching only `examples/**` triggers no workflow at all, so the demo would silently not gate its own directory. Path filters are per workflow rather than per job, so the demo becomes a gate on core and adapter changes the moment it exists.

**No matrix**, and both candidate axes were considered rather than forgotten. `db: [sqlite, postgres]` would vary a claim the adapter jobs own, and cannot be varied here anyway: SQLite has no `uuid` type, so the one schema the two stacks share could not exist on it. `direction: [django-first, prisma-first]` would be six `if:` guards to reorder steps the scenario already runs in both directions in one pass.

The job installs both stacks from the checkout — never from a registry, because what the demo proves is that these two trees interoperate — asserts the adapter's built entry points exist before the `file:`-linked demo tries to resolve them, runs `makemigrations --check` and `manage.py check --fail-level WARNING` before `migrate`, generates the Prisma client and the field map, and then runs the checker, the acts, the transcript check and the shape check in that order. The transcript is uploaded as an artifact.

## 7. What this cannot demonstrate, and why

**Three logical types, not six.** The shared model uses `string`, `int` and `bytes` only, because `boolean` and `datetime` do not round-trip between these two adapters — [G25](issues/G25-logical-type-byte-rendering.md). Django's codec renders `True` as `b"True"` and Prisma's renders it as `b"true"`; each side refuses the other's rendering rather than coercing it, which is the correct behaviour and is why the defect is loud rather than silent. `datetime` round-trips today only because V8 accepts Django's non-ISO-8601 form, which ECMA-262 §21.4.3.2 leaves implementation-defined.

The restriction is enforced rather than commented: `check_declarations.py` refuses any inner type outside the three, with the reason in the failure message. The demo does not fix the divergence, and must not — which rendering is right is the normative question G25 exists to answer, and either edit is a plaintext encoding change, which under §7.8's reasoning is a backfill rather than an edit.

**No L3 tenant binding and no L4.** Both are orthogonal to the claim, both adapter suites already cover them, and Django cannot do L4 at all — a demo using it would show an asymmetry that is a property of Django rather than of fieldseal.

**No benchmark numbers.** `docs/07` §8 permits a demo's incidental numbers; the benchmark programme is Phase 2. If a timing prints, it prints with no claim attached.

**No web UI and no hosted service** (PRD N4, `docs/07` §8). The entry points are named `scenario.py` and `scenario.ts` rather than `app.py`, and the README's first sentence says the demo exists to prove a claim rather than to be forked. A runnable demo is the most adoption-shaped artifact in this repository while Gate 0b is open, and a banner alone is not sufficient — so the structural safeguards are part of the design: key material is taken from `vectors/keys/test-keys.json` by `key_ref`, so that file's public-test-material banner travels with any copy-paste.

**An example is not an adapter.** AD-1 (spec §11.3) binds adapters to contain no cryptographic code and CI asserts it with a grep over `adapters/*/src`. That grep deliberately does not extend to `examples/`: an application is not an adapter, and extending a normative rule to a new class of thing is a decision that gets an issue first.
