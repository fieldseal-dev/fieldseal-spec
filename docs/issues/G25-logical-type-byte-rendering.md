# G25 — nothing pins the logical-type → plaintext rendering: a date rewritten through the other adapter becomes unreadable to the first, a decimal loses precision silently, and a boolean cannot cross at all

**Labels:** §3 · §10.2 · §12 · docs/09 §7 · docs/12 §2 · docs/13 §1 · spec-gap
**Blocks:** No envelope byte, no derived value, no error code. It blocks the **central claim** for three of the six logical types in the adapter vocabulary, in three different failure classes — one loud, one asymmetric-then-fatal, one silent.
**Found:** 2026-09-08, while planning the M5 / WS-G demonstration app — deciding which column types its shared model could safely use. Extended 2026-09-09 with the `date` and `Decimal` measurements after the boolean case was correctly challenged as unlikely to occur in practice.

## Gap

Spec §3 pins the **byte layer**: envelope layout, AAD, commitment, and the exact bytes of every derivation. Nothing in the specification pins the **logical-type-to-plaintext rendering** — what bytes an application value becomes before it is encrypted. That decision belongs to an adapter, both shipped adapters make it, and they make it differently. The adapter vocabulary itself (`string`, `int`, `float`, `boolean`, `datetime`, `bytes`) is also unspecified: it exists in `docs/13` §1 as a Prisma `as:` declaration and nowhere normative, and it has no entry for a **decimal**.

Measured through each adapter's real codec (`adapters/django/src/fieldseal_django/codec.py` on Django 6.1 / CPython 3.14.6, `adapters/prisma/src/codec.ts` on Node v24.16.0), 2026-09-08 and 2026-09-09:

| value | Django writes | Prisma writes |
|---|---|---|
| `date(2026, 9, 8)` | `b"2026-09-08"` | `b"2026-09-08T00:00:00.000Z"` (there is no `as: "date"`; the nearest declaration is `datetime`) |
| `datetime(2026, 9, 8, 12, 0, tz=utc)` | `b"2026-09-08 12:00:00+00:00"` | `b"2026-09-08T12:00:00.000Z"` |
| `Decimal("1.50")` | `b"1.50"` | no `as: "decimal"` exists; the nearest declaration is `float`, which writes `b"1.5"` |
| `True` | `b"True"` | `b"true"` |
| `1.5`, `42`, text, bytes | agree | agree |

**The three failure classes, in the order they matter.**

### 1. `date` — silent on the way in, fatal on the way back (asymmetric)

Composed from three measurements, each taken separately:

- Prisma reads Django's `b"2026-09-08"` and **succeeds**, returning a JavaScript `Date` — an *instant* at UTC midnight, where the stored value was a calendar date. `new Date("2026-09-08")` is well-defined here; the ISO date-only form is specified.
- Re-writing that value — an ordinary read-modify-write, which is what an application does — renders `b"2026-09-08T00:00:00.000Z"`.
- Django then reads that and **raises**: `ValidationError: "2026-09-08T00:00:00.000Z" value has an invalid date format. It must be in YYYY-MM-DD format.`

So **a single ordinary write through the Prisma stack renders a row permanently unreadable to the Django stack**, with nothing raised at the moment the damage is done. That is a strictly worse shape than the boolean below, which fails loudly on first contact and damages nothing.

There is a second consequence in the same conversion, before any rewrite: a calendar date has no timezone and an instant does. `new Date("2026-09-08")` is UTC midnight, so **any local-time rendering of it west of UTC is the previous day** — observed while measuring, on a GMT-0500 machine, as `Mon Sep 07 2026 19:00:00`. An encrypted date of birth is a canonical field for this specification, and it is off by one day for a large fraction of the world the moment it is read through the other stack.

### 2. `Decimal` — no vocabulary entry, so precision is lost silently

There is no `as: "decimal"`. An encrypted `DecimalField` — money, dosages, lab results — has to be declared `as: "float"` on the Prisma side, which is an IEEE-754 double. Measured, with the re-write that persists the damage:

| Django writes | Prisma reads | Prisma re-writes |
|---|---|---|
| `b"1.50"` | `1.5` | `b"1.5"` — scale lost |
| `b"12345678901234567.89"` | `12345678901234568` | `b"12345678901234568"` — **value changed** |
| `b"99999999999999999999.01"` | `100000000000000000000` | `b"100000000000000000000"` — **value changed** |

Nothing raises in either direction. The envelope is authentic, the key is right, the commitment verifies, and the number is wrong. This is the silent-wrong-answer class that spec §10.2 exists to prevent everywhere else, arriving through the one door §10.2 does not cover — the codec rather than the query.

Django's own scale is preserved on its own path (`Decimal("1.50")` → `b"1.50"` → `Decimal("1.50")`), so this is purely a cross-adapter loss.

### 3. `boolean` — loud, in both directions, and the least important of the three

| | Django reads Prisma's `b"true"` | Prisma reads Django's `b"True"` |
|---|---|---|
| result | raises `ValidationError` (`"true" value must be either True or False`) | throws `FieldsealNotSupported` |

Neither codec coerces; each refuses. That is the designed behaviour and it is the right one — `codec.ts` says so where it does it: *"returning a coerced value would hide it."* So `boolean` is an **availability/interoperability** defect, not a wrong-answer one, and it does not belong in §10.2's wrong-answer class.

It is also unlikely to be reached. **An encrypted boolean cannot be blind-indexed at all**: `projected_population` has a hard floor of 16 (spec §7.4; `blindindex.py:346`) and the §7.6 override relaxes only the 2¹⁰ gate, not that floor — so a two-valued column is refused at construction with no ceremony available, making it a column that can never be filtered on. This issue originally led with `boolean` because it is the case that breaks *today*; that was the wrong emphasis, and the two above are the reason the gap is worth closing.

### Why no existing test catches any of it

The N×N cross harness moves a document of the form `{plaintext, envelope, context}` between implementations, and a consumer decrypts the envelope and compares against *the producer's own recorded plaintext*. Every producer therefore grades its own homework at the logical-value layer. Nothing asks "would the **other adapter** have produced these bytes for this value?" — which needs an adapter↔adapter comparison the produce/consume shape cannot express. `docs/14` §3 names the codec as "the adapter decision no core test can see" and then does not test it across adapters.

### A doc/code drift in the same area

The Django codec's module docstring says the encoding is *"Django's own `value_to_string` contract wherever it exists"*; the implementation uses `get_prep_value()` then `str()`, which for `DateTimeField` produces a different string than `value_to_string()` does. That belongs in the same resolution.

## Proposed direction

Starting point for discussion, not a decision:

1. **A normative vocabulary and a normative rendering table**, in the specification, with the precision §3 gives the envelope: for each logical type, the exact byte rendering. The vocabulary needs at least one addition (`decimal`) and probably a `date` distinct from `datetime`, because the two measured defects above are both cases where an adapter had no faithful declaration available and reached for the nearest one.
2. **Or an explicit refusal to standardize**, which is a real option and must be stated as one: adapters would then MUST refuse the types no suite pins, rather than each rendering its own way. Cheaper, honest, and strictly better than the status quo — a refused column is a schema change; a corrupted decimal is not recoverable.
3. **§10.2 gains the codec as a named site.** Its wrong-answer rule is written entirely about *query* shapes. The `Decimal` case is a wrong answer that never touches a query.
4. **Vectors** for whatever is chosen, pinning plaintext bytes per logical type.
5. **The Django codec's docstring** corrected to describe what it does.

**Do not resolve this by editing one adapter to match the other.** Which rendering is right is the question. Either edit is a change to the plaintext bytes of every row already written, which under §7.8's reasoning is a **backfill**, not an edit.

## What breaks

Nothing today: no `date`, `Decimal` or `boolean` column exists in either adapter's cross-language surface, and nothing is frozen. Once resolved, whichever adapter does not already match the chosen rendering has a plaintext encoding change, which is a backfill for any deployment that has written such a column.

The forward-looking half is the larger cost. Five adapters are unwritten. Each will choose a rendering for every logical type it supports, and each choice becomes a backfill once it ships. The `Decimal` case shows the shape of what happens when an adapter has no faithful declaration to reach for.

The M5 / WS-G demonstration app is constrained by this gap rather than blocked by it: its shared model uses `string`, `int` and `bytes` only, and `examples/patient-directory/check_declarations.py` refuses any other inner type with this issue's reason in the failure message.

## Vector obligations

**Yes, and they are the point.** A logical-type rendering table is exactly the kind of claim the vector suite exists to verify: a family pinning, per logical type, the plaintext bytes an adapter must produce for a given application value. Unlike G19–G24 — adapter obligations over *query shapes*, which vectors cannot express — this one is bytes, and belongs in vectors rather than in per-adapter tests. Without it the same divergence returns the first time a third adapter is written.

## Cryptographic review

**No — no bearing on any Gate 0b question.** The decision is about the encoding of a value *before* it reaches the core, upstream of every cryptographic operation; no construction, key derivation, or envelope byte changes. It needs a decision, not a cryptographer.
