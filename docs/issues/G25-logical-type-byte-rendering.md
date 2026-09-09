# G25 — nothing pins what bytes a logical type becomes, and the two adapters already disagree about `boolean`

**Labels:** §3 · §12 · docs/09 §7 · docs/12 §2 · docs/13 §1 · spec-gap
**Blocks:** No envelope byte, no derived value, no error code. It blocks the **central claim** for one logical type: a `boolean` column written through the Django adapter cannot be read through the Prisma adapter, or the reverse. Both adapters are conformant to the specification as written, and they disagree.
**Found:** 2026-09-08, while planning the M5 / WS-G demonstration app — specifically while deciding which column types its shared model could safely use.

## Gap

Spec §3 pins the **byte layer**: envelope layout, AAD, commitment, and the exact bytes of every derivation. Nothing in the specification pins the **logical-type-to-plaintext rendering** — what bytes an application value becomes before it is encrypted. That decision belongs to an adapter, both shipped adapters make it, and they make it differently.

Measured 2026-09-08 through each adapter's real codec (`adapters/django/src/fieldseal_django/codec.py`, `adapters/prisma/src/codec.ts`):

| logical type | Django writes | Prisma writes |
|---|---|---|
| `boolean` | `b"True"` | `b"true"` |
| `datetime` | `b"2026-09-08 12:00:00+00:00"` | `b"2026-09-08T12:00:00.000Z"` |
| `int` | `b"42"` | `b"42"` |
| `float` | `b"1.5"` | `b"1.5"` |
| `string`, `bytes` | UTF-8 / passthrough | UTF-8 / passthrough |

Cross-reading those same bytes:

| | Django reads Prisma's | Prisma reads Django's |
|---|---|---|
| `boolean` | raises `ValidationError` (`"true" value must be either True or False`) | throws `FieldsealNotSupported` |
| `datetime` | OK, correct value | OK, correct value |

**`boolean` is a live interoperability defect, and it fails loudly in both directions.** Neither codec coerces; each refuses. That is the designed behaviour and it is the right one — `codec.ts` says so where it does it: *"returning a coerced value would hide it."* So this is an **availability/interoperability** defect, not a silent-wrong-answer defect, and it does not belong in §10.2's wrong-answer class.

**`datetime` round-trips today, and the reason it does is worth naming.** V8 accepts Django's `"2026-09-08 12:00:00+00:00"` and Django's `DateTimeField.to_python` accepts Prisma's ISO-8601 — but a non-ISO-8601 string is **implementation-defined** in ECMA-262 §21.4.3.2, so the Prisma direction rests on a V8 behaviour no standard requires. Latent, not live.

**Why no existing test catches it.** The N×N cross harness moves a document of the form `{plaintext, envelope, context}` between implementations, and a consumer decrypts the envelope and compares against *the producer's own recorded plaintext*. Every producer therefore grades its own homework at the logical-value layer. Nothing asks "would the **other adapter** have produced these bytes for this value?" — which needs an adapter↔adapter comparison the produce/consume shape cannot express. `docs/14` §3 names the codec as "the adapter decision no core test can see" and then does not test it across adapters.

**The Django codec also documents an assumption it is not keeping.** Its module docstring says the encoding is *"Django's own `value_to_string` contract wherever it exists"*; the implementation uses `get_prep_value()` then `str()`, which for `DateTimeField` produces a different string than `value_to_string()` does. That doc/code drift belongs in the same resolution.

## Proposed direction

Starting point for discussion, not a decision:

1. **A normative table**, in the specification, giving the exact byte rendering of each logical type in the adapter vocabulary — `string`, `int`, `float`, `boolean`, `datetime`, `bytes` — with the same precision §3 gives the envelope. Candidates worth stating rather than assuming one: lowercase `true`/`false` (Prisma's, and JSON's); RFC 3339 with a `Z` and millisecond precision (Prisma's).
2. **Or an explicit refusal to standardize**, which is a real option and must be stated as one: adapters would then MUST refuse `boolean` and `datetime` columns until a suite pins them, rather than each rendering its own way. That is a worse product and an honest specification.
3. **Vectors** for whatever is chosen, in a family that pins plaintext bytes per logical type — because a normative change without vectors cannot be verified across implementations, and this is precisely a cross-implementation claim.
4. **The Django codec's docstring** is corrected to describe what it does, whichever way (1) resolves.

**Do not resolve this by editing one adapter to match the other.** Which rendering is right is the question. Either edit is a change to the plaintext bytes of every row already written, which under §7.8's reasoning is a **backfill**, not an edit.

## What breaks

Nothing today, because nothing is frozen and no `boolean` column exists in either adapter's cross-language surface — the Prisma fixture has one, the Django fixture does not, and no cross case pairs them. Once resolved, whichever adapter does not already match the chosen rendering has a plaintext encoding change, which is a backfill for any deployment that has written such a column.

The M5 / WS-G demonstration app is constrained by this gap rather than blocked by it: its shared model uses `string`, `int` and `bytes` only, and `examples/patient-directory/check_declarations.py` refuses any other inner type with this issue's reason in the failure message.

## Vector obligations

**Yes, and they are the point.** A logical-type rendering table is exactly the kind of claim the vector suite exists to verify: a family pinning, per logical type, the plaintext bytes an adapter must produce for a given application value. Unlike G19/G20/G21 — adapter obligations over *query shapes*, which vectors cannot express — this one is bytes, and belongs in vectors rather than in per-adapter tests. Without it the same divergence returns the first time a third adapter is written.

## Cryptographic review

**No — no bearing on any Gate 0b question.** The decision is about the encoding of a value *before* it reaches the core, upstream of every cryptographic operation; no construction, key derivation, or envelope byte changes. It needs a decision, not a cryptographer.
