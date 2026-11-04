# Decision note: how every core answers a wrong-typed operand

[#254](https://github.com/fieldseal-dev/fieldseal-spec/issues/254), to-do 3. Follows [PR #256](https://github.com/fieldseal-dev/fieldseal-spec/pull/256) (to-do 1, Python, merged 2026-10-17).

## 1. Status

- **Proposed** in Research on 2026-11-04. It said: `INVALID_ARGUMENT` for a wrong-typed operand on `encrypt`, `decrypt`, `rotate` and `blind_index` in every core and mode; `readonly` keeps `MODE_VIOLATION` first; and `is_ciphertext` returns `false` rather than throwing.
- **Confirmed by the project owner** on 2026-11-04, with refinements. The owner stated the order rule (configuration first, not only "after readonly"), defined bytes per core, put the `rotate` reading in docs/09, noted that the `is_ciphertext` fix is a code change in two cores, and chose the pin mechanism. Every point below is the confirmed answer. The points the owner left open are in §7, each marked as this card's choice.

## 2. The decision

**(a) Order: configuration-derived refusals come before any look at the operand** (docs/18 D-04).

- `encrypt`: `MODE_VIOLATION` → `SUITE_PROVISIONAL` → the operand check (`INVALID_ARGUMENT`) → `LENGTH_EXCEEDED` → the context → recognition and key work. This is the order Python merged in #256.
- `rotate`: the same first two steps, then the operand as `decrypt` reads it.
- `decrypt`: it has no mode gate, so the operand check comes first among the steps docs/09 §3.2 lists.
- The rule is what is pinned. `readonly` answering `MODE_VIOLATION` for any operand follows from it.

**(b) One code, no coercion.** `encrypt`, `decrypt`, `rotate` and `blind_index` refuse a wrong-typed operand with `INVALID_ARGUMENT` in every core and every read mode (`strict`, `permissive`, `readonly`). They never coerce it. `INVALID_ARGUMENT` is the implementation-local argument code docs/09 §9 and §7.1 permit; it is not a spec §9 code, and this card does not change spec §9.

**(c) `blind_index`.** Wrong-typed means neither text nor bytes; text is accepted in every core under docs/09 §7.1. The refusal is never filed in the bucket by `on_unindexable = bucket`.

**(d) `is_ciphertext` is total.** It never raises, and any non-bytes operand (including a null) answers `false`. The principle, stated so #257 can apply it: **the predicate never raises, and it never answers `true` for an operand the operations refuse.**

**(e) The `rotate` reading.** Spec §11.1 says "`rotate` of non-envelope input raises `NOT_CIPHERTEXT`". It is read as bounded by §11.1's bytes signature: an argument outside the signature is outside the operation's domain, so it is `INVALID_ARGUMENT`, not non-envelope input. This is a reading, not spec text, and it is revisitable at Gate 0b. It is recorded in docs/09 §3.5 so the TypeScript and Java implementers can see it without reading the Python tree.

## 3. "Bytes", per core

| Core | Bytes means | Source |
|---|---|---|
| Python | `bytes`, `bytearray`, or a one-dimensional contiguous `memoryview` of format `'B'` | `blindindex.is_byte_string` (#256); `docs/10` §4 |
| TypeScript | `Uint8Array`; `Buffer` is its subclass and is included | `docs/11` §4 |
| Java | a non-null `byte[]` | `docs/27` §4 |

A bytes-typed operand of the wrong **shape** (a wide, strided or multi-dimensional view) is [#257](https://github.com/fieldseal-dev/fieldseal-spec/issues/257)'s question and stays there.

## 4. Out of scope

- **Where `decrypt` validates the context.** The cores differ: TypeScript validates it before recognition, Java after the allow-list, and Python not at all on that path. That belongs to G5 ([#5](https://github.com/fieldseal-dev/fieldseal-spec/issues/5)), to the spin-off issue PR #256 promised and has not filed, and to card 0021. This decision does not choose. docs/09 §3.2 says so explicitly, and its pipeline has no context step.
- **The wrong-shape question** (#257).
- **Any edit to the spec** (`docs/02`).

## 5. Pin mechanism

- **`pinned_decisions.wrong-typed-operand`**, a new key in docs/14 §4's mandatory table. It is **test-backed** under docs/14 §4's rule: its text cites the tests that prove it, and the report generator runs them. If they are missing, did not run, or are red, the report claims no level. The precedent is the Java core's `index-role-use-budget` ([#225](https://github.com/fieldseal-dev/fieldseal-spec/issues/225)). This key is the first test-backed key every core MUST carry.
- **Not an `errors/` entry.** No vector can carry a typed operand, because the suite is hex bytes (docs/08). This is the same representability limit docs/14 §4 records for the lone-surrogate entry, and the same no-vector situation as G17's `key-material-ownership` (`docs/issues/G17-key-material-ownership.md`). For CONTRIBUTING's "vectors" requirement on spec-level changes, the report key and its backing tests stand in.
- **It does not retire** when docs/09 settles the rule, because what it states is still per binding: the byte type, the `blind_index` position, and a reading of §11.1 that is not spec text.

## 6. What each core owes

This card changes docs only. The code below is owed by the core cards. This card **blocks 0011 and 0013**, and the card does not say which core each one is, so this note does not assign them.

- **TypeScript.**
  - Move the type guard out of `recognize` (`core/typescript/src/envelope.ts`) to the operations' boundary, so `isCiphertext` on a non-`Uint8Array` answers `false`. Today it throws `INVALID_ARGUMENT`.
  - Ship this in **one PR with the [#241](https://github.com/fieldseal-dev/fieldseal-spec/issues/241) accessor**, since both touch recognition.
  - Add `wrong-typed-operand` with backing tests.
  - Add the operand step to `api-boundary-order`. Its text today goes from `SUITE_PROVISIONAL` straight to `LENGTH_EXCEEDED`.
  - Reword `decrypt-order` so it does not name `len<3`.
- **Java.**
  - Measure `isCiphertext(null)` with a test and make it `false`. By reading the code (`EnvelopeCodec.isCiphertext` → `Operand.of`), it throws `InvalidArgumentError` today. That is not measured.
  - Add `wrong-typed-operand` to `MANDATORY_PINNED`, and back it through `PINNED_TESTS`.
- **Python.**
  - Behaviour already conforms.
  - Add `wrong-typed-operand`, backed by the #256 tests in `tests/test_parity.py`.
  - Reword `decrypt-order` so it does not name `len<1` and `len<51`.
  - **No card is named for this.**
- Each core's PR adds its own `docs/07` entry, as #256 did, and replaces the "owed" text in its binding doc with as-built text.

## 7. Choices this card made where the owner left the point open

| Point | Choice | Why |
|---|---|---|
| Key name | `wrong-typed-operand` | It names exactly what the row pins. `api-boundary-order` stays about the relative order of the boundary refusals. |
| A `blind_index` key of its own? | No; it is covered by `wrong-typed-operand` | The owner asked to pin the rule, and it is one rule over four operations. This closes the `api-boundary-order` row's "until a key of its own is decided". |
| Mandatory for every core? | Yes, and test-backed | The decision is cross-core, and the owner asked for a per-core test. |
| `blind_index`'s operand position relative to context and declaration lookup | Not pinned; each core states its own | The cores differ: Python after the declaration is resolved, Java and TypeScript on the value first. All three come before key acquisition. Nobody decided between them. |
| docs/09 step numbering | Steps extended (1a new, 1b widened, §3.2 step 1 widened), not renumbered | Java code and `docs/27` cite "step 1b" as the length guard, and this card cannot change code. |
| `decrypt-order` length wording | State recognition by spec §3.4's outcomes, with floors named as the spec names them, not internal thresholds | This is how the Java report words it (`docs/27` §4). The wording rule goes in docs/14 §4's `decrypt-order` row. |

## 8. On "the report generator checks it"

The card's criterion asks that the report generator check the pin. This card makes that check a docs/14 §4 MUST: the generator runs the key's backing tests, and if they are missing or red the report claims no level. The generator code that enforces it is core code (`run_vectors.py`, `tests/harness/run.ts`, `ConformanceReport.java`). It lands with the core changes in §6, not in this card, which may not change core code.

## 9. Independence

This note and the docs edits quote all three cores, which a docs card may do. They add no exposure beyond what `docs/07` already discloses for #254 (the third comment on the issue quoted TypeScript and Java code). Core implementers should take their obligations from docs/09 §3, not from another core's tree.
