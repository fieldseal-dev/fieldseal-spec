# G22 — `docs/09` §7.1 requires cores to export the assigned-code-point check for adapters; neither core does, and the adapter that needs it has to parse an error message

**Labels:** docs/09 §7.1 · docs/10 · docs/11 · docs/12 §10.2 · docs/13 §9 · spec-gap
**Blocks:** No stored byte, no derived value, no vector in any family. `docs/13` §9's message requirement, which the Prisma adapter currently satisfies by regex over `InvalidArgumentError.message`.
**Found:** 2026-08-27, writing the Prisma adapter's unindexable-value path (WS-F PR1).

**Status:** OPEN — filed, not applied. The adapter ships the workaround with the reason written at the call site.

## Gap

`docs/09` §7.1, in the normative block G16 part A rewrote:

> Cores MUST still export the assigned-code-point check (`first_unassigned` / `firstUnassigned`) for adapters that hold the text earlier and can give a better-sited error, and clause 5's strict decode still governs the bytes path.

**Neither core exports it.**

- **TypeScript.** `src/unicode/index.ts` defines `firstUnassigned`, and `src/normalize.ts:135` re-exports it — but `src/index.ts` does not, and `package.json`'s `exports` map exposes only `./dist/index.js` and `./dist/testing/index.js`. So it is unreachable from `@fieldseal/core` by construction, not merely by omission.
- **Python.** `first_unassigned` appears in `fieldseal/blindindex.py` and `fieldseal/unicode/__init__.py`, and not in `fieldseal/__init__.py`.

The clause names its beneficiary exactly — "adapters that hold the text earlier and can give a better-sited error" — and the Prisma adapter is that adapter. `docs/13` §9 then depends on it:

> the thrown error MUST carry what a UI needs to build the message in `docs/12` §10.2 — the offending code point and its offset — because an error that says only "invalid input" forces the application to either show that to a person or guess.

With no exported check, the only route to the code point and offset is the core's own error **message**, which does carry them (`value contains U+0378, which is not assigned in Unicode 17.0.0`; `value contains an unpaired high surrogate U+D800 at index 3`). The Prisma adapter parses it with a regex, and that is a dependency on prose: a message reworded for clarity silently degrades a user-facing error that `docs/12` §10.2 makes normative in shape.

## Why this is worth a change and not a shrug

The check is not a convenience. Its whole purpose is to let a caller refuse a value **before** the write, where it can be attributed to a form field and rendered next to it, rather than mid-operation where the adapter can only throw. `docs/12` §10.2's three rules — name the character and its position, put the fault on the system, offer a route ending with the real value stored — are hard to satisfy from an exception raised inside a `create`.

This is also the second time the same clause has been under-implemented: G16 part A found the TypeScript core's error message actively *countermanding* §7.1 by pointing callers at `TextEncoder`. The rule keeps being stated and not carried into the public surface.

## Proposed direction (starting point, not a decision)

1. **Export it from both cores' public entry points**, under the `docs/09` §12 casing rule: `firstUnassigned` (TypeScript, via `src/index.ts`) and `first_unassigned` (Python, via `fieldseal/__init__.py`). Signature as it already exists: text in, the first unassigned or surrogate code point and its offset out, or a null result when every code point is assigned.
2. **Decide whether the pinned Unicode version travels with it.** An adapter that reports "U+XXXX is not assigned in Unicode 17.0.0" needs the version string, and `UNICODE_VERSION` is unexported in the same way. Either export it or have the check return it.
3. **`docs/13` §9 and `docs/12` §10.2** stop depending on message text and name the function.
4. Consider whether this belongs in the `docs/14` §4 report as an `out_of_band` entry, the way G16's lone-surrogate refusal did (`docs/09/7.1/lone-surrogate-refusal`). Argument against, following G18: an export's presence is directly testable per core, so a report key would legitimise a divergence rather than record an unobservable one.

## Justification

`docs/09` §7.1 already contains the MUST; this issue does not propose a new rule, it proposes carrying an existing one into the surface it names. The reason the rule exists is G16's finding: `TextEncoder` substitutes U+FFFD for an unpaired surrogate, so a caller who encodes before calling has already collapsed two distinct values into one — a manufactured false match in the exact feature built to prevent them. Keeping the refusal where the information still exists is the whole design, and an adapter cannot participate in it without the check.

## What it breaks

Nothing. It is a widening of both public surfaces: no stored byte, no derived value, no error code, no existing caller affected.

## Vector obligations

**None expressible.** Same reasoning G16 recorded for the lone-surrogate refusal: `blind-index/` keys its input as hex bytes, an unpaired surrogate has no UTF-8 encoding, and widening the field to text would not help because Go string literals cannot hold a surrogate value and Rust's `String` is UTF-8 by invariant. Per-core unit tests are the executable form.

## Review flag

**No cryptographic review**, and no bearing on any Gate 0b question. It decides which already-existing function appears on a module's public surface — no construction, no derivation, no stored byte. Part D of G16 declined to send the closely related question to reviewers on exactly this reasoning.
