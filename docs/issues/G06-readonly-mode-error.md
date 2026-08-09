# G6 — §9/§10.3: No error code for mode violations; readonly's index-computation stance unstated

**Labels:** §9 · §10.3 · spec-gap · blocks-vectors
**Blocks:** one case in `errors/policy.json`.
**Status:** RESOLVED in spec 2026-08-09, adopted as proposed (all three items) — docs/02 §9 adds `MODE_VIOLATION` with the API-boundary note, §10.3 rewritten onto two explicit axes with the pass-through choice justified and the orthogonal-knob alternative recorded as considered-and-rejected — including the honest note that the three named modes cover only three of the four combinations those axes allow, and that the omitted one is legitimate rather than absurd, §12 gains the mode vector obligations; marker sweep in docs/08 §4.6/§9, docs/09 §3.1/§3.2/§3.3/§3.5/§9, docs/10, docs/issues/G10. Close tracker issue [#6](https://github.com/fieldseal-dev/fieldseal-spec/issues/6) when this lands.

## Gap

§10.3 defines the `readonly` read mode, but §9 defines no error for calling `encrypt()` (or `rotate()`) while in it — implementations would each invent their own exception type, which the shared error vectors cannot pin. Separately, §10.3 does not say whether a `readonly` client may compute blind indexes: an index value is needed to *query* (WHERE clause), not to write, so forbidding it would make `readonly` unable to look anything up — almost certainly not the intent.

Third under-definition: §10.3 defines `strict` and `permissive` by their **non-envelope** behavior (raise vs pass-through) and `readonly` only as "decrypts but never encrypts" — the three are not on the same axis, and a `readonly` client has no defined answer for unmigrated plaintext. That is precisely the migration/rollback scenario §10.3 lists `readonly` for, so the gap bites exactly where the mode is meant to be used.

## Proposed direction (starting point, not a decision)

1. Add `MODE_VIOLATION` to §9: raised when an operation not permitted by the configured mode is invoked (`encrypt`/`rotate` in `readonly`). One code covers future modes; the message names the operation and mode.
2. One clarifying sentence in §10.3: `readonly` forbids operations that produce ciphertext for storage; computing a blind index for query construction is permitted. (Matches the pipeline note in `docs/09-core-architecture.md` §3.3.)
3. Define `readonly`'s non-envelope read behavior: **pass-through, as `permissive`** (with the same §10.3 warning/metric), because the mode exists for migration and rollback windows where unmigrated plaintext is expected. Alternative for the issue discussion: make the read-axis behavior an orthogonal knob (`readonly` composing with `strict|permissive`) — more expressive, but a config-surface expansion §10.3 may not want.

## Justification

Interoperability of error behavior is a stated goal of the vector suite (`vectors/README.md`: "Negative vectors matter as much as positive ones… Each must produce the specific error type from spec §9"). A mode violation is a distinct, testable failure class; without a code it is untestable. No external citation applies — this is internal consistency of §9/§10.3.

## What it breaks

Nothing stored; adds an error code (additive) and a clarifying sentence. Non-breaking by `CONTRIBUTING.md` standards, but still issue-first because §9 is normative.

## Vector obligations

- `errors/policy.json`: `encrypt()` under `mode=readonly` → MODE_VIOLATION; `blind_index()` under `mode=readonly` → success (positive control); `decrypt()` of a valid envelope under `mode=readonly` → plaintext (positive control); non-envelope input under `mode=readonly` → the pinned behavior from item 3.

## Review flag

None.
