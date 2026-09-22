# @fieldseal/core (TypeScript) reference

The detail behind [`README.md`](README.md): where this core came from, the
behaviours it pins where the specification leaves a choice open, why it
refuses strings in the envelope operations, its testing namespace and
development setup. The README is the place to start; this file is for
reviewers and contributors. The design it implements is
[`docs/11-core-typescript.md`](../../docs/11-core-typescript.md).

Everything here describes an experimental, unreviewed pre-1.0 release; the
README's warning applies to all of it.

## Provenance

This package is the M2 deliverable of
[`docs/17-m2-implementer-brief.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/17-m2-implementer-brief.md); the
divergence report it was built to produce is
[`docs/18-m2-report.md`](https://github.com/fieldseal-dev/fieldseal-spec/blob/main/docs/18-m2-report.md).

## Bytes, strings and the asynchronous companions

All five operations are synchronous and perform no I/O (spec §11.1). Inputs are
`Uint8Array`; outputs are `Buffer`. **Strings are not accepted by the envelope
operations** — an implicit UTF-8 coercion there is exactly the kind of
cross-language divergence the vector suite exists to catch. `blindIndex` is the
deliberate exception and takes text *or* bytes (docs/09 §7.1): index derivation
is the one operation whose answer depends on the difference between a string
and its encoding, because `TextEncoder` silently substitutes U+FFFD for an
unpaired surrogate — so a caller who encodes first has already collapsed two
distinct values into one index before this core is entered.

`blindIndexAsync` and `unindexableMarkerAsync` are the spec §11.1 companions to
the two Argon2id derivations: byte-identical output, the same §9 error for the
same condition (as a rejection), and the synchronous forms are **not**
implemented by blocking on them. The conformance report runs the entire vector
suite a second time through them (`async_companions: true`, 182 `#async`
results).

## Error precedence

The decrypt-path precedence is pinned by this core under the still-open G5
question and declared verbatim in its conformance report
(`pinned_decisions.decrypt-order`). One consequence to know: **`AAD_MISMATCH`
is never raised on the `0xFF01` path.** Under dual-layer binding (§6.3) a wrong
context changes the derived key, so at decrypt time it is indistinguishable
from a wrong key and surfaces as `COMMITMENT_INVALID`.

## Unicode tables

- **`nfc-casefold-v1`** uses vendored Unicode 17.0.0 tables for **both** NFC
  and full case folding, so an index value does not depend on the runtime's
  ICU. The conformance report records the platform's ICU/Unicode versions for
  information only, and names the vendored version it actually used. A value
  containing a code point the pinned version does not assign is refused, or —
  where the column declares it — bucketed under a reserved marker; it is never
  silently indexed under a substituted character.

## Testing namespace

`@fieldseal/core/testing` exports `encrypt_with_materials(client, plaintext,
ctx, msgSeed, nonce)`, which runs the full production pipeline with
caller-supplied seed and nonce in place of the two CSPRNG draws. It is inert —
every call throws — unless `FIELDSEAL_TEST_MODE=1` is set. *An implementation
that accepts a caller-supplied nonce or seed outside of vector-test mode is
non-conformant* (`vectors/README.md`). The main entry never reaches this
module, and the production `encrypt()` takes no seed or nonce in any form.

## Developing

```
npm ci
npm test            # vitest: vector suite (both passes) + gates + totality +
                    # primitives + providers + async companions
npm run vectors     # emit the docs/14 §4 conformance report to stdout
npm run build       # tsc → dist/
npm run typecheck
```

The harness iterates `vectors/MANIFEST.json` `files` only and never
`held_out`. The suite has held nothing out since `0.6.0-provisional` —
`blind-index/argon2id.json` was the last entry, and has been pinned and counted since then
(`docs/07` §7), so a green run reports `held_out: 0`.
