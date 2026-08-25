# G17 — docs/09 §8.1, §3.1/§3.2: key-material ownership is undefined, so one core destroys a buffer the provider may still own and the other cannot erase anything

**Labels:** docs/09 §8.1 · docs/09 §3.1 · docs/09 §3.2 · docs/09 §8.3 · docs/10 · docs/11 · spec-gap
**Blocks:** a defect reachable by a conformant custom `KeyProvider`; the honesty obligation `docs/09` §8.3 places on every language binding; no stored bytes and no vector in any family.
**Found:** 2026-08-25, tracing the `docs/09` §8.1 interface question that the PR [#55](https://github.com/fieldseal-dev/fieldseal-spec/pull/55) review left unfiled (`docs/11` §5 records it verbatim as "a docs/09 §8.1 interface question for both cores, not a binding-level fix"). Neither core is wrong under the text as it stands, which is the reason this is a spec issue and not two bug reports.

**Status:** OPEN — tracker [#67](https://github.com/fieldseal-dev/fieldseal-spec/issues/67), posted 2026-08-25. Not provisionally adopted; no spec or `docs/09` text carries a marker for it.

## Gap

`docs/09` §8.1 gives the `KeyProvider` interface as three signatures:

```
KeyProvider:
    encryption_key(ctx)  → (key_material, key_id[16])
    decryption_keys(header) → ordered list of key_material
    warm(contexts)       → async prefetch
```

and `docs/09` §3.1 and §3.2 prescribe erasure of derived material at four points — step 13 of the encrypt path (`best-effort zeroize record_key`), the decrypt path's `→ return plaintext (+ zeroize record_key)`, §8.3's zeroize-on-eviction, and §3.2's failure exits.

**Neither section says whether any of that material is mutable, and neither says who owns it.** `key_material` is an unqualified term; the pseudocode zeroizes without stating what it is entitled to zeroize. Three consequences, all live in the two shipped cores today.

### Part A — the core erases a buffer it was never given

The TypeScript core zeroizes the provider's return value on the encrypt path:

```ts
// core/typescript/src/api.ts:154-163
const recordKey = deriveRecordKey(suite, ek.key, ek.keyId, msgSeed, cc);
try { … } finally {
  recordKey.fill(0);   // ours: derived here
  ek.key.fill(0);      // NOT ours: returned by KeyProvider.encryptionKey
}
```

`ek` is whatever `KeyProvider.encryptionKey(ctx)` returned. Nothing in `docs/09` §8.1, in spec §8, or in the interface's own declaration says that value is a fresh copy the caller may destroy. The declared type says the opposite as loudly as TypeScript can:

```ts
// core/typescript/src/keyprovider.ts:20-24
export interface EncryptionKey {
  readonly key: Uint8Array;
  readonly keyId: Uint8Array;
}
```

`readonly` on the property prevents rebinding the field, not mutating the buffer behind it, so `ek.key.fill(0)` type-checks while overwriting memory the interface presents as read-only.

**This is safe today only by accident of the shipped providers.** All three of them return copies — `return { key: new Uint8Array(this.#dek), … }` (`keyprovider.ts:85`, `:87`) — so the core wipes a per-call duplicate. A custom provider is under no obligation to do that: the obvious efficient implementation returns a reference to its own cached DEK, which is exactly what a provider backed by an existing key cache would do. On the first `encrypt`, the core silently zeroizes that cache entry. Every subsequent operation resolving to the same key derives from 32 zero bytes, and the failure surfaces as `COMMITMENT_INVALID` on reads of data written moments earlier — a decrypt-side error for a write-side memory bug, with no diagnostic pointing at the provider.

The Python core has the same interface and does not do this, because it cannot: `decryption_keys` and the encryption-key path are typed `bytes` (`core/python/src/fieldseal/keyprovider.py:54`), and `bytes` is immutable. So the two cores differ not by decision but by what their type systems allowed, and neither difference is written down.

### Part B — the same interface, the opposite ownership assumption, in the same file

Sixty lines below the encrypt path, the same core declines to zeroize the same interface's other return value, and says why:

```ts
// core/typescript/src/api.ts:229-232
// The candidate `dek` buffers are deliberately NOT zeroized here: the §8
// interface gives this client no ownership of them, and a custom provider
// may return buffers it still needs (docs/11 §5 documented exception).
for (const dek of candidates) { … }
```

That reasoning is correct, and it is the exact reasoning that Part A's `ek.key.fill(0)` contradicts. Both values come from the same `KeyProvider`; one is treated as owned and one as borrowed. `docs/11` §5 documents the decrypt-side choice as an exception and names §8.1 as the place it should be settled; nothing documents the encrypt-side choice at all.

The cost of the conservative side is stated honestly in `docs/11` §5 — the shipped providers' per-call copies reach GC unzeroized — and is small: they are copies of material the cache holds anyway, and spec §5.5 already concedes that GC languages cannot guarantee erasure. The cost of the permissive side is Part A.

### Part C — a prescribed step that one shipped core cannot perform, and does not say so

`docs/09` §3.1 step 13 and §3.2's decrypt path both require best-effort erasure of `record_key`. The TypeScript core does it (`api.ts:161`, `api.ts:242`, both in `finally`). The Python core does not, at either site (`core/python/src/fieldseal/api.py:193` on encrypt, `:239` in the candidate loop), because its `record_key()` returns `bytes`:

```python
# core/python/src/fieldseal/kdf.py:29-37
def record_key(tenant_dek: bytes, key_id: bytes, msg_seed: bytes,
               ctx: FieldContext, length: int) -> bytes:
```

There is no defect here — CPython offers nothing to overwrite — but `docs/09` §8.3 requires that "each per-language spec states exactly what its zeroization does and does not achieve," and `docs/10` does not. Its one zeroization paragraph (§5) is about the **DEK cache**: `bytes` are immutable, the cache stores DEKs in `bytearray` and overwrites on eviction. That is accurate and it is not this. A reader of `docs/10` cannot learn that two of the four erasure points `docs/09` prescribes are unperformable in this binding, and the conformance report does not carry it either.

**None of this is observable through the vector suite.** No envelope byte changes, no error code changes, and a wiped-versus-live buffer is invisible to a produce/consume matrix. Like G14's platform HKDF caps and G16's lone-surrogate refusal, it is a property the whole verification apparatus is structurally unable to see, which is the argument for pinning it in text rather than waiting for a test to fail.

## Proposed direction (starting point, not a decision)

**Part A/B — `docs/09` §8.1 states ownership, and the answer is that the provider keeps it.**

> Key material returned by `encryption_key` and `decryption_keys` is **owned by the provider**. A core MUST NOT mutate or erase it, and MUST NOT retain a reference beyond the call that obtained it. A core that needs erasable material MUST copy first and erase its own copy.

Three reasons this is the proposal rather than its opposite. It is what the decrypt path already argues for in a comment, so adopting it makes the core self-consistent by deleting one line (`api.ts:162`) rather than by adding a rule. It is implementable in every target language, where "the core owns and MUST erase" is not — Python's `bytes` cannot satisfy it, so a MUST that one shipped core is structurally unable to meet would be a MUST the spec cannot mean. And it fails safe: a provider that hands over a copy loses nothing under a borrow rule, while a provider that hands over its cache is destroyed by an ownership rule.

Recorded alternatives:

- **Core takes ownership and MUST erase.** Better hygiene on paper — no provider copy outlives the call. Rejected as the primary because Python cannot implement it under the current type and because it converts every provider that returns a cached reference from "efficient" to "broken", which is the Part A defect promoted to a requirement.
- **Explicit opt-in handover** — a provider declares per-return whether it is yielding ownership. Rejected as over-engineering for a value the spec already concedes cannot be reliably erased in GC languages (spec §5.5); it adds an interface field to buy a best-effort property.
- **Say nothing and fix the TypeScript line as a bug.** This is what happens if the issue is closed as an implementation defect. Rejected on the standing rule that a fix in one core does not protect the next one — a Go or Java core gets `[]byte`/`byte[]`, mutable, and no instruction either way.

**Part C — `docs/09` §3.1/§3.2 gain a precondition, and `docs/10` gains the paragraph `docs/11` already has.**

The zeroization steps are qualified: they apply where the binding's type for the value is mutable, and a binding whose type makes a step unperformable MUST state which steps those are in its language document. `docs/10` §5 gains that sentence for `record_key` on both paths. This is not new policy — it is `docs/09` §8.3's existing honesty obligation applied to §3's steps, which it currently is not.

**Both parts — one `pinned_decisions` key.** Following the G5 precedent (§9 pins a rule about orders; each core declares its own), the conformance report gains `key-material-ownership`, declaring `provider-owned` or `core-owned` and listing the erasure points the binding actually performs. That makes the divergence visible in the artifact the project already compares across cores, which is the only place it can be visible at all.

## Justification

- Spec §5.5 already states that zeroization is best-effort and that GC languages cannot guarantee no copies; `docs/09` §8.3 makes that honesty a per-language obligation. This issue asks for nothing new in kind — it applies an existing rule to the four §3 erasure sites and to the §8.1 interface those sites touch.
- The Part A defect is a memory-ownership bug of the ordinary kind, and the ordinary remedy is an explicit ownership contract at the interface boundary. Rust's borrow rules, the C convention of documenting caller-versus-callee allocation, and OpenSSL's `_free` conventions all exist because "who owns this buffer" is not inferable from a signature. `docs/09` §8.1 is a signature.
- `readonly key: Uint8Array` not preventing `key.fill(0)` is a known and documented property of TypeScript's `readonly` modifier, which is shallow. An interface cannot express this constraint in the type system of at least one target language, so it has to be expressed in the specification.
- G14 established the precedent for this issue's class: a property the vectors cannot observe, differing between cores by inherited language behaviour rather than by decision, is closable by engineering judgment but must be closed in text because the next core inherits the same silence.

## What it breaks

Nothing stored. No envelope byte, no derived value, no vector expectation, no error code, no registry entry. The changes are:

- `docs/09` §8.1 gains an ownership paragraph; §3.1 step 13 and §3.2's erasure sites gain a mutability precondition.
- `docs/10` §5 gains one honesty paragraph naming the two unperformable steps.
- `docs/11` §5's "documented exception" is rewritten as conformance with the rule rather than a deviation from an unstated one.
- `docs/14` §4 gains one required `pinned_decisions` key, which both cores must emit — the reports have carried identical key sets since G15 and this preserves that.
- One line deleted in the TypeScript core (`api.ts:162`), with a regression test asserting that a provider returning a reference to its own buffer still holds intact key material after an `encrypt`. That test is the whole point of the change and should be written before the deletion.
- **`docs/10` §6 item 2's related invariant is folded in here rather than left loose:** `decryption_keys` candidate reads must not deplete `max_uses`. `docs/09` §8.3 states use counting only from the encrypt side ("incremented per `encryption_key` return"), so the read-path half is an inference; §8.1 should state it, since it is a property of the interface rather than of the cache.

## Vector obligations

**None are possible, and that is the finding rather than an omission.** Buffer lifetime after a call produces no bytes for a vector to pin and no error for the harness to match. The obligations are therefore:

- `docs/14` §4 — the `key-material-ownership` `pinned_decisions` key above, required of every core.
- Per-core unit tests, not vectors: a provider that returns a reference (not a copy) from `encryption_key` must find its material intact after `encrypt`, and after `decrypt` for the candidate path.
- No `out_of_band` report entry is proposed. The G16 precedent applies to an assertion a vector *would* express if the operand were representable; here there is no operand, so the report key is the right instrument.

## Review flag

**No cryptographic review required.** This is an interface-ownership contract and an honesty obligation, not a construction: no key, nonce, derivation, encoding or stored byte changes under either option. It is closable by engineering judgment under the rule that closed G3, G6, G8–G13 and G16, and unlike G14 it has no bearing on any Gate 0b question — nothing here touches Q1–Q8.
