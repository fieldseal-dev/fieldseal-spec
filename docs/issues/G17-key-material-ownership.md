# G17 — docs/09 §8.1, §3.1/§3.2: `KeyProvider` return values have no ownership contract, and what makes the current cores safe is an undocumented defensive copy

**Labels:** docs/09 §8.1 · docs/09 §3.1 · docs/09 §3.2 · docs/09 §8.3 · docs/10 · docs/11 · spec-gap
**Blocks:** an invariant both cores depend on and neither states or tests; the honesty obligation `docs/09` §8.3 places on every language binding; no stored bytes and no vector in any family.
**Found:** 2026-08-25, tracing the `docs/09` §8.1 interface question that the PR [#55](https://github.com/fieldseal-dev/fieldseal-spec/pull/55) review left unfiled (`docs/11` §5 records it verbatim as "a docs/09 §8.1 interface question for both cores, not a binding-level fix").

**Status:** CLOSED 2026-08-25 — tracker [#67](https://github.com/fieldseal-dev/fieldseal-spec/issues/67), posted and closed the same day. Resolution in `docs/07` §7 and in the README closure note; the Part A withdrawal below is part of the record, not an erratum to be tidied away.

> **Correction, 2026-08-25 — this issue was filed with a defect claim that is false, and the claim is withdrawn.** The original Part A asserted that the TypeScript core erases key material a `KeyProvider` returned, and that a custom provider returning a reference to its own cached DEK would have that cache destroyed on the first `encrypt`. It does not. `api.ts:162`'s `ek.key.fill(0)` erases a value produced by `#encryptionKey`, which validates the provider's return and hands back **a fresh copy** (`api.ts:182`: `return { key: new Uint8Array(ek.key), keyId: new Uint8Array(ek.keyId) }`). The same helper serves the blind-index path (`api.ts:307`), so both `.fill(0)` sites act on the core's own copies. The claim was made from reading the `encrypt` body without following the helper, and it was caught by the regression test the issue itself asked for: written against unmodified code, it passed. **There is no defect in either shipped core.** What survives is a real but narrower gap — an unstated, untested invariant that the safety of two `.fill(0)` calls rests on, and a next-core hazard. The parts below are rewritten to that scope.

## Gap

`docs/09` §8.1 gives the `KeyProvider` interface as three signatures:

```
KeyProvider:
    encryption_key(ctx)  → (key_material, key_id[16])
    decryption_keys(header) → ordered list of key_material
    warm(contexts)       → async prefetch
```

and `docs/09` §3.1 and §3.2 prescribe erasure of derived material at four points — step 13 of the encrypt path (`best-effort zeroize record_key`), the decrypt path's `→ return plaintext (+ zeroize record_key)`, §8.3's zeroize-on-eviction, and §3.2's failure exits.

**Neither section says whether any of that material is mutable, and neither says who owns it.** `key_material` is an unqualified term; the pseudocode zeroizes without stating what it is entitled to zeroize. Three consequences.

### Part A — the invariant that makes erasure safe is real, undocumented, and untested

The TypeScript core erases key material on two paths:

```ts
// core/typescript/src/api.ts:161-162 (encrypt)     …:335 (blind index)
recordKey.fill(0);
ek.key.fill(0);
```

That is safe, and it is safe for a reason nothing writes down. Both `ek` and the index path's `material` come from `#encryptionKey`, whose job is to validate the provider's return — key length, `key_id` length, provider exceptions mapped to `KEY_UNAVAILABLE` — and which finishes by copying:

```ts
// core/typescript/src/api.ts:182
return { key: new Uint8Array(ek.key), keyId: new Uint8Array(ek.keyId) };
```

So the core erases **its own copy**, and a provider returning a reference to its own cached DEK is unharmed. Verified 2026-08-25 by a provider that deliberately hands out references to its own buffers: encrypt, decrypt and `blindIndex` all leave the provider's material intact, and repeated operations keep round-tripping (`tests/providers.test.ts`, "key-material ownership").

The gap is that **none of this is stated or tested anywhere, and the whole safety of two `.fill(0)` calls rests on it.** The copy exists for validation; erasability is a side effect of it. Nothing in `docs/09` §8.1, `docs/11`, the interface declaration or any test says the copy must stay. An ordinary refactor — hoisting validation, or noting that the provider already returns copies so the allocation is redundant — turns `ek.key.fill(0)` into the provider-cache-destroying bug the first version of this issue wrongly reported, with no test to catch it and a failure that surfaces one operation later as `COMMITMENT_INVALID` on a read of data written moments earlier.

The declared type does not help. `EncryptionKey.key` is `readonly` (`keyprovider.ts:22`), but TypeScript's `readonly` is shallow: it forbids rebinding the property, not mutating the buffer, so `ek.key.fill(0)` type-checks on the provider's own array as readily as on a copy.

The Python core cannot reach the question at all: `decryption_keys` and the encryption-key path are typed `bytes` (`keyprovider.py:54`), which is immutable. So the two cores are safe for entirely different reasons — one by a deliberate copy, one by a type — and neither reason is recorded.

**The live risk is the next core.** A Go, Java or .NET implementer reads §8.1, gets `[]byte`/`byte[]`, and has no instruction either to copy or to refrain from erasing. Both mistakes are available and neither is observable through the vector suite.

### Part B — the same interface, two different ownership assumptions, undocumented in both directions

The decrypt path declines to erase its candidates, and says why:

```ts
// core/typescript/src/api.ts:229-232
// The candidate `dek` buffers are deliberately NOT zeroized here: the §8
// interface gives this client no ownership of them, and a custom provider
// may return buffers it still needs (docs/11 §5 documented exception).
```

That reasoning is right, and — once the `#encryptionKey` copy is visible — the encrypt path does not contradict it: the decrypt path borrows and does not erase, the encrypt path copies and erases the copy. Both are correct under one rule. But the two paths reach that rule by opposite mechanisms, only one of them is commented, `docs/11` §5 records the decrypt-side choice as an *exception* to an unstated rule, and the encrypt-side copy is not mentioned at all. A reader of either path cannot tell which is the principle and which is the accommodation.

The cost of the borrow rule is stated honestly in `docs/11` §5 — the shipped providers' per-call copies reach GC unzeroized — and is small: they are copies of material the cache holds anyway, and spec §5.5 already concedes GC languages cannot guarantee erasure.

### Part C — a prescribed step that one shipped core cannot perform, and does not say so

`docs/09` §3.1 step 13 and §3.2's decrypt path both require best-effort erasure of `record_key`. The TypeScript core does it (`api.ts:161`, `:242`, both in `finally`). The Python core does not, at either site (`api.py:193` on encrypt, `:239` in the candidate loop), because its `record_key()` returns `bytes`:

```python
# core/python/src/fieldseal/kdf.py:29-37
def record_key(tenant_dek: bytes, key_id: bytes, msg_seed: bytes,
               ctx: FieldContext, length: int) -> bytes:
```

There is no defect here — CPython offers nothing to overwrite — but `docs/09` §8.3 requires that "each per-language spec states exactly what its zeroization does and does not achieve," and `docs/10` does not. Its one zeroization paragraph (§5) is about the **DEK cache**: `bytes` are immutable, the cache stores DEKs in `bytearray` and overwrites on eviction. That is accurate and it is not this. A reader of `docs/10` cannot learn that two of the four erasure points `docs/09` prescribes are unperformable in this binding, and the conformance report does not carry it either.

**None of this is observable through the vector suite.** No envelope byte changes, no error code changes, and a wiped-versus-live buffer is invisible to a produce/consume matrix. Like G14's platform HKDF caps and G16's lone-surrogate refusal, it is a property the whole verification apparatus is structurally unable to see — which is the argument for pinning it in text, and, as this issue's own false start demonstrates, for pinning it in tests too.

## Proposed direction (starting point, not a decision)

**Part A/B — `docs/09` §8.1 states ownership, and the answer is that the provider keeps it.**

> Key material returned by `encryption_key` and `decryption_keys` is **owned by the provider**. A core MUST NOT mutate or erase it, and MUST NOT retain a reference to it beyond the call that obtained it. A core that needs erasable material MUST copy first and erase its own copy.

This **codifies what both cores already do** rather than changing either. Three reasons for this direction over its opposite. It is implementable in every target language, where "the core owns and MUST erase" is not — a binding whose key material is an immutable type cannot satisfy it, so it would be a MUST a conformant core could not meet. It fails safe: a provider handing over a copy loses nothing under a borrow rule, while a provider handing over its cache is destroyed under an ownership rule. And it makes the TypeScript core's `#encryptionKey` copy load-bearing by contract instead of incidentally, which is the actual finding.

Recorded alternatives:

- **Core takes ownership and MUST erase.** Rejected: Python cannot implement it under its current type, and it converts every provider that returns a cached reference from efficient to broken.
- **Explicit opt-in handover** — a provider declares per-return whether it is yielding ownership. Rejected as over-engineering for a property spec §5.5 already concedes cannot be reliably achieved in GC languages.
- **Say nothing; the cores are already safe.** This is the do-nothing baseline and it is now the strongest it has ever looked, because the defect this issue was filed on does not exist. Rejected anyway, on two grounds: the safety rests on an untested invariant one refactor away from being wrong, and a core in a language with mutable byte arrays and no immutability backstop gets no instruction at all.

**Part C — `docs/09` §3.1/§3.2 gain a precondition, and `docs/10` gains the paragraph `docs/11` already has.**

The zeroization steps are qualified: they apply where the binding's type for the value is mutable, and a binding whose type makes a step unperformable MUST state which steps those are in its language document. This is not new policy — it is §8.3's existing honesty obligation applied to §3's steps, which it currently is not.

**Both parts — one `pinned_decisions` key.** Following the G5 precedent (§9 pins a rule about orders; each core declares its own), the conformance report gains `key-material-ownership`, declaring the ownership stance and the erasure points the binding actually performs. That makes the divergence visible in the artifact the project already compares across cores, which is the only place it can be visible at all.

## Justification

- Spec §5.5 already states that zeroization is best-effort and that GC languages cannot guarantee no copies; `docs/09` §8.3 makes that honesty a per-language obligation. This issue applies an existing rule to the four §3 erasure sites and to the §8.1 interface those sites touch.
- "Who owns this buffer" is not inferable from a signature. Rust's borrow rules, the C convention of documenting caller-versus-callee allocation, and OpenSSL's `_free` conventions all exist for that reason. `docs/09` §8.1 is a signature.
- `readonly key: Uint8Array` not preventing `key.fill(0)` is a documented property of TypeScript's shallow `readonly`. The constraint is inexpressible in at least one target language's type system, so it has to be expressed in the specification.
- G14 established the precedent for this class: a property the vectors cannot observe, holding in each core for reasons that differ by language, is closable by engineering judgment but must be closed in text because the next core inherits the same silence.

## What it breaks

Nothing stored, and — after the correction above — **no core behaviour**. No envelope byte, no derived value, no vector expectation, no error code, no registry entry, and no line of either core's value path changes. The changes are:

- `docs/09` §8.1 gains an ownership paragraph; §3's erasure sites gain a mutability precondition.
- `docs/10` §5 gains one honesty paragraph naming the two unperformable steps.
- `docs/11` §5's "documented exception" is rewritten as conformance with the rule, and gains the `#encryptionKey` copy as the stated mechanism.
- `docs/14` §4 gains one required `pinned_decisions` key, which both cores must emit — the reports have carried identical key sets since G15 and this preserves that.
- **Tests, not a fix.** A provider returning references to its own buffers must find them intact after `encrypt`, `decrypt` and `blindIndex`. These pass today; they exist so that the copy at `api.ts:182` cannot be refactored away silently. In the Python core the equivalent asserts the core never mutates provider-supplied material.
- **`docs/10` §6 item 2's related invariant folds in here:** `decryption_keys` candidate reads must not deplete `max_uses`. `docs/09` §8.3 states use counting only from the encrypt side, so the read-path half is an inference; §8.1 should state it, since it is a property of the interface rather than of the cache.

## Vector obligations

**None are possible, and that is the finding rather than an omission.** Buffer lifetime after a call produces no bytes for a vector to pin and no error for the harness to match. The obligations are therefore:

- `docs/14` §4 — the `key-material-ownership` `pinned_decisions` key above, required of every core.
- Per-core unit tests as described, which are the only executable form this requirement has.
- No `out_of_band` report entry is proposed. The G16 precedent applies to an assertion a vector *would* express if the operand were representable; here there is no operand, so the report key is the right instrument.

## Review flag

**No cryptographic review required.** An interface-ownership contract and an honesty obligation, not a construction: no key, nonce, derivation, encoding or stored byte changes. Closable by engineering judgment under the rule that closed G3, G6, G8–G13 and G16, and unlike G14 it has no bearing on any Gate 0b question — nothing here touches Q1–Q8.
