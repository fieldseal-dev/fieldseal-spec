# G14 — §6.1/§6.2: `tenant_id` and `row_id` are unbounded, so KDF `info` is unbounded — and platform HKDFs cap it

**Labels:** §6.1 · §6.2 · §5.3 · §7.2 · spec-gap
**Blocks:** one boundary behavior (acceptance/rejection consistency at large contexts); no stored bytes in any shipped vector.
**Found:** 2026-08-22, in review of the TypeScript core (`docs/18-m2-report.md` §4, `node:crypto` row addendum; fixed for that core in PR [#42](https://github.com/fieldseal-dev/fieldseal-spec/pull/42)). Filed as a spec issue because the fix in one core does not protect the next one.

**Status:** OPEN — tracker [#43](https://github.com/fieldseal-dev/fieldseal-spec/issues/43), posted 2026-08-22. Not provisionally adopted; no spec text carries a marker for it yet. Note the tracker number no longer equals the gap number: #14–#42 were consumed by pull requests after G13 was filed.

## Gap

§6.1 types `tenant_id` and `row_id` as `bytes | null` with no upper bound. §6.2 makes `canonical_context` the HKDF `info` for record-key derivation (§5.3) and index-key derivation (§7.2), and part of the AAD (§6.3). The length of `info` is therefore whatever the caller's identifiers are, plus a fixed 121 bytes of framing at the longest `purpose`:

```
len(canonical_context) = 1                      // presence
                       + (8+2) + (8+16) + (8+16) // suite_id, table_uuid, column_uuid
                       + [8 + len(tenant_id)]
                       + [8 + len(row_id)]
                       + 8 + len(purpose)        // ≤ 8 + 38 ("index:" + 32-byte index-id)
                     ≤ 121 + len(tenant_id) + len(row_id)
```

RFC 5869 places no bound on `info` ("optional context and application specific information (can be a zero-length string)", §2.3). Several platform HKDF entry points do, and they do so at different values:

| Platform HKDF | `info` bound | Failure mode | Verified |
|---|---|---|---|
| Node.js `crypto.hkdf` / `hkdfSync`, and Web Crypto `subtle.deriveBits` on Node | **1024 bytes** | `ERR_OUT_OF_RANGE`, "must not contain more than 1024 bytes" | `lib/internal/crypto/hkdf.js`, `validateParameters`, read 2026-08-22; reproduced on Node 24.16 (the TypeScript core's `encrypt`, `decrypt` and `blindIndex` all threw above ~930 bytes of optional context) |
| OpenSSL 3.0–3.5 `EVP_KDF` "HKDF" provider | **32 768 bytes** (`HKDF_MAXINFO`) | Set-params returns 0 with no error reason raised; the caller sees a generic failure | `providers/implementations/kdfs/hkdf.c` on branches `openssl-3.0` through `openssl-3.5`, read 2026-08-22. The check is **absent on `master`**; which release drops it was not determined |
| .NET `System.Security.Cryptography.HKDF` on Linux | inherits OpenSSL's bound above when OpenSSL 3's `EVP_KDF` HKDF is available | [VERIFY: the exception type surfaced] | `HKDF.OpenSsl.cs` selects `Interop.Crypto.HkdfExpand` when `EvpKdfAlgs.Hkdf` is non-null, else the managed RFC 5869 implementation; `pal_evp_kdf.c` passes `info` as a single `OSSL_KDF_PARAM_INFO`. Read 2026-08-22, **not executed**. The Windows path was not read |
| Java `javax.crypto.KDF` HKDF (JEP 510, JDK 25) | none found | — | `com.sun.crypto.provider.HKDFKeyDerivation` bounds only the output length (`255 · HashLen`); `info` is passed through. Read 2026-08-22 |
| Go `crypto/hkdf` | none found | — | `crypto/internal/fips140/hkdf/hkdf.go` writes `info` into the HMAC unconditionally. Read 2026-08-22 |
| pyca `cryptography` HKDF | none found | — | Implemented in Rust over the package's own HMAC (`src/rust/src/backend/kdf.rs`), not over OpenSSL's `EVP_KDF`; the Python core round-trips a 2000-byte `tenant_id`. Read and run 2026-08-22 |

Not examined: BoringSSL, browser Web Crypto implementations, libsodium (which has no HKDF), Bouncy Castle, Windows CNG's `BCryptKeyDerivation` with `BCRYPT_HKDF_ALGORITHM`.

The consequence is the central-claim failure in miniature: the Python core wrote an envelope under a 2000-byte `tenant_id`, and the TypeScript core — conformant against every shipped vector — could not derive the key to read it. No vector caught this because the largest `tenant_id` in `vectors/` is **11 bytes** and the largest `row_id` is 6 (measured 2026-08-22 across all seven files); `docs/08` §4.3 asks for boundary lengths of 1, 16 and 64 bytes, which is also well under every cap above. The TypeScript core now hand-rolls RFC 5869 over `createHmac` and round-trips contexts up to 70 000 bytes, but a Java, .NET or Go core written tomorrow against `docs/09` has no instruction not to reach for the platform HKDF, and the .NET one would inherit a bound that differs between Linux and Windows hosts of the *same* core.

This is the same class of gap as G10 (§3.5): a bound the spec does not choose is a bound every implementation inherits from its runtime, and inherited bounds disagree.

## Proposed direction (starting point, not a decision)

Two options are on the table; the first is proposed.

**Option A — bound the optional fields in §6.1.** `tenant_id` and `row_id`, when present, MUST each be at most **N bytes**, with N chosen so that the longest `canonical_context` fits under the smallest known platform cap with room for §6.2's extension path:

- N = **255** gives a maximum `canonical_context` of 121 + 255 + 255 = **631 bytes**, under Node's 1024 with ~390 bytes of headroom for future presence-bitmap fields (§6.2's injectivity argument says new optional fields take new bits; each costs 8 + its own bound).
- An over-bound identifier is refused at the API boundary before any key acquisition or cryptographic processing, on the same terms as `LENGTH_EXCEEDED` and `MODE_VIOLATION` (§9), and is therefore outside the G5 decrypt-path ordering. Whether it reuses `LENGTH_EXCEEDED` (re-scoped from "plaintext" to "an input length bound") or gets a dedicated `CONTEXT_LENGTH_EXCEEDED` is part of this issue. The G10 closure argued against overloading codes whose meaning is specific; `LENGTH_EXCEEDED` as defined is specifically about plaintext, so a dedicated code is the consistent choice, at the cost of one more row in §9.
- Because `canonical_context` is recomputed from caller-supplied context rather than parsed from the envelope, the decrypt side refuses the same inputs the encrypt side does; there is no "envelope already written under a longer context" case once both sides enforce.
- Prose for adapters: an application whose natural identifier exceeds N (a long composite primary key serialized as text, a hierarchical tenant path) maps it through a stable, collision-resistant surrogate — e.g. `SHA-256(identifier)` — the same way `table_uuid` already stands in for the SQL table name. Binding needs only that distinct rows get distinct `row_id`s; it does not need the bytes to be the key itself. Neither Phase 1 adapter design binds `row_id` yet (`docs/12`: L3-row deferred to client-generated PKs; `docs/13`: L3-row ❌), so no adapter serialization is constrained by choosing N now — which makes now the cheapest moment to choose it.

**Option B — leave the fields unbounded and constrain implementations instead.** Add to §5.3/§7.2 (or `docs/09`) a MUST: an implementation's KDF accepts an `info` of any length the encoding can produce, which in practice means implementing RFC 5869 over an HMAC primitive rather than calling a platform HKDF with a cap. Every core then carries the TypeScript fix. This keeps the caller's identifier space unconstrained, but it is an instruction the spec can only enforce with a very large context vector, it leaves the .NET Linux/Windows split for the implementer to discover, and it makes the AAD (which carries the same bytes, §6.3) the next inherited-limit question for whichever AEAD binding caps it.

Option A is proposed because it turns an implementation footgun into a testable rule, and because the bound is not expected to bind: `tenant_id` is typically a UUID, an integer, or a slug, and `row_id` an integer or UUID. Option B is recorded so that the review can reject A on the ground that some deployment class needs long identifiers — the surrogate mapping in A is the answer to that objection, and if the reviewers find it unconvincing, B is the fallback.

Either option also corrects `docs/08` §4.3: the "boundary lengths" case must include the maximum (under A) or a length above every known platform cap (under B), and the generator must actually emit it — the shipped 11-byte maximum is a generator gap independent of this issue's outcome.

## Justification

- RFC 5869 §2.3 leaves `info` unbounded; the caps above are implementation choices, not a property of the construction. The spec therefore cannot rely on "RFC 5869" alone to make the derivation portable.
- The argument is G10's: cross-implementation agreement on *rejection* is the same interoperability property as agreement on acceptance (§3.5 *Justification*), and a bound chosen by the spec is testable where one inherited from a runtime is not.
- Narrowing the domain of `canonical_context` cannot weaken §6.2's injectivity argument (a function injective on a set is injective on every subset), so Option A does not reopen Q4. It does not change a single byte of any encoding within the bound, so it is not an envelope-format change.
- The smallest known cap (Node, 1024) is the design constraint because the TypeScript core is a Phase 1 deliverable and because Web Crypto is the only HKDF available in browser and edge runtimes, which `docs/11` lists as a possible future target. Sizing N so the *whole* `canonical_context` fits under it means a future core may use the platform primitive without reproducing this bug.

## What it breaks

Nothing stored: no shipped vector and no existing deployment (pre-alpha, no adoption permitted under Gate 0a) carries an identifier over 255 bytes. Under Option A, §6.1's type for the two fields narrows, one error code is added or re-scoped in §9, and `docs/09` §4 gains an API-boundary check. Under Option B, §5.3/§7.2 gain a MUST and `docs/09` a primitive-selection rule. Neither touches the registry or the envelope layout.

## Vector obligations

- `context/canonical.json`: `tenant_id` and `row_id` at exactly the bound (Option A) or at a length above the largest known platform cap (Option B), in the same vector, with `purpose = "index:" + 32-byte index-id` so the total is the true maximum; plus a negative declaration one byte over the bound (Option A), asserting the refusal code.
- `envelope/ff01.json`: one round-trip vector at the maximum context. This is the vector that would have caught the TypeScript failure.
- `kdf/record-key.json` and `kdf/index-key.json`: one vector each at the maximum context, so the failure is localized to the KDF rather than surfacing as a decrypt error.
- `errors/`: the over-bound refusal, once the code is chosen (Option A only).
- Harness contract (`docs/08` §5): the conformance report's `pinned_decisions` names which option the core is built against until the spec settles it.

All of these are ordinary repository-sized vectors; no `out_of_band` substitute is needed.

## Review flag

**No cryptographic review required.** This is an interoperability bound, and Option A only narrows the domain of an encoding whose injectivity is already Q4's question. It is therefore closable by engineering judgment under the same rule that closed G3, G6, G8–G13 — but it should not be closed before the Phase 0 reviewers have seen it, because a reviewer answering Q4 may have a view on whether the encoding's *extension* budget (the headroom under 1024) is the right thing to be sizing against.
