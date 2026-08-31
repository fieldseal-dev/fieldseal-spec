# Core Library Architecture Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the language-agnostic architecture every core implementation (`core/{python,typescript,java,dotnet,go}`) follows. Per-language bindings of this architecture are in `docs/10-core-python.md` and `docs/11-core-typescript.md` (Phase 1); Java/.NET/Go follow in Phase 2 with their own documents.

**Authority:** `docs/02-spec-v0.1.md` is normative. Where this document goes beyond the spec it says so; where the spec is silent and the gap is cross-implementation-relevant, the gap is listed in `docs/07-implementation-plan.md` §5 as a spec issue rather than decided here. Envelope-level design is conditional on ADR-0001 (`docs/adr/0001-envelope-format-source.md`) — if the project profiles the AWS structured-encryption format instead of the v0.1 envelope, §4 and §5 of this document are rewritten.

---

## 1. Component decomposition

Identical module boundaries in every language, so a reader of one core can navigate any other:

```
core/<lang>/
  api          the five sync operations + warm()          (spec §11)
  envelope     header struct, parse/serialize, is_ciphertext   (spec §3)
  registry     frozen suite table + allow-list policy     (spec §4)
  context      FieldContext, canonical_context, AAD       (spec §6)
  kdf          record-key and index-key derivation        (spec §5.3, §7.2)
  aead         per-suite AEAD backends over platform crypto
  commitment   key-commitment compute/verify              (spec §4.6; construction provisional, G1)
  blindindex   IDFs (Argon2id, HMAC-SHA-512), truncation, normalizers  (spec §7)
  keyprovider  KeyProvider interface + Static/Derived/Envelope providers  (spec §8)
  cache        DEK cache (max-age + max-uses + zeroization)  (spec §5.5)
  config       client configuration: mode, allow-list, provider, cache policy, index declarations
  errors       the §9 taxonomy as typed errors
  testing      encrypt_with_materials + fixed entropy source  (docs/08 §6; never exported from the main module)
```

Dependency rule, enforced by review and (where the language allows) by package visibility: `api` → everything; `envelope`/`context`/`kdf`/`aead`/`commitment`/`blindindex` → `registry` + `errors` only; `keyprovider`/`cache` → `errors` only. No module imports `api`. `testing` imports the internals it injects into; nothing imports `testing`.

## 2. The client object

The spec's API (§11.1) is five functions plus `warm`, but they need configuration (mode, allow-list, provider). Every core therefore exposes a **client** — one constructed object holding configuration, with the five operations as methods:

```
Fieldseal(config) where config = {
    key_provider     : KeyProvider           (required)
    allowed_suites   : set<suite_id>         (required, non-empty — no implicit "all registered")
    write_suite      : suite_id              (required; MUST be in allowed_suites)
    read_mode        : strict | permissive | readonly    (default: strict)
    cache            : { max_age, max_uses (≤ 2^32), capacity }   (required for EnvelopeKeyProvider)
    index_registry   : declared blind-index configurations (§7 below)
    on_warning       : hook (permissive-mode plaintext reads, StaticKeyProvider outside test)
    metrics          : hook (counters: plaintext_reads, decrypt_errors by type, cache evictions)
}
```

Design rules:

- **Explicit allow-list.** `allowed_suites` has no default. Forcing the deployment to write `["0xFF01"]` is the §4.3 retirement mechanism working as designed.
- **The client is immutable after construction.** Mode changes, suite changes, and provider changes are new clients. This removes a class of concurrency bugs and makes "which config produced this ciphertext" answerable.
- **Construction validates everything**: write suite in allow-list, cache thresholds within §5.5 bounds, every declared index passing the §7.6 cardinality gate or carrying an explicit logged override, StaticKeyProvider triggering the §8 warning outside test configuration.
- Per-language surface (constructor idioms, builder patterns) is defined in the per-language specs; the semantics above are fixed.

**Configuration reflection (normative).** A constructed client MUST be able to report back every element of its validated configuration that affects stored bytes, query results, or read behaviour: at minimum `read_mode`, `write_suite`, `allowed_suites`, the spec §4.8 arming state, and the **validated index declarations** (§7). Values MUST be reported in their **validated, resolved form** — defaults filled in — not as supplied. A client MUST NOT expose its `KeyProvider`, its cache, or any key material through this surface. An accessor MUST NOT permit mutation of the client: a core returning a collection MUST return one the caller cannot use to alter the client's own state, which the immutability rule above otherwise only claims.

*Justification.* The immutability rule states that it "makes 'which config produced this ciphertext' answerable"; immutability is necessary for that and not sufficient, and the sufficient half is being able to ask. Configuration a caller cannot read back is configuration a caller cannot check — the same argument spec §7.4 makes for recording both `b` and the projected population, and §7.6 for the logged override ceremony: a validated decision that leaves no inspectable trace cannot be audited afterwards.

The rule is stated as a principle rather than a field list so that it does not have to be re-litigated as the configuration grows, and the `KeyProvider` carve-out is why it must be a principle at all: "expose the configuration" would otherwise put a handle to the object holding key material on the public surface of every client, which is a strictly larger attack surface than any consumer needs. An index declaration contains no key material — table and column UUIDs, an index id, an IDF name, cost parameters, a normalizer id, a truncation length, a projected population, and two override flags.

**Resolved, not as-declared**, because the two differ in the direction that matters: validation fills in the §7.3 Argon2 minima, the `"exact"` `index_id` default and the §7.2 `refuse` default, so reporting the as-supplied form would let two declarations that agree textually and differ operationally register as a match. That is not hypothetical — it is [#62](https://github.com/fieldseal-dev/fieldseal-spec/issues/62), where one core read the Argon2 cost from a module constant and the other took it per column, agreeing on every shipped vector and diverging the first time an operator raised the cost.

**The index registry is the load-bearing element**, because it is the only part of the configuration whose mismatch produces silent wrong answers rather than an error. A client missing a declared index fails every lookup on that column, visibly. A client carrying an **extra** index derives and stores values for a column under rules no schema states, and nothing ever raises. That asymmetry is why an adapter's registry check must be an exact match in both directions, and why a presence predicate (`has_index(ctx)`) does not satisfy this clause: it can detect the first case and not the second. **None of this is observable through the vector suite** — an accessor is a language-local API surface and no produce/consume run can see one — but unlike §3's erasure steps it is directly testable inside each core, so it carries **no `pinned_decisions` key**: a core without it is non-conformant to this section, not differently configured, and a report key would legitimise the divergence the clause exists to end.

## 3. Operation pipelines

These pipelines are the reference sequence every implementation follows. Steps map 1:1 onto spec clauses; reordering is permitted only where observable behavior (including error codes and timing notes) is unchanged.

**Erasure steps and what they apply to (normative).** Where a pipeline below says *zeroize*, it means best-effort erasure of a value **the core itself derived** — `record_key` and any intermediate plaintext buffer. It never licenses erasing key material a `KeyProvider` returned, which the core does not own (§8.1). Two preconditions bound these steps, and both are honesty obligations rather than escape hatches:

- A binding whose type for the value is **immutable** cannot perform the step. Python's `bytes` is the shipped example. This is permitted, and the binding's language document MUST name the steps it cannot perform (§8.3 already requires each per-language spec to state exactly what its zeroization does and does not achieve; these steps are within that obligation, not outside it).
- Erasure is best-effort everywhere. Spec §5.5 concedes that a garbage-collected runtime cannot guarantee that no copy survives, and no language document may claim more (§8.3).

**None of this is observable through the vector suite.** A wiped buffer and a live one produce identical bytes and identical error codes, so no vector and no produce/consume run can distinguish a core that performs these steps from one that does not. That is why the choice is declared in the conformance report (`pinned_decisions.key-material-ownership`, docs/14 §4) rather than tested.

### 3.1 `encrypt(plaintext, ctx) → envelope`

```
1. mode check: readonly → MODE_VIOLATION                   // §9, §10.3 (G6 resolved)
1b. len(plaintext) > 2^31−1 → LENGTH_EXCEEDED              // §3.5 (G10 resolved); API boundary, like step 1.
                                                           // Order against step 1 is unobservable: no vector
                                                           // pairs the two (§3.5 has no vector at all, §12)
2. validate ctx (purpose = "encrypt"; table/column UUIDs present, 16 B)
3. suite = registry[config.write_suite]
4. (dek, key_id) = key_provider.encryption_key(ctx)        // cache hit expected; MUST NOT do network I/O (§11.1)
5. msg_seed = CSPRNG(32)                                   // §3.1
6. nonce    = CSPRNG(suite.nonce_len)                      // §4.4
7. cc  = canonical_context(ctx)                            // §6.2
8. record_key = HKDF(ikm=dek, salt=key_id ‖ msg_seed, info=cc, len=suite.key_len)   // §5.3
9. commitment = HKDF-SHA-512(record_key, salt "", "fieldseal-commit-v1", 32)  // §4.6, provisional (G1)
10. aad = AAD(fmt_ver, key_id, msg_seed, cc)               // §6.2
11. ct, tag = suite.aead.seal(record_key, nonce, plaintext, aad)
12. return fmt_ver ‖ suite_id ‖ key_id ‖ msg_seed ‖ nonce ‖ ct ‖ tag ‖ commitment
13. best-effort zeroize record_key                          // §3 preamble: derived here, so ours to erase;
                                                           // `dek` from step 4 is NOT (§8.1)
```

Steps 5–6 are the only entropy draws; `testing.encrypt_with_materials` replaces exactly these two steps and nothing else (docs/08 §6).

### 3.2 `decrypt(envelope, ctx) → plaintext`

Proposed check order — **this order is an engineering proposal that must be pinned normatively by the G5 spec issue before error vectors freeze**, because each step's failure maps to a §9 error code and implementations must agree:

```
1.  mode: all read modes may decrypt
2.  structural parse:
      len < min registered envelope length        → NOT_CIPHERTEXT (strict) / pass-through (permissive
                                                    and readonly — §10.3 gives readonly permissive's
                                                    non-envelope behavior, G6 resolved)
      fmt_ver unrecognized                        → UNKNOWN_FORMAT_VERSION *
      suite_id not registered                     → NOT_CIPHERTEXT (recognition, §3.4)
      remaining length inconsistent with suite    → NOT_CIPHERTEXT
3.  suite_id not in allowed_suites                → SUITE_NOT_ALLOWED   (after recognition — §3.4 decoupling)
4.  ctx.suite_id ← header.suite_id                // NORMATIVE-INTENT NOTE: on decrypt, the context's
                                                  // suite_id member comes from the parsed (and now
                                                  // allow-listed) header — NEVER from config.write_suite.
                                                  // A 0xFF02-writing client must still derive the right
                                                  // key for a 0xFF01 envelope (§4.3/§5.6 mixed-suite
                                                  // reads; §5.9 re-encryption sweeps; §3.5 rotate).
                                                  // Tampering is caught: suite_id is bound in the KDF
                                                  // info and AAD (§6.2). Pinned normatively by G5.
5.  candidates = key_provider.decryption_keys(header)      // preference-ordered, all valid versions (§8)
      empty                                       → KEY_UNAVAILABLE
6.  for each candidate dek:
      record_key = HKDF(dek, key_id ‖ msg_seed, canonical_context(ctx))
      if commit_verify(record_key, commitment):   // constant-time compare
          ok = aead.open(record_key, nonce, ct, tag, aad)
          ok                                      → return plaintext (+ zeroize record_key, not the candidate)
          fail                                    → TAG_INVALID       // key+context proven right by commitment;
                                                                      // remaining causes: ct/tag corruption
7.  no candidate's commitment verified            → COMMITMENT_INVALID-or-AAD_MISMATCH [G5]
```

\* Whether `UNKNOWN_FORMAT_VERSION` can be raised at all is subtle: a future `fmt_ver` may not keep `suite_id` at the same offset, so an unrecognized version is *structurally* indistinguishable from non-ciphertext. Proposal for the G5 issue: raise `UNKNOWN_FORMAT_VERSION` when the first byte is a **reserved-known-future** version value and the length is plausible; otherwise `NOT_CIPHERTEXT`. This matches §9's stated meaning ("data written by a newer implementation") while keeping §3.4 recognition sound.

The step-7 ambiguity is real and worth stating plainly: under dual binding (§6.3), a wrong *context* produces a wrong *record key*, so context mismatch and key confusion are cryptographically indistinguishable at this layer. §9 wants `AAD_MISMATCH` distinguished from key problems because "usually a data-migration bug" needs different operator action than "partitioning-oracle attempt." Engineering proposal for the issue: report `COMMITMENT_INVALID`, and — as a **diagnostic, not a control path** — optionally re-derive with known-legitimate context variants (e.g. `row_id` omitted) to enrich the error message with "context mismatch suspected." Vectors then pin only the error code, not the diagnostics.

The spec §3.5 length bound (G10) is deliberately *not* placed in this ordering. Its decrypt-side form reads the received byte count against the suite's fixed overhead, so it is available anywhere between step 2's structural parse and the step-6 allocation, needs neither key nor context, and cannot change which code any other step produces. Implementations apply it before allocating the plaintext buffer; G5 does not have to adjudicate it.

Timing note: commitment verification and tag comparison MUST be constant-time compares. The candidate-key loop's early exit on commitment success is acceptable — commitment values are public envelope content, not secrets — but per-candidate work should be identical in structure.

### 3.3 `blind_index(plaintext, ctx) → bytes`

```
1. mode: readonly MAY compute indexes (needed for queries) — readonly forbids *writes*, and an index
   computed for a WHERE clause is not a write. Normative as of §10.3 (G6 resolved).
2. declaration = config.index_registry[ctx.table_uuid, ctx.column_uuid, index_id from ctx.purpose]
      missing → configuration error (fail closed; never fall back to a default IDF)
3. cardinality gate already enforced at construction (§2); here only assert declaration exists
4. (index_key_material, _) = key_provider.encryption_key(ctx)   // provider MUST return the tenant
      index key, never the DEK, when purpose is "index:…" (§8 / spec §8)
5. index_key = HKDF(ikm=index_key_material, salt="fieldseal-index-v1",
                    info=canonical_context(ctx with row_id=null), len=32)     // §7.2
6. normalized = normalizer[declaration.normalize](plaintext)
7. raw = IDF(index_key, normalized)          // Argon2id or HMAC-SHA-512 per declaration [G2]
8. return truncate(raw, declaration.b)       // §7.2: leading ⌈b/8⌉ bytes, trailing bits of final byte zeroed, MSB-first
```

The return value is the stored form: spec §7.11 makes those exact `⌈b/8⌉` bytes what goes in the column. The core returns bytes and MUST NOT encode them — the hexadecimal alternative §7.11 permits for text-only columns is applied by the adapter's storage layer, which is also where the binary-collation requirement is enforced through DDL. This keeps the bytes-in/bytes-out rule of §5 intact and keeps one representation decision out of five language cores.

### 3.4 `is_ciphertext(bytes) → bool`

Pure function of the registry (spec §3.4): length ≥ min registered envelope, recognized `fmt_ver`, **registered** suite (not allow-listed — recognition ≠ authorization). Never decrypts, never trial-decrypts. Operates on raw bytes only; base64-stored deployments decode at the adapter/storage layer before calling the core (the core is bytes-in/bytes-out everywhere — see §5).

### 3.5 `rotate(envelope, ctx) → envelope`

Mode check first: `rotate` produces ciphertext for storage, so `readonly` raises `MODE_VIOLATION` before any of the below runs (§10.3). Then `decrypt` (full §3.2 pipeline, including allow-list — a retired suite is *not* decryptable even for rotation; un-retiring it for a migration sweep is an explicit, temporary allow-list change, which is the §4.3 model working as intended) followed by `encrypt` under `config.write_suite` and the provider's active-for-write key version. Always produces a fresh envelope (fresh seed, fresh nonce) even when the input is already current — a deterministic "already current, skip" fast path would require comparing key versions, which callers (backfill tooling) can do themselves from the envelope header via the provider; the core stays simple.

### 3.6 `warm(contexts)` (async where the language has async)

Resolves and caches key material for the given contexts before the value path needs it. All KMS/network I/O lives here or in provider background refresh (§11.2). `warm` failures are reported but MUST NOT poison the cache; the value path either hits cache or fails `KEY_UNAVAILABLE` per the deployment's §8.1 degradation mode.

## 4. Envelope codec

- Header layout per spec §3.1; `suite_id` big-endian. Parse produces `EnvelopeHeader { fmt_ver, suite_id, key_id, msg_seed, nonce }` — exactly what `KeyProvider.decryption_keys` receives (spec §8).
- Serialization is single-pass concatenation; total length = 51 + nonce_len + |ct| + tag_len + commit_len, all suite-determined.
- **Plaintext length bounds:** normative as of spec §3.5 (G10, issue #10, resolved 2026-08-09) — reject plaintexts > 2³¹−1 bytes at the API boundary with `LENGTH_EXCEEDED`, and reject on decrypt before allocating when an envelope implies more than the bound. The decrypt-side check reads the received byte count and the suite's fixed overhead only, so it needs no key or context and does not interact with the G5 ordering question. The bound is a ceiling, not a support guarantee: a runtime that fails below it with an allocation error is still conformant, but a 2³¹-byte input MUST produce `LENGTH_EXCEEDED` rather than the platform's error. **[VERIFY at implementation time: the actual buffer maxima for each Phase 1 language — Node `buffer.constants.MAX_LENGTH`, JVM array max, .NET array size limits — and document per core where the platform binds before the spec bound does.]**
- The codec module is where fuzzing concentrates (per-language specs mandate a fuzz/property-test pass over `parse ∘ serialize` and over `is_ciphertext` on arbitrary bytes).

## 5. Byte-orientation and value semantics

The core is **bytes-in, bytes-out** in every language (spec §11.1 signatures). Serialization of application types (strings, ints, JSON) to bytes is the adapter's job, because it is inherently ORM/type-system-specific — with one hard rule inherited from Rails' RCE lesson (`docs/04` §8): adapters MUST use non-code-executing serializations. Nothing in any core ever deserializes bytes into executable or reflective structures.

Base64/text storage (spec §3.3) is likewise an adapter/storage concern: the core never emits or accepts base64.

## 6. Registry

A hard-coded, frozen table — not a plugin surface:

| field | 0xFF01 | 0xFF02 |
|---|---|---|
| aead | AES-256-GCM | XChaCha20-Poly1305 [G7: normative definition source] |
| key_len | 32 | 32 |
| nonce_len | 12 | 24 |
| tag_len | 16 | 16 |
| commit_len | 32 | 32 |
| kdf | HKDF-SHA-512 | HKDF-SHA-512 |

There is deliberately **no registration API**: adding a suite is a code change in every core plus vectors plus a spec revision (spec §4.1's freeze, PRD SP-20's registry process). The table's shape leaves room for a future NIST accordion-mode suite (spec §13.3) without structural change: a suite with `commit_len = 0` (natively committing AEAD) is already representable.

## 7. Blind-index declarations and normalizers

Index configuration is **declared to the client at construction**, not passed per call (spec §7.8 immutability; §7.6 gate at declaration time):

```
IndexDeclaration {
    table_uuid, column_uuid, index_id           // "exact" default; [a-z0-9-]{1,32} per spec §6.1 (G11)
    idf              : argon2id | hmac-sha512   // per §7.3 domain classes
    argon2           : { time_cost, memory_kib } | absent
                                                // argon2id only; absent = the §7.3 minima
    normalize        : normalizer id
    truncate_bits    : b                        // §7.4 band; both b and projected P recorded
    projected_population : P                    // ≥ 16; recorded per SP-10
    cardinality_override : { reason, approved_by, date } | absent   // §7.6 logged override
    on_unindexable   : refuse | bucket          // §7.2; default `refuse`
    unindexable_override : { reason, approved_by, date } | absent   // required for `bucket`
}
```

The validated form of these declarations is what §2's *Configuration reflection* clause requires a client to report back, keyed by `(table_uuid, column_uuid, index_id)`. A core MUST also expose the validation entry point and the registry-key construction publicly: a caller comparing its own declarations against a client's registry needs both to build the same keys and resolve the same defaults, and reconstructing either by hand is exactly the coupling the accessor exists to remove.

**The Argon2id cost is per-column, and §7.3 states it as a minimum rather than a value.** That section fixes `version`, `p`, `output_len` and the salt derivation, and permits a deployment to raise `t` and `m` — a raised pair being a *new index* under §7.8, not a reconfiguration of an existing one. A core that reads the cost from a constant is not merely less configurable than one that takes it per column: the two agree on every shipped vector, because the vectors pin the minima, and they diverge the first time an operator raises the cost on the core that can express it. The column then holds two index values for the same plaintext, and the cross-implementation lookup returns **nothing** rather than raising — the central claim failing in the one place the vector suite cannot see it. Every core therefore MUST take `t` and `m` from the declaration, default them to the §7.3 minima, and refuse at construction (`CONFIGURATION_ERROR`) both a value below either minimum and any value at all on an `hmac-sha512` index, which has no cost parameters. The vector schema carries the pair as `idf_params` (`docs/08` §4.4); the cores name the declaration field `argon2`, Argon2id being the only IDF that has parameters. Recorded as [#62](https://github.com/fieldseal-dev/fieldseal-spec/issues/62) — found in the Python core, which read the cost from a module constant while the TypeScript core took it per column.

The declared normalizer also fixes the **equality that re-verification compares under**: spec §7.5 (G19, resolved 2026-08-26) requires `normalize(stored)` against `normalize(queried)` on the normalizer's output bytes — a column has exactly one equality and the index can serve only it. That is why `normalize` and the normalizer identifiers are **public API** in every core: an adapter that reimplemented `nfc-casefold-v1` for its §7.5 step would be duplicating portability surface where a drift is a silent lookup miss.

Normalizers are a **closed, versioned set** shipped by every core identically (they affect stored index values, so they are portability surface):

- `identity` — bytes unchanged.
- `nfc-casefold-v1` — for email-like text. Defined completely below.
- `digits-only-v1` — strip ASCII non-digits (phone/SSN-like values). ASCII-scoped and defined on bytes; it consults no Unicode table and needs no version pin.

### 7.1 `nfc-casefold-v1` (normative)

The identifier *is* the definition: two cores that compute different bytes for the same input under this name are not both conformant, and the difference is a silent lookup miss rather than an error. All five clauses below are part of what `nfc-casefold-v1` means.

**1. Unicode version: 17.0.0**, for normalization and folding alike. Input containing any code point unassigned in Unicode 17.0.0 MUST be refused with `INVALID_ARGUMENT` — an argument error, not a §9 code (§9 below). A lone surrogate is refused on the same terms, having no UTF-8 encoding.

*Why refuse rather than pass through.* The refusal is what makes the pin exact rather than aspirational. Unicode's Strong Normalization Stability policy (4.1+) guarantees that a string composed only of characters assigned in version *V* normalizes identically under every conforming implementation at *V* or later. Restricting input to 17.0.0-assigned characters therefore buys agreement with every future version, for free. Accepting an unassigned code point buys the opposite: its combining class and decomposition are not yet fixed, so a core built against a later UCD would order and compose it differently — and would do so silently. A visible refusal is the better failure.

*The cost, stated.* A value containing a character encoded after Unicode 17.0.0 cannot be indexed until the pin moves, and what moving the pin costs depends on when it happens — see *Pin currency* below. Refusal is scoped to index derivation: `encrypt` does not normalize, so such a value can still be stored — but an adapter that derives an index on every write will fail that write rather than store a row its own queries cannot find. **Which of those an adapter should do is a per-column decision, not a global one** — §7.2's `IndexDeclaration.on_unindexable`, defaulting to refusal (G16 part B, closed 2026-08-25). The adapter obligation is in `docs/12` §10 and `docs/13` §9; an earlier version of this paragraph pointed at "§12" of each, and no such section existed in either, which is part of what G16 was filed about.

***Pin currency (normative).*** Unicode publishes a version roughly every September, so a pin with no policy behind it drifts by default and the project ships one version behind on its own launch day. The rule has two regimes, divided by the format freeze (PRD §8, Gate 0b):

- **Before freeze**, `nfc-casefold-v1` **tracks the most recent *released* Unicode version**, and the pin moves by **redefining `v1` in place**. This is legitimate only here: there are no stored index values to preserve, no frozen suite identifier naming the construction, and the vector suite is provisional, so a redefinition costs a regenerated `blind-index/` family and nothing else. A pin bump before freeze SHOULD therefore happen as soon as a release is available.
- **After freeze**, the same move MUST mint a new identifier (`nfc-casefold-v2`) and MUST be accompanied by a planned re-index. The identifier *is* the definition (§7 preamble), so redefining `v1` in place would silently change what every existing stored value means — two cores at different versions would agree on the name and disagree on the bytes, which is the precise failure this section exists to prevent.

The cost of a bump therefore rises discontinuously at the freeze, not gradually with stored data. **Deferring a bump past the freeze is a decision to keep the older pin permanently, or to pay for a new identifier and a migration later.**

*A released version, not merely a numbered one.* A bump MUST be to a version unicode.org has **published**, and an implementation generating its tables MUST fail rather than fetch a version path that redirects. Measured 2026-08-25, `https://www.unicode.org/Public/18.0.0/ucd/` answered `302` to `http://www.unicode.org/Public/draft/ucd/` for all three consumed files — an unreleased version's path is served as the *moving* draft, and over plaintext HTTP at that. A generator following that redirect produces tables from a draft, labels them with a release number, and cannot reproduce them a week later. `tools/ucd-gen/generate.py` refuses redirects, refuses non-HTTPS hops, and verifies that the URL that answered is the URL requested; `tools/ucd-gen/test_generate.py` holds those guards and runs in CI. This is a build-integrity requirement rather than a portability one, but it fails the same way if ignored: a wrong table is a silent lookup miss.

*Status.* The pin is 17.0.0, which is the current release. Unicode 18.0 is in draft with a stated September 2026 target; under the rule above it is adopted once released, in place, provided the freeze has not happened first. **No tracker issue carries the bump and none is needed** — the rule above is self-executing, and `tools/ucd-gen/` refuses to fetch an unreleased version at all: as of 2026-08-25 `Public/18.0.0/ucd/` 302-redirects to `Public/draft/ucd/` over plaintext HTTP, and the generator rejects the redirect, the protocol downgrade, and any served URL that is not the one requested. So the pin cannot move to a draft by accident, and the `unicode-tables` CI job fails if the vendored tables stop matching whatever version is pinned. G16 part C (tracker [#60](https://github.com/fieldseal-dev/fieldseal-spec/issues/60)) closed 2026-08-25 on the policy and the guards; the bump itself waits on the release.

**2. Folding: `CaseFolding-17.0.0.txt`, statuses C and F only**, applied per code point. No `T` (Turkic) mappings: they make the result depend on the caller's locale, and a blind index has no locale. No `S`, which `F` supersedes wherever both exist. This is "full case folding" as UAX #44 defines it — `ß` folds to `ss`, not to `ß`.

**3. Normalization: NFC at 17.0.0.** A core MAY take NFC from its platform **only if** the platform's Unicode version is at least 17.0.0 *and* the core demonstrates agreement with the pinned tables exhaustively in its own test suite. Otherwise it MUST vendor the normalization data.

Refusing code points newer than the *platform's* version, as a way to use an older platform normalizer, is **not** a conformant route. It would make the set of accepted inputs a property of the deployment's runtime: one core would index a value that another refuses, both would pass the whole vector suite, and neither report would show it. "A accepts what B rejects" is an interoperability failure of the same kind this specification exists to prevent, and it is invisible to the vectors precisely because the vectors contain no such characters.

Both reference cores vendor both tables rather than taking either from the platform. `tools/ucd-gen/generate.py` generates them from the published UCD; CI re-runs it with `--check`, so a hand-edited table fails the build.

**4. A second normalization after folding.** The output of clause 2 is normalized to NFC again and then UTF-8 encoded. `nfc-casefold-v1` is therefore:

```
NFC( toCasefold( NFC( X ) ) )
```

*Why the second pass is not optional.* Without it this is a deterministic function that is not a caseless-matching one, and caseless matching is the entire reason the normalizer exists. Folding a precomposed character can produce a decomposed sequence, so one letter written in two cases lands on two index values: U+0390 (ΐ) folds to `U+03B9 U+0308 U+0301`, while the same letter spelled in uppercase as `U+03AA U+0301` folds to `U+03CA U+0301`. Those are canonically equivalent — one lookup to a user — and two different blind indexes to the database. Measured over UCD 16.0.0, dropping the second pass fails to collide 12 case/canonical variant pairs at the code-point level and 302 letter-plus-combining-mark strings in the BMP; restoring it fixes 8 and 294 of those respectively and breaks none.

*This is not Unicode's canonical caseless match*, which is `NFD(toCasefold(NFD(X)))` and outputs NFD. Documents MUST NOT describe `nfc-casefold-v1` as canonical caseless matching. NFC is chosen for the final step because it is shorter as a stored value; over the BMP below U+2000 the NFC form is 7,467 UTF-16 units against NFD's 8,536.

**5. Bytes input is decoded as strict UTF-8** before clause 1; a decoding failure is `INVALID_ARGUMENT`. Decoding with replacement characters would map distinct malformed inputs onto one index value, which is a false-match primitive rather than a leniency. A text-typed API (Python `str`, JavaScript `string`) reaches clause 1 directly.

> **Where the refusal has to live (normative).** **An index-derivation API MUST accept the language's text type**, not bytes alone — Python `str`, JavaScript `string`, Java `String`, .NET `string`, Go `string`. A caller MAY still pass bytes, which clause 5 decodes strictly.
>
> The reason is that the encoding step is lossy in one direction only, and in the direction that matters. `TextEncoder` and its equivalents substitute U+FFFD for an unpaired surrogate rather than failing (WHATWG Encoding requires it), and U+FFFD is an assigned character, so a core that receives only bytes sees well-formed UTF-8 and cannot tell. Two distinct malformed values reach one index. That is a false match manufactured inside the construction whose purpose is to prevent them, and it is invisible to the vectors and to the conformance report, because the collision happens before the core is called.
>
> An earlier version of this section put the obligation on the caller instead — "a core that accepts bytes only MUST expose the assigned-code-point check, and an adapter encoding on the core's behalf MUST apply it before encoding." That is unenforceable: it is advice to a frame the core cannot inspect, a missed call raises no error and fails no test, and integrations the project does not write are outside its reach. It was also actively countermanded in one core, whose refusal message told callers that encoding was the adapter's job and thereby named the substituting conversion as the way in. Accepting text does not merely add a backstop behind that path; it removes the trap, because the safe call becomes the obvious one.
>
> Cores MUST still export the assigned-code-point check (`first_unassigned` / `firstUnassigned`) for adapters that hold the text earlier and can give a better-sited error, and clause 5's strict decode still governs the bytes path. Neither is the mechanism any longer.

**Satisfied 2026-08-31 (G22, [#88](https://github.com/fieldseal-dev/fieldseal-spec/issues/88)), and the signature is part of the requirement.** The check returns the offending code point **and its offset in code points** — not the code point alone, which is what both cores returned while the MUST went unexported. `docs/12` §10.2 requires a rendered message to name the character *and its position*, so a check that answers only half of that leaves an adapter parsing the core's error text for the rest, which is the dependency this clause exists to remove. The unit is code points, not UTF-16 units: it is what §10.2's own example counts ("3rd character"), and it is the only unit every target language can produce without extra work. `UNICODE_VERSION` / `unicode_version` is exported alongside it, because an adapter rendering "not assigned in Unicode 17.0.0" that keeps its own copy of the version has two copies to drift.
>
> *A note on the resulting asymmetry.* `encrypt` remains bytes-only while `blind_index` takes text. This is deliberate and is not to be tidied away: normalization is a text operation and encryption is not, so index derivation is the only place where the difference between a string and its encoding changes the answer. The Python core has had exactly this asymmetry since it was written.
>
> *Rejecting U+FFFD outright was considered and declined.* It is an assigned character that legitimately occurs in text; refusing it would convert this false match into an unindexable row, which is the failure mode of `on_unindexable` below. It would also catch only one symptom of one cause — the same naive truncation can cut between a base character and its combining marks, or mid-grapheme in a legitimately composed name, producing text that is valid and merely wrong. It remains available as an opt-in per-column data-quality check, and is not part of the normalizer.

Custom normalizers are out: a deployment-defined normalizer is a portability break by definition. New normalizers go through the same process as suites (spec change + vectors).

`index_id` is validated against the spec §6.1 `index-id` grammar at declaration time and rejected as a `ConfigurationError` if it fails — fail closed, before any derivation string is built. This is construction-time validation, so it has no §9 error code (docs/09 §9); the `context/` vector family pins the refusals (docs/08 §4.3).

### 7.2 Unindexable values: `on_unindexable` (normative)

`encrypt` does not normalize and `blind_index` does, so the two operations disagree about what they can accept. A value containing a code point the pin does not define **encrypts perfectly well and cannot be fingerprinted** (§7.1 clause 1). That leaves an adapter with a choice no earlier version of this document made: fail the write, or store a row that its own queries can never find.

Neither horn is acceptable as a global default. A required, searched-on column — a login email — is worse unfindable than un-writable. A column holding a person's name is the opposite: refusing it is a hard failure for that person, and "your name is unsupported" is not a message any product wants to send. **`on_unindexable` is therefore declared per column**, because the right answer differs per column and a single rule is wrong somewhere.

```
on_unindexable = refuse   (default)
    Index derivation raises INVALID_ARGUMENT (§7.1 clause 1, unchanged).
    An adapter deriving an index on write fails the write.

on_unindexable = bucket
    Index derivation returns the declaration's `unindexable_marker`
    instead of raising. The row is stored and remains findable.
```

**The marker (normative).** `bucket` MUST NOT store *no* index — an absent index value is the silent-missing-row failure this whole section exists to prevent, and spec §10.2 forbids it by name. Instead the value is derived, exactly like any other index value:

```
RESERVED_PREIMAGE  = 0xFF || "fieldseal-unindexable-v1"      (25 bytes)
unindexable_marker = truncate(IDF(index_key, RESERVED_PREIMAGE), b)
```

Two properties do the work. The leading `0xFF` **can never appear in UTF-8**, so no input `nfc-casefold-v1` accepts can normalize to this preimage: the marker cannot collide with a real value by construction rather than by luck. And because it is derived under the column's own `index_key`, it is a per-column, per-tenant value that **looks like every other index value** to anyone reading the column. A fixed constant — all-zero bytes, say — would announce to an observer with no key exactly which rows hold a character the pin does not define.

**Why this needs nothing from the query path.** The marker is returned on *lookup* as well as on write, because the same value normalizes the same way whichever direction it is travelling. So a query for an unindexable value derives the marker, matches the bucketed rows, and spec §7.5 re-verification — already mandatory and unconditional for every index hit — decrypts the candidates and keeps the ones that match **under §7.5's comparison rule** (G19, resolved 2026-08-26: equality under the index's declared normalizer; for a bucket column the normalizer *refuses* these values, so the comparison falls back to their raw bytes — two different unindexable values sharing one marker are separated by exactly this step). A query for an *indexable* value derives an ordinary index value and never touches the bucket, since a bucketed row by definition contains a character no accepted value can contain.

> This is a correction to how the mechanism was first described in G16 part B, which had every indexed lookup additionally probe the marker. That is unnecessary and strictly worse: it doubles every query's candidate set to no purpose and widens the leak below. Equality lookup already works, because the bucket is not a special case in the query path — it is one more collision class in an index that spec §7.4 *mandates* collisions in.

**The cost, stated.** The bucket is an equivalence class that can grow far larger than §7.4's expected `P × 2^(−b)`, so it is **distinguishable by frequency**: an observer who can read the index column sees one value that is unusually popular, and can infer that those rows share the property "contains a character outside the pin". That observer cannot tell *which* character, cannot compute the marker without the index key, and learns nothing about any other column. The class is also **growable by anyone who can write to the column**, so a hostile writer can inflate it and make lookups against it progressively more expensive — bounded by §7.5 re-verification cost, not by anything cryptographic. A column where either property is unacceptable keeps `refuse`.

**Declaring `bucket` requires the §7.6 ceremony.** `unindexable_override` MUST carry `{ reason, approved_by, date }`, refused as a `ConfigurationError` if absent. This is deliberately the same shape spec §7.6 already requires to relax the cardinality gate: relaxing a default-deny rule on a column is a reviewed, recorded act, not a configuration default that gets copied between columns. A declaration whose normalizer can never refuse (`identity`, `digits-only-v1` — neither consults a Unicode table) is also a `ConfigurationError` under `bucket`: the setting could never take effect, and silently accepting it would misrepresent the column as protected.

**What `refuse` obliges the adapter to do.** A refusal is only humane if the value can still be stored by *someone*, so `refuse` and `bucket` are specified as a pair: `bucket` is the escape hatch behind the refusal, applied per column by an operator, not a dead end. `docs/12` §10 and `docs/13` §9 carry the resulting adapter obligation and the shape of the message — including the three rules a refusal message must satisfy: name the character and its position, put the fault on the system, and offer a route that ends with the real value stored.

**Vectors.** The marker's *bytes* are pinned, not merely its behaviour: two cores deriving different markers would put their unindexable rows in two different buckets, and a lookup across them would silently return nothing — the failure this setting exists to prevent, reintroduced by the fix. `blind-index/` carries `unindexable-marker-b15` (the derivation) and `unindexable-bucketed-b15` (that a refused value lands on it, and that `refuse` still refuses), from suite `0.3.0-provisional`.

## 8. Key providers and cache

### 8.1 Interface (spec §8, made concrete)

```
KeyProvider:
    encryption_key(ctx)  → (key_material, key_id[16])
        // purpose "encrypt"  → tenant DEK (active-for-write version)
        // purpose "index:*"  → tenant INDEX key (sibling, never the DEK) — spec §8
    decryption_keys(header) → ordered list of key_material
        // all currently-valid versions, active first (§5.6)
    warm(contexts)       → async prefetch (§11.2)
```

`key_id` structure is provider-defined and opaque to the core (spec §3.1). `EnvelopeKeyProvider`'s recommended layout — documented, not normative: 4 B provider tag ‖ 8 B tenant-key handle ‖ 4 B version. Rationale: `decryption_keys` must resolve versions from the header alone.

**Ownership of returned key material (normative).** Key material returned by `encryption_key` and `decryption_keys` is **owned by the provider**. A core MUST NOT mutate or erase it, and MUST NOT retain a reference to it beyond the call that obtained it. A core that needs erasable material MUST copy first and erase its own copy.

*Justification.* Without this rule the signature alone decides the question, and it cannot: a returned byte string may be a fresh copy or a reference into the provider's own cache, and the two are indistinguishable to the caller. A core that erases what it was handed silently destroys the second kind — the next derivation runs against zeroes and the failure surfaces as `COMMITMENT_INVALID` on a read of data written moments earlier, a decrypt-side error for a write-side memory bug with nothing pointing at the provider. The rule is stated in this direction, rather than as "the core owns and MUST erase", for three reasons. It is implementable in every target language, where the converse is not: a binding whose key material is an immutable type cannot erase anything, so a MUST to erase would be one a conformant core could not meet. It fails safe in both directions — a provider handing over a copy loses nothing under a borrow rule, while a provider handing over its cache is destroyed under an ownership rule. And it costs the core almost nothing: what it declines to erase is a per-call copy of material the cache holds anyway, and §8.3 already zeroizes on eviction.

The corollary for providers is worth stating, because it is where the cost lands: a provider that wants its returned material erased MUST erase it itself, on its own schedule. Returning a copy remains the safe default and is what the three shipped providers do.

**Candidate reads are not uses (normative).** `decryption_keys` MUST NOT count against §8.3's `max_uses`. §8.3 states use counting only from the write side — incremented per `encryption_key` return — and the read-path half has to be said rather than inferred: a decrypt resolving four candidate versions would otherwise spend four uses of a budget spec §5.5 defines as a limit on **encryptions** under one key, and a rotation sweep would evict the key it is reading with. The candidate list is a read of what the cache already holds.

### 8.2 The three shipped providers

- **StaticKeyProvider** — one key, warning outside test config (spec §8). Its warning fires through `on_warning`, not a log side effect, so embedders can escalate it to a hard failure.
- **DerivedKeyProvider** — tenant DEK = HKDF(root_secret, salt=provider-defined, info=tenant scope); index key derived with a distinct info label so the sibling rule (§5.2) holds even in the derived provider. No network I/O by construction.
- **EnvelopeKeyProvider** — KMS-wrapped DEKs; the production path. Unwrap happens **only** in `warm`/background refresh; `encryption_key`/`decryption_keys` are cache-only and MUST NOT block on network (spec §11.1). On cache miss the behavior is the deployment's §8.1 degradation mode: `fail-closed` → `KEY_UNAVAILABLE`; `serve-cached` is the same thing on the read path (that mode's meaning is *only* "what the cache can decrypt"). KMS SDK integration is per-language and pluggable behind a small `Wrapper` interface (`wrap(dek) / unwrap(blob)`), keeping cloud SDK dependencies optional.

### 8.3 DEK cache (spec §5.5)

- Keyed by (provider scope, tenant, key version, role: dek|index).
- Eviction: max-age AND max-uses (≤ 2³²) AND capacity LRU. Use counting is per cached entry, incremented per `encryption_key` return.
- **Zeroization on eviction is best-effort and honesty-documented per language** — GC languages cannot guarantee no copies (spec §5.5's own "honest limitation"). Each per-language spec states exactly what its zeroization does and does not achieve; no language doc may claim guaranteed erasure.
- `mlock`/no-swap: SHOULD where the platform supports it (spec §5.5). Python and Node cannot do this meaningfully for GC-managed buffers; both per-language specs document the deviation instead of pretending.
- Concurrency: single-flight on refresh (one KMS unwrap per key even under concurrent misses), lock-free or fine-grained-locked reads; the value path never blocks on another tenant's refresh.
- Metrics: hits, misses, evictions by cause, age distribution — the §5.5 "TTL is a security parameter" stance needs observability to be auditable.

## 9. Errors

One root type per language (`FieldsealError`) with exactly the §9 taxonomy as subtypes/codes: `UNKNOWN_FORMAT_VERSION`, `SUITE_NOT_ALLOWED`, `KEY_UNAVAILABLE`, `AAD_MISMATCH`, `TAG_INVALID`, `COMMITMENT_INVALID`, `NOT_CIPHERTEXT`, `MODE_VIOLATION` (added to §9 by G6), `LENGTH_EXCEEDED` (added by G10; spec §3.5), plus a configuration-error code for construction-time failures that remains implementation-local — §9 does not define one, because construction never reaches the crypto path or the vectors. Messages carry: error code, suite_id, key_id (hex — it is public envelope content), context identifiers (table/column UUIDs — public by §6.5), and never plaintext, key material, or derived keys (§9). The vector-suite error strings map 1:1 to these codes; the mapping table lives in each per-language spec and is exercised by the `errors/` vectors.

## 10. Concurrency and process model

- The client is thread-safe after construction (immutable config + concurrent-safe cache). All five sync operations are re-entrant.
- No global mutable state; multiple clients with different configs coexist in one process (needed for `readonly` analytics alongside `strict` serving, §10.3).
- Fork-safety: CSPRNG must be fork-safe (per-language: Python `os.urandom`/`secrets` — kernel-backed, fork-safe; Node `crypto.randomBytes` — kernel-backed). Cache contents surviving a fork are DEK copies in the child — documented as part of the §5.5 memory-exposure honesty, with guidance to construct clients post-fork in prefork servers (gunicorn/uwsgi).

## 11. What the core deliberately does not contain

Restating spec §11.3 as a review checklist: no SQL, no ORM types, no row/column names (only opaque UUID surrogates), no HTTP, no KMS SDK in the required dependency set (optional provider extras only), no logging framework dependency (hooks only), no plaintext persistence of any kind, no telemetry with values in it.

On async: the five operations are synchronous in every core, and that is not negotiable (spec §11.1). Spec §11.1 does now permit *additional* async companions (G9, issue #9), but a core that ships them owes byte-identical output, identical error codes, a suite run through both paths, and a sync implementation that is not merely a blocking wait on the async one. Whether to ship them at all is a per-language decision recorded in that core's tech spec, not a default.

## 12. Cross-language consistency table

| Concern | Rule |
|---|---|
| Public operation names | `encrypt`, `decrypt`, `blind_index`, `unindexable_marker`, `is_ciphertext`, `rotate`, `warm` — snake_case or the language's casing of the same words; no synonyms |
| Index parameters | supplied by the `IndexDeclaration` given at construction (§7), never as arguments to `blind_index`. The §7.4 band and the §7.6 cardinality gate are properties of a column, so they are checked once, where the column is declared, and a declaration that fails never reaches a key derivation |
| Argon2id cost | `t` and `m` come from that declaration and default to the spec §7.3 minima; below either minimum, or present at all on an `hmac-sha512` index, is refused at construction. `version`, `p`, `output_len` and the salt derivation are fixed by §7.3 and are fields on nothing |
| Bytes type | Python `bytes` in/out · TypeScript `Uint8Array` in, `Buffer` out (Buffer is a Uint8Array) · future cores: idiomatic byte type |
| FieldContext | identical field names as spec §6.1; constructed once per column by adapters, not per call. The `suite_id` member is filled by the **core**, never the adapter: `config.write_suite` on encrypt, the parsed header on decrypt (§3.2 step 4) |
| Assigned-code-point check | `first_unassigned` / `firstUnassigned` (§7.1's MUST), returning the code point **and its offset in code points** under one shared type name, `Unassigned` — a NamedTuple in Python, an interface in TypeScript. The unit is part of the contract: UTF-16 offsets are an artifact of one binding's string type, and `docs/12` §10.2 renders the position to a person as "the Nth character". `UNICODE_VERSION` / `unicode_version` is exported beside it, so no caller keeps its own copy of the pin to drift. (Row added by G22, [#88](https://github.com/fieldseal-dev/fieldseal-spec/issues/88); the two cores had shipped the same concept under two type names, which is what this table exists to catch.) |
| Error codes | identical strings to §9, exposed as a machine-readable `code` property |
| Testing namespace | `fieldseal.testing` / `@fieldseal/core/testing` — same function name `encrypt_with_materials` |
| Vector harness output | the shared report format of `docs/14-conformance-ci.md` §4 |
