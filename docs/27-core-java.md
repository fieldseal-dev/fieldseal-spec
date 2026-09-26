# Java Core Technical Specification

**Date:** 2026-09-22 · **Status:** Draft 1, the tech spec the Java core is built against; stages S1 (scaffold and CI), S2 (capability audit) and S3 (envelope codec, registry, errors) of §8 are built, and the core itself holds no cryptographic code yet · **Purpose:** the Java/JVM binding of [`docs/09-core-architecture.md`](09-core-architecture.md), in the shape of `docs/10` and `docs/11`. It is the first Phase 2 core (WS-I, [`docs/26-phase-2-plan.md`](26-phase-2-plan.md) §2) and the third implementation of the format. It is built under the `docs/17` isolation protocol, against the vector inputs and the specification, never against another core.

**Where it came from.** This document is the JVM core design drafted and reviewed on 2026-09-19, made into a repository document when Phase 2 opened (`docs/26` §1 item 3). On the way in, it lost what was true only on the day it was drafted:
- its premise that `docs/09` §4's buffer-maxima flag waited on this core ([#167](https://github.com/fieldseal-dev/fieldseal-spec/issues/167) and #168 turned that flag into a per-binding obligation, which §6 here discharges);
- the report-contract gap it proposed to fix, which [G26](https://github.com/fieldseal-dev/fieldseal-spec/issues/176) has since closed;
- its references to working files outside the repository.

Its review record is kept as §0, because the corrections listed there are the evidence the design was checked.

**Library-fact caveat:** as in `docs/10` and `docs/11`, a claim about a platform or library API that has not been run on this core's toolchain is marked **[VERIFY]**. Each is resolved at the capability-audit stage (S2, §8), as *confirmed* or *corrected*, with a dated `docs/07` §7 entry (`docs/07` §4). **S2 resolved all of them on 2026-09-24** (`docs/07` §7, that date). Where it corrected a claim, the text below now states what was measured, and names the correction.

**Reading path for the implementer (normative for this workstream):**
- `docs/02-spec-v0.1.md` (the authority);
- this document;
- `docs/08-test-vector-spec.md` §4–§6;
- `docs/09-core-architecture.md`;
- `docs/14-conformance-ci.md` §4;
- `docs/17-m2-implementer-brief.md`;
- `vectors/` itself.

Do **not** open, read, grep or list `core/python/**`, `core/typescript/**`, `core/dotnet/**` or `tools/vector-gen/**`. The independence rule (`docs/17` §1) applies to the third core exactly as it did to the second, and a sibling binding is an implementation, not a specification (`docs/26` §2.2).

**This document is a read input, and its authors read more than the implementer may.** The 2026-09-19 reviewer read the TypeScript harness (`core/typescript/tests/harness/run.ts`) for §0. The session that wrote this document had read small ranges of that harness, of `core/typescript/src/registry.ts` and of `core/python/tests/run_vectors.py` while implementing G26. Nothing here about the shipped cores comes from those reads where a public document says it: such facts are cited to `docs/11`, `docs/14`, `docs/18` or the G26 record. The implementer's isolation statement names this document. Where it is wrong, that is a bug in this document, and it goes in the divergence log (`docs/17` §5 item 4). The session that wrote it does not implement the core (`docs/26` §2.2).

---

## 0. Review record, 2026-09-19

A second agent reviewed the first draft of the design against the repository and against primary platform sources. What it changed, and why, follows. Two items it left open have been settled since, and §0.3 says how.

### 0.1 Corrections of fact

| Draft said | Correct | Evidence |
|---|---|---|
| "Phase 1-plus", "not in the PRD Phase 1 window" | The JVM core is PRD **Phase 2** | `docs/01-prd.md` §8, Phase 2 |
| `SOFT_MAX_ARRAY_LENGTH` = 2³¹−8 = 2,147,483,639 | `Integer.MAX_VALUE - 8` = 2,147,483,639 = **2³¹−9** | `openjdk/jdk` master, `jdk/internal/util/ArraysSupport.java`, fetched 2026-09-19 |
| "public `java.util.ArraysSupport` since JDK 22" | No such public class exists; `ArraysSupport` is `jdk.internal.util` only | `java/util/ArraysSupport.java` returns 404 on `openjdk/jdk` master |
| A 2³¹−1 plaintext gives an envelope of "~2³¹+103" bytes | 2³¹−1 + 111 = **2³¹+110** | spec §3.1: overhead 1+2+16+32+12+16+32 = 111 |
| JCA GCM: `update` returns ct, `doFinal` returns the tag, so the core needs a "split-tag dance" | Encrypt `doFinal` returns the final ciphertext bytes **followed by** the tag, and decrypt takes ct‖tag as one input. Spec §3.1 places `ciphertext` and `tag` **contiguously**, so there is no split to get wrong (§5.1) | spec §3.1 layout; the JCA `Cipher` AEAD contract |
| `HKDFParameterSpec.ExtractExpand`, `deriveData(..., 32)` | `HKDFParameterSpec.ofExtract().addIKM(..).addSalt(..).thenExpand(info, 32)` yields `HKDFParameterSpec.ExtractThenExpand`, and `KDF.deriveData(spec)` takes only the spec | `javax/crypto/spec/HKDFParameterSpec.java`, `javax/crypto/KDF.java`, fetched 2026-09-19. Moot at the JDK 21 floor (§1), which does not use this API |
| On JDK 21, HKDF "must fall back to BouncyCastle" | RFC 5869 over `javax.crypto.Mac` (`HmacSHA512`) is about 20 lines, is available on every JDK, and the `kdf/` family checks it. A JDK 21 floor costs no dependency | RFC 5869 §2 |
| Argon2id salt: "32-byte salt handling" in one place, "16 bytes" in another | **16 bytes**, derived by HKDF-SHA-512 with `info = "fieldseal-argon2-salt-v1"` | spec §7.3, the Argon2id invocation block |
| bcprov is "the mainstream FIPS-listed pure-Java crypto provider" | `bcprov-jdk18on` is **not** FIPS-validated; the validated module is the separate `bc-fips` artifact. The claim is removed | BC distribution naming. **Resolved at S2: `bc-fips` carries no Argon2.** Its current release, 2.1.3, has no class whose name contains "argon" (0 of 7,004 jar entries; it ships scrypt). A FIPS-validated BouncyCastle build therefore offers no Argon2id path, which matters only if CL-9 FIPS conversations ever reach this core |
| CSPRNG "seeded via the strongest available source" | `SecureRandom.getInstanceStrong()` can block on Linux. Use `new SecureRandom()`, the platform default, which does not block. The JVM does not `fork()` a running VM, so `docs/09` §10's prefork guidance does not apply | JDK `SecureRandom` documentation |
| Node's `MAX_LENGTH` "≈ 2⁵³" on "Node ≥ 22"; a 32-bit Node figure | `docs/18` measured `buffer.constants.MAX_LENGTH` = 2⁵³−1 **on Node 24 x64**, and the TypeScript core targets Node ≥ 24.7. The 32-bit figure had no source and is dropped | `docs/18` §4 |

### 0.2 Structural changes

1. **The binding doc is written first, not last.** `docs/17` §2 and §5 item 1 have the implementer build "per the module layout and API shape in the language binding doc", and `docs/10` and `docs/11` existed as tech specs before their cores did. This document is that tech spec; stage S8 (§8) updates it as built.
2. **The draft's "reachability audit by reflection" is replaced** (§6.2). Reflection can list methods but cannot see the order of statements inside one. The replacement is a behavioural test through an internal operand seam: a synthetic 2³¹-long operand whose content accessors throw, and a spy provider that must record zero calls. `docs/09` §4 has named this seam as architecture since G26.
3. **The platform-maximum probe is informational, not a gate** (§6.4). The unrepresentability argument rests on the **type** (`byte[].length` is `int`, so no operand reaches 2³¹), not on any measurement. The probe earns its place by naming the real ceiling in this document.
4. **An out-of-band entry the draft had missed is added:** `docs/09/7.1/lone-surrogate-refusal`. `java.lang.String` is UTF-16 and **can** hold an unpaired surrogate, so this core runs the entry and passes it directly (§6.5).
5. **Memory claims include JCA's own buffering** (§6.3). SunJCE's GCM decryption holds back plaintext until the tag verifies, so it buffers about the size of the operand internally. The draft's "the only allocations on the decrypt path are…" was not true of the platform cipher. *(S2 corrected this review item in turn: the buffering happens only when ciphertext arrives through `update()`. A single `doFinal`, the call §5.1 prescribes, allocates no operand-sized buffer; §6.3 has the figures.)*
6. **`max-uses` is a `long`.** Spec §5.5 allows max-uses up to 2³², which does not fit in an `int`: the same int/long hazard as the buffer bound, in a place the draft did not look (§4, §7).
7. **The module layout uses JPMS properly** (§3). A module exports packages, not classes, so the draft's flat class list could hide nothing. `testing` becomes a separate Gradle subproject and artifact, which is how "never exported from the main module" (`docs/09` §1) reads on the JVM.

### 0.3 What the review left open, and how it closed

- **The JDK floor.** Decided **21** by the maintainer on 2026-09-22 (`docs/26` §5 item 1, `docs/07` §7). The ground is that the Hibernate adapter is in Phase 2's scope and is the reason this core exists. The draft's claim that Hibernate deployments skew toward 17 and 21 is unsourced and is not part of that ground.
- **The report-contract gap.** Applied literally, `docs/14` §4 gave this core `not-run` on both length-bound entries forever. G26 ([#176](https://github.com/fieldseal-dev/fieldseal-spec/issues/176), closed 2026-09-22) added the `basis` field and the seam route, so this core can record `pass` with `basis: "seam"` under the conditions in §6.5.
- **Still open:** the Maven coordinates. A group id such as `dev.fieldseal` needs its namespace verified on Maven Central before anything is published under it, and nothing is published under this document outside PRD §8's five experimental-release conditions (§10).

---

## 1. Package identity and toolchain

| Item | Decision | Notes |
|---|---|---|
| Location | `core/java/` | Stage S1 since 2026-09-23: the Gradle scaffold, the module skeleton and the `java-core` job. Stage S2 since 2026-09-24: `CapabilitiesTest` and the `java-memory-probe` job. Stage S3 since 2026-09-24: the codec, the registry and the error taxonomy. Stage S4a since 2026-09-25: the crypto primitives (`context`, `kdf`, `aead`, `commitment`). Stage S4b since 2026-09-25: the key providers, the `DekCache` and the client |
| Build | Gradle 9.x, `foojay-resolver-convention` toolchains | A pinned JDK patch; nightly legs float the latest patch (`docs/14` §5) |
| JDK floor | **21 (LTS)** | §0.3. HKDF is written over `Mac` (§5.2); JEP 510's `javax.crypto.KDF` arrives with JDK 25 and is not used |
| Module | `dev.fieldseal.core`, plus `dev.fieldseal.core.testing` as a separate artifact | Final names follow the governance decision on coordinates (§0.3) |
| CI | a `java-core` job in `.github/workflows/conformance.yml` | Mirrors the Python and TypeScript jobs; uploads `conformance-java.json` |

**Joining the shared jobs** is the list WS-L left in the workflow (the comment above `cross-produce`, and `docs/14` §2–§3):
- a `needs` entry, a named download and `java` in `--cores` for `cross-core-result-ids`;
- a `java` entry in `cross-produce`'s matrix, with its produce steps;
- `java` in the workflow's `CROSS_PRODUCERS`;
- a `java` consumer in `cross-consume`, with its consume steps.

No change to the comparison or to the existing consumers is needed.

## 2. Dependencies

| Need | Choice | Notes |
|---|---|---|
| AES-256-GCM, HMAC-SHA-512, constant-time compare, CSPRNG | the JDK (SunJCE, `SecureRandom`) | No third-party crypto for suite `0xFF01` apart from Argon2id |
| HKDF-SHA-512 | written in the core over `Mac.getInstance("HmacSHA512")` | RFC 5869; about 20 lines; checked by `kdf/` (§5.2) |
| Argon2id (spec §7.3) | `org.bouncycastle:bcprov-jdk18on` 1.86, **for Argon2id only** | SunJCE has no Argon2. BouncyCastle is pure JVM, while `argon2-jvm` goes through JNA to native code. **Confirmed at S2:** the class names (`org.bouncycastle.crypto.generators.Argon2BytesGenerator`, `org.bouncycastle.crypto.params.Argon2Parameters.Builder`), and that `withVersion(ARGON2_VERSION_13)`, `withParallelism(1)` and a 16-byte salt reproduce all 12 `raw` values in `blind-index/argon2id.json`, at both cost points it pins (t = 3 and t = 4, m = 32768). **The salt, answered:** the builder copies it (`withSalt`), `build()` copies it again, and `getSalt()` returns a copy. `Builder.clear()` and `Argon2Parameters.clear()` erase the two copies they hold, and the core is to call both (S5). A third copy, taken through `getSalt()` inside every `generateBytes` call, is never erased; that is read from the 1.86 bytecode, since no test can observe it, and §5.4 counts it. The builder also caps `m` at 2²⁴ KiB (16 GiB) through the system property `org.bouncycastle.argon2.max_memory_exp`, far above any cost spec §7.3 contemplates |
| Tests only | JUnit 5, jqwik (property and fuzz testing), Jackson (vector JSON), ArchUnit | None of these ships in the published artifact |

## 3. Module layout

Package root `dev.fieldseal.core`. The packages mirror `docs/09` §1's modules, so that JPMS can hide them:

```
core/java/
  fieldseal-core/            module dev.fieldseal.core
    dev/fieldseal/core/                  api: Fieldseal, FieldContext, KeyProviders, IndexDeclaration, CachePolicy, ReadMode   (exported)
    dev/fieldseal/core/errors/           FieldsealError + one subclass per §9 code                              (exported)
    dev/fieldseal/core/keyprovider/      KeyProvider SPI, KeyRequest, EnvelopeHeader, KeyMaterial, Wrapper, WrappedKeyStore   (exported: callers implement the SPI)
    dev/fieldseal/core/internal/envelope/     header, parse, serialize, isCiphertext, BufferLimits, Operand (the §6.2 seam)
    dev/fieldseal/core/internal/registry/     frozen suite table + allow-list
    dev/fieldseal/core/internal/context/      canonical_context, AAD
    dev/fieldseal/core/internal/kdf/          HKDF, record_key, index_key
    dev/fieldseal/core/internal/aead/         0xFF01 over javax.crypto.Cipher
    dev/fieldseal/core/internal/commitment/   §4.6 compute/verify (provisional, G1)
    dev/fieldseal/core/internal/blindindex/   IDFs, truncation, normalizers, UCD tables
    dev/fieldseal/core/internal/cache/        DekCache
    dev/fieldseal/core/internal/config/       (empty since S4b: the builder validates, in api)
  fieldseal-core-testing/    module dev.fieldseal.core.testing: encrypt_with_materials, armed by FIELDSEAL_TEST_MODE=1 (docs/08 §6)
```

- `module-info.java` exports the three public packages, plus one qualified export (`exports … to dev.fieldseal.core.testing`) for the test seam, and nothing else.
- `docs/09` §1's dependency rule is enforced by an ArchUnit test in CI, not by prose: `internal/*` may depend only on `registry` and `errors`, and `keyprovider` and `cache` only on `errors`.
- The construction lives behind the `commitment` and `aead` module boundaries, so a Gate 0b change to G1 or ADR-0002 touches one module (`docs/26` §6).
- **The three shipped providers are built in the api package, not in `keyprovider`** (decided 2026-09-25, `docs/07` §7). The derived provider needs `kdf` and the envelope provider needs `cache`, and `keyprovider` may reach `errors` only, so `keyprovider` holds the SPI and `KeyProviders` in the api package assembles the three. `docs/09` §1 and the ArchUnit rules are unchanged. The builder's validation lives in the api package for the same reason, which leaves `internal/config/` empty.

## 4. Public API shape

Bytes in, bytes out:

```java
Fieldseal fs = Fieldseal.builder()
    .keyProvider(KeyProviders.envelope(wrapper, store))   // required; or staticKeys / derived / your own
    .allowedSuites(Set.of(0xFF01))            // required, non-empty
    .writeSuite(0xFF01)                       // required, member of allowedSuites
    .readMode(ReadMode.STRICT)                // STRICT | PERMISSIVE | READONLY
    .armProvisionalSuites(false)              // spec §4.8; also env FIELDSEAL_ARM_PROVISIONAL_SUITES=1
    .cachePolicy(new CachePolicy(             // required with the envelope provider, refused otherwise
        Duration.ofMinutes(10),               // max age
        1L << 20,                             // max uses: long, since spec §5.5 allows up to 2^32
        10_000))                              // capacity
    .warmExecutor(warmPool)                   // envelope provider only; default: 4 shared daemon threads
    .onWarning(log::warn)                     // default: System.Logger at WARNING
    .indexes(List.of(new IndexDeclaration(...)))   // S5
    .build();                                 // validates everything; immutable afterwards

FieldContext ctx = FieldContext.of(tableUuid, columnUuid).withTenant(tenantId);   // .withRow(rowId)
byte[]  ct  = fs.encrypt(plaintext, ctx);
byte[]  pt  = fs.decrypt(envelope, ctx);
byte[]  ix  = fs.blindIndex(value, ctx);      // S5: String (preferred) or byte[] (strict UTF-8)
byte[]  mk  = fs.unindexableMarker(ctx);      // S5
boolean ok  = fs.isCiphertext(bytes);
byte[]  ct2 = fs.rotate(envelope, ctx);       // ciphertext to ciphertext in every mode (spec §11.1)
CompletableFuture<Void> w = fs.warm(List.of(ctx));   // docs/09 §3.6: async where the language has it

// docs/09 §2 configuration reflection: validated, resolved, not mutable
fs.readMode(); fs.writeSuite(); fs.allowedSuites(); fs.provisionalArmed();
Map<String, ValidatedIndex> fs.indexes();     // S5, keyed by indexRegistryKey(...)
// + public validateIndexDeclaration, indexRegistryKey, firstUnassigned -> Unassigned, UNICODE_VERSION (docs/09 §12, G18/G22)
```

The cache values above are examples, not defaults: `CachePolicy` has none, and every limit is required (decided 2026-09-25, `docs/07` §7). Its documentation and the README describe the limits as security parameters, not performance tuning (spec §5.5).

Decisions:

- **`byte[]` is the byte type** (`docs/09` §12, "idiomatic byte type"). The public value path has no `ByteBuffer`.
- **`blindIndex` accepts `String` and `byte[]`** (`docs/09` §7.1, "where the refusal has to live"). The `byte[]` form decodes with a `CharsetDecoder` set to `CodingErrorAction.REPORT`, and a decoding failure is `INVALID_ARGUMENT`, which the `blind-index/` `refuse` vectors pin (suite `0.8.0-provisional`). `new String(bytes, UTF_8)` replaces malformed input silently and MUST NOT appear in a value path; CI greps for it.
- **`firstUnassigned` offsets count code points, not UTF-16 units** (`docs/09` §12). This is the JVM-specific way to get it wrong, and it has an astral-plane test.
- **The five operations are synchronous and I/O-free** (spec §11.1). This binding ships **no async companions**: Hibernate cannot await in the value path, and a companion would still pay Argon2id's CPU cost on some thread. This is the binding's G9 decision (`docs/09` §11), and the report says `async_companions: false`.
- **Errors:** `FieldsealError` subclasses whose `.code()` returns the exact §9 string (the base class is `sealed` over exactly these, since S3), plus the local configuration code (`docs/09` §9) and `INVALID_ARGUMENT` (`docs/09` §7.1). Mappings:
  - `AEADBadTagException` → `TAG_INVALID`, and only after the commitment has verified (`docs/09` §3.2 step 6);
  - provider exceptions → `KEY_UNAVAILABLE`;
  - malformed UTF-8 → `INVALID_ARGUMENT`.
- **What an internal module throws** (since S4a): a `FieldsealError` only for a caller's input it is the first to see (`ContextFields` refuses a wrongly sized UUID with `INVALID_ARGUMENT`), and otherwise `IllegalArgumentException` or `IllegalStateException`, which mean a bug in the core. The AEAD checks its offsets before calling the JDK, so a bad one there is an `IllegalArgumentException` rather than a JDK array or buffer exception; the codec relies on recognition having bounded every offset first (§6.3). The client does not map these two to a §9 code: a core bug must not read as a verdict on the ciphertext.
- **`api-boundary-order` is this core's own pinned decision** (`docs/14` §4). It is declared in the report and tested. `docs/09` §3.1 notes that the order of steps 1 and 1b cannot be observed through vectors. As built (S4b, `ApiBoundaryOrderTest`): on `encrypt`, `MODE_VIOLATION` → `SUITE_PROVISIONAL` → the operand (null: `INVALID_ARGUMENT`; then `LENGTH_EXCEEDED`) → the context (`INVALID_ARGUMENT`) → key acquisition. On `rotate`, the same first two, then the operand as `decrypt` reads it, except that a non-envelope is `NOT_CIPHERTEXT` in every mode.
- **`decrypt-order`**, as built: the operand (null) → recognition (`UNKNOWN_FORMAT_VERSION`; a non-envelope is `NOT_CIPHERTEXT` in `strict`, returned as-is otherwise) → `LENGTH_EXCEEDED` → `SUITE_NOT_ALLOWED` → the context → `KEY_UNAVAILABLE` → per candidate, the commitment and then the tag (`TAG_INVALID`) → `COMMITMENT_INVALID`. `AAD_MISMATCH` is never raised (`aad-mismatch`): under spec §6.3 a wrong context and a wrong key are indistinguishable.
- **`unimplemented-registered-suite`** (decided 2026-09-25): naming `0xFF02` in `allowedSuites` or as `writeSuite` is a `ConfigurationError` that names G7. A `0xFF02` envelope is still recognized (`isCiphertext` is true), and decrypting one is `SUITE_NOT_ALLOWED`.
- **`FieldContext` has no `suite_id` and no `purpose`.** The core fills both (`docs/09` §12): `suite_id` from `writeSuite` on a write and from the envelope's header on a read (`docs/09` §3.2 step 4); the purpose is `"encrypt"` for values and an index's own at S5, never a string a caller passed.
- **`decryptionKeys` receives the call's context as well as the header** (decided 2026-09-25). Spec §8 passes the header alone, and a derived provider cannot find a tenant in an opaque `key_id`. `EnvelopeHeader` carries `suite_id`, `key_id` and a `KeyRequest` for the call.
- **What the core checks in what a provider returns:** a non-empty key and a 16-byte `key_id`, and a non-empty candidate list of non-empty keys. Anything else, and any exception, is `KEY_UNAVAILABLE`, with the provider's exception as its cause. The DEK's length is not checked: the spec does not fix it.
- **Warnings** go through `onWarning`, by default `System.Logger` at `WARNING` (no logging framework, `docs/09` §11): at construction, for a permissive or readonly client and for the static provider outside `FIELDSEAL_TEST_MODE=1`. The metrics hook of `docs/09` §2 is not built yet.
- **The envelope provider fails closed.** `warm` is the only place it calls the key store or the KMS. A key that was never warmed, or has aged out or used up its budget, is `KEY_UNAVAILABLE` until the next `warm`; there is no background refresh. Each `warm` of a slot re-unwraps every version the store lists (restarting its age and use budget, so a schedule shorter than max-age never lapses), evicts the versions the store no longer lists, and then makes the first listed version active. The slot changes only once its whole list has loaded, so a failed warm never changes which key writes go out under (#190 review).

## 5. Security-relevant implementation notes

### 5.1 AES-256-GCM through JCA
- `Cipher.getInstance("AES/GCM/NoPadding")` with `GCMParameterSpec(128, nonce)`, and `updateAAD(aad)` before any data.
- **Encrypt:** `doFinal(plaintext, 0, n, envelope, 63)` writes ct‖tag straight into the pre-sized output envelope at offset 51 + 12. That is one allocation: the envelope itself.
- **Decrypt:** `doFinal(envelope, 63, ctLen + 16, out, 0)` consumes ct‖tag in place. Spec §3.1 makes the two fields contiguous, so no split and no copy are needed.
- **A new `Cipher` for every call.** Instances are not thread-safe, and SunJCE refuses a repeated key and IV on an encrypting instance anyway.
- **Confirmed at S2** by the `envelope/` family: with the vector's record key, nonce and AAD, the encrypt call above rebuilds all nine envelopes byte for byte, and the decrypt call reads each back in place. A flipped tag bit, ciphertext bit or AAD bit each raises exactly `AEADBadTagException`, not a subclass or sibling. The repeated key-and-IV refusal is confirmed too (`InvalidAlgorithmParameterException`).
- **Found at S2, and binding on the core:**
  - **Decrypt is one `doFinal`, never `update()`.** Through `update()`, SunJCE buffers the ciphertext and allocates about 3× the operand; one `doFinal` allocates no operand-sized buffer (§6.3).
  - **After a tag failure the output range holds no plaintext,** and is not left as it was either: SunJCE on Temurin 21 zero-fills it. The core discards that array anyway; it must not assume its earlier contents survive. The audit asserts only the absence of plaintext, which is the property the core relies on, and prints the observed fill, since what the provider writes there is its own business and may change under a JDK.

### 5.2 HKDF-SHA-512 at the JDK 21 floor
- **The construction:** RFC 5869 extract-then-expand over `Mac.getInstance("HmacSHA512")`, with the PRK erased after expand.
- **One JVM-specific trap.** Wherever the spec's HKDF salt is empty (the commitment in spec §4.6, and the Argon2id salt in §7.3; `record_key` in §5.3 is salted with `key_id ‖ msg_seed`), RFC 5869 §2.2 substitutes HashLen (64) zero bytes, and spec §4.6 says so in its own comment. `new SecretKeySpec(new byte[0], "HmacSHA512")` throws on an empty key, so the core passes 64 zero bytes explicitly. HMAC pads its key to the 128-byte block with zeros, so the two are the same key. **Confirmed at S2:** `SecretKeySpec` throws `IllegalArgumentException` on the empty key, and 64 zero bytes reproduce all three commitment values in `commitment/` and the Argon2id salt carried by each of the 23 vectors in `blind-index/argon2id.json`. Every all-zero key of 1 to 128 bytes gives the same HMAC, and 129 bytes does not, which is the padding argument itself. The `kdf/` value vectors (four record keys, five index keys) pass over the same `Mac` construction. Their two `distinct` vectors give a context object rather than `info`, so they waited for `canonical_context`, and run since S4a (`KdfVectorsTest`).
- **G14.** The length of the canonical `info` is bounded by spec §6.1's unsettled G14 question. `Mac` does not cap `info`. This document records what the core accepts at S8, so that G14's resolution can be checked against it.

### 5.3 The rest of the crypto
- **Constant-time compare:** `MessageDigest.isEqual`. Tags and commitments have equal lengths by construction; check the lengths first anyway, with a comment explaining why. A mismatch is the core's bug, so it throws before any derivation rather than answering "no match", which would surface as `COMMITMENT_INVALID` and blame the ciphertext (since S4a).
- **Argon2id (spec §7.3):**
  - version 0x13, p = 1, output 64 bytes;
  - `t` and `m` from the declaration, defaulting to the §7.3 minima;
  - construction refuses a declaration below either minimum, and one carrying `t` or `m` on an `hmac-sha512` index (`docs/09` §12);
  - the salt is the 16-byte HKDF-derived value, erased after the call.

### 5.4 Zeroization and the memory model (this binding's G17 half)
- `byte[]` is mutable, so `Arrays.fill(x, (byte) 0)` in a `finally` performs `docs/09` §3's erasure steps on the buffers the core owns: `record_key` on both paths, the untruncated IDF output, the Argon2id salt, the HKDF PRK and expand blocks, the commitment recomputed on decrypt, and the AEAD output on every exit that does not return it.
- **The core never zeroizes provider-owned material** (`docs/09` §8.1, G17). It validates what a provider returns (key length, `key_id` length) and maps exceptions to `KEY_UNAVAILABLE`. A test with a provider that keeps and inspects its own buffer proves the core never writes to it.
- **What the core cannot promise:**
  - `SecretKeySpec` copies the key it is given;
  - `Cipher` and `Mac` internals, JIT register spills and GC compaction can leave copies the core cannot reach;
  - BouncyCastle's Argon2 takes one more copy of the salt on every call and never erases it (found at S2, §2);
  - the DEK copies a provider returns on every call: one per `encryptionKey`, and one per cached version on every `decryptionKeys`. They are the provider's (`docs/09` §8.1), so the core may not erase them, and the envelope provider's are fresh copies that nothing erases. Their fate is the garbage collector's (S4b). [#192](https://github.com/fieldseal-dev/fieldseal-spec/issues/192)'s slot index does not narrow them: it stops a decrypt from walking other tenants' entries, but a decrypt still receives one copy per fresh version in its own slot, as before. Narrowing them is [#200](https://github.com/fieldseal-dev/fieldseal-spec/issues/200).
- `pinned_decisions.key-material-ownership` lists the steps performed, the provider carve-out, and a clause saying none of this is guaranteed (spec §5.5).
- **No `mlock` and no swap protection:** a documented deviation, worded as `docs/10` and `docs/11` word theirs.

### 5.5 Concurrency and CSPRNG
- The client is immutable after construction and the `DekCache` is thread-safe, so all five operations are re-entrant (`docs/09` §10).
- **CSPRNG:** one `new SecureRandom()` per client (it is thread-safe), never `getInstanceStrong()`.
- **Fork-safety** does not apply: a JVM is not `fork()`ed while it is running.
- **`warm`:** single-flight refresh, so N concurrent misses cause one unwrap per key (`docs/09` §8.3). Built at S4b as `ConcurrentHashMap.putIfAbsent` of a future that concurrent loads join, with the unwrap outside the cache's lock; a failed load leaves nothing behind.
- **The value path's lock.** The `DekCache` has one lock, and its entries are indexed by slot, so `encryptionKey` and `decryptionKeys` hold it for their own slot's versions only, never for a walk of the whole cache ([#192](https://github.com/fieldseal-dev/fieldseal-spec/issues/192)). The lock is still one for the whole cache, so tenants take turns for it: this is short of `docs/09` §8.3's "lock-free or fine-grained-locked reads", a recorded deviation until a striped or lock-free cache replaces it. Unwraps already run outside it, so no read waits on a KMS call. A read counts no use, but marks the keys it returns recently used, so a key that only decrypts is not the first evicted at capacity. Before #192 a read walked every entry in order, which left the order unchanged. That lengthens how long a key that is only read stays cached, which is the direction §5.4 is about: it now leaves at max-age, or when colder keys are gone, rather than first. Max-age still bounds it, because a read checks age before it returns a key.
- **Where `warm` blocks.** The envelope provider's `warm` calls the key store and the KMS, which block, so it runs them on the builder's `warmExecutor` ([#192](https://github.com/fieldseal-dev/fieldseal-spec/issues/192)). By default that is a pool of four daemon threads named `fieldseal-warm-N`, each gone after a minute idle; a `warm` beyond the four waits its turn and is never refused. The threads do not inherit the calling thread's inheritable thread-locals, so a request's context is not handed to a `Wrapper`. It is never the ForkJoin common pool: that pool's threads belong to the application's other async work, and on two CPUs or fewer `CompletableFuture` uses a new thread per task instead of it. **The pool is shared by every client in the process**, the one process-wide object in this core whose contents change. `docs/09` §10's "no global mutable state" is there so that clients with different configurations coexist, and the pool holds no client's state or configuration, so they still do. What they now share is one thread budget: one client's burst of warms delays another's. A caller who needs a bound of their own, or isolation, passes `warmExecutor`; a same-thread executor makes `warm` block its caller. A `warm` still loads its slots one after another; loading them in parallel is a separate change. An executor that rejects the task fails `warm`'s future.

## 6. Buffer limits and the report contract

This section discharges the per-binding obligation in `docs/09` §4: each core's binding doc states its platform's largest byte buffer, and whether that ceiling or spec §3.5's bound binds first.

### 6.1 Where the JVM binds relative to the spec bound

| Limit | Value | Source / status |
|---|---|---|
| Java language (`int` array length) | 2³¹−1 = 2,147,483,647 | JLS §10: array length is `int`. A length computed past `Integer.MAX_VALUE` wraps to a negative number, and `new byte[negative]` throws `NegativeArraySizeException` |
| JDK soft limit `SOFT_MAX_ARRAY_LENGTH` (internal) | `Integer.MAX_VALUE - 8` = 2,147,483,639 = 2³¹−9 | `jdk.internal.util.ArraysSupport`; used by the JDK's growth policies, not a VM limit |
| HotSpot allocatable `byte[]` | **2³¹−3 = 2,147,483,645** on Temurin 21.0.12 (HotSpot, G1, `-Xmx6g`), the same on Windows x64 and on CI's `ubuntu-24.04` runner; one byte more fails with "Requested array size exceeds VM limit", the VM's limit, not the heap's | Measured by §6.4 on 2026-09-24, not cited: locally, and in the `java-memory-probe` job on PR #186 |
| 32-bit JVM | far lower, bound by address space | spec §3.5 names the case. Documented only, never run in CI |

**The platform binds first, by construction.** No Java array has a length of 2³¹ or more, so a 2³¹-byte plaintext cannot be an operand, and an over-bound envelope (at least 2³¹+111 bytes) cannot be received either. This holds on every JVM, whatever heap or flags it runs with. Spec §3.5 already says it: "the JVM cannot reliably allocate a `byte[]` of exactly `Integer.MAX_VALUE`".

**An asymmetry, recorded in `harness_notes`:** Python and Node can produce a valid envelope larger than any JVM array. The largest is 2³¹+110 bytes, for a 2³¹−1 plaintext, and a JVM cannot receive it at all. The spec's ceiling-not-a-guarantee clause covers the case.

**The same limit on encrypt.** An envelope is its plaintext plus 111 bytes, so on HotSpot 21 the largest plaintext this core can encrypt is (2³¹−3) − 111 = 2,147,483,534 bytes, 113 short of the bound. A plaintext between that and 2³¹−1 passes the `LENGTH_EXCEEDED` guard and then fails to allocate its envelope. That surfaces as an `OutOfMemoryError`, not as `LENGTH_EXCEEDED`: the VM's own for a total it can attempt, and the codec's, raised with a message that says so, for a total no `int` holds, where the alternative is a wrapped cast. It stays an `Error` so that a converter's `catch (Exception)` cannot turn the value into a silent failure. The plaintext is within the bound, and spec §3.5 makes a platform failure below the bound conformant (built at S3).

### 6.2 The seam, and why an `int`-typed guard would be wrong

`if (plaintext.length > MAX_PLAINTEXT)` against an `int` constant of 2³¹−1 is dead code by construction, and a test that calls it only with real arrays proves nothing. The guard is made testable by `docs/09` §4's length seam, which for this core is part of the core, not an option (`docs/26` §4):

- An internal `Operand` interface exposes `long length()` and bounded read and copy methods. Each public entry point (`encrypt`, `decrypt`, `rotate`) builds it exactly once from the caller's `byte[]` (`Operand.of(p)`) and passes it to the internal pipeline. Every later step reads through it.
- **The guard takes a `long` length** (`2_147_483_647L`), so 2³¹, 2³² and `Long.MAX_VALUE` all reach the refusal.
- **Positions:**
  - **`encrypt`:** step 1 is `readonly → MODE_VIOLATION`, and step 1b is the length guard. Both sit at the API boundary, before context validation, key acquisition or any copy (`docs/09` §3.1).
  - **`decrypt`:** spec §3.5 leaves the position open. This core applies the guard right after structural recognition (`docs/09` §3.2 step 2), before the allow-list, key lookup and output allocation, and declares that choice in `decrypt-order`.
  - **`rotate`:** both checks apply.
  - **`blindIndex` and `unindexableMarker`:** no length guard applies.
- **The wiring test:**
  - **Encrypt case:** a synthetic `Operand` reporting `length() = 2^31` that throws on every content access, driven through the internal pipeline with a spy `KeyProvider`. It asserts `LENGTH_EXCEEDED`, zero provider calls and zero content accesses.
  - **Decrypt case:** a synthetic operand whose implied plaintext length (received length minus the suite's fixed overhead) is at least 2³¹. It serves a valid `0xFF01` header from a small backing array and throws on any other offset. Same assertions, except that recognition reads bytes 0–2 first: the test asserts no access past offset 2.
  - **Bite check:** move the guard one statement later and confirm the test fails, before merging.
  - **Built:** the codec half at S3 (`BufferLimitsWiringTest`), the provider half at S4b (`SeamWiringTest`), through the package-private pipeline each public `encrypt`, `decrypt` and `rotate` enters.

`BufferLimits` (in `internal/envelope`):

```java
static final long MAX_PLAINTEXT = 2_147_483_647L;   // 2^31 - 1, spec §3.5
static final int  HEADER_LEN    = 51;               // 1 + 2 + 16 + 32
static long    fixedOverhead(Suite s)             { return HEADER_LEN + s.nonceLen() + s.tagLen() + s.commitLen(); } // 0xFF01: 111
static long    impliedPlaintextLen(long received, Suite s) { return received - fixedOverhead(s); }
static boolean plaintextWithinBound(long len)     { return len >= 0 && len <= MAX_PLAINTEXT; }
static boolean impliedWithinBound(long received, Suite s) { return impliedPlaintextLen(received, s) <= MAX_PLAINTEXT; }
```

Three rules, each with a test:
1. **64-bit arithmetic wherever a length is computed,** including in every test that builds a near-bound length. `111 + 2_147_483_648` computed as `int` wraps negative.
2. **A negative implied length belongs to recognition,** not to the length check. It means the envelope is too short for its suite: `NOT_CIPHERTEXT` in `strict`, pass-through in the other read modes (`docs/09` §3.2 step 2).
3. **Over-bound is `LENGTH_EXCEEDED`, never the platform's error.** No clamping and no wrapping.

### 6.3 No-copy recognition, and what the platform copies anyway
- **Recognition** is index arithmetic on the caller's array: 1 B version, 2 B suite, 16 B `key_id`, 32 B `msg_seed`. The operand is never copied with `Arrays.copyOfRange`. `key_id` and `msg_seed` are copied, because the KDF and the provider need arrays, and they are small and fixed-size.
- **What the core allocates.** On decrypt: the header object, the small fixed fields, and the output plaintext, which comes after the guard. On encrypt: `msg_seed`, the nonce and the output envelope.
- **What the platform allocates.** This said SunJCE's GCM decryption buffers the ciphertext until the tag verifies, putting peak decrypt memory at about 2× the operand plus the output. **Corrected at S2**, measured with `getCurrentThreadAllocatedBytes` on Temurin 21.0.12 over a 64 MiB operand, after a warm-up (`CapabilitiesTest`):

  | Call | Allocated beyond the caller's arrays |
  |---|---|
  | encrypt, one `doFinal` into a pre-sized output | 22,280 B |
  | decrypt, one `doFinal` over ct‖tag into a separate output | 22,320 B |
  | decrypt, the same bytes through `update()` then `doFinal` | 201,349,032 B (3.0×) |

  The claim was true of the `update()` path only. Given the whole of ct‖tag in one call, SunJCE does not buffer, and it releases no plaintext on a failed tag (§5.1). The core decrypts in one `doFinal` (§5.1), so its decrypt peak is the envelope plus the plaintext it returns. The test first checks that its counter registers a 64 MiB array, then fails if either one-shot figure reaches 1 MiB, so a JDK that starts buffering is noticed. This document still does not promise zero-copy crypto: the figures are one JDK's.
- **Large but conformant operands.** A positive round trip near the ceiling is not a conformance requirement; only the refusal is. At the measured figures, decrypting a 1 GiB envelope needs about 2 GiB of heap, the envelope and its plaintext, and spec §3.5 makes an out-of-memory failure there conformant. The core adds no heap pre-checks.

### 6.4 The platform-maximum probe (informational)
`BufferMaxProbe` is a JUnit test tagged `@Tag("memory")`, run by `./gradlew memoryProbe` (never by `build`) in the `java-memory-probe` CI job with `-Xmx6g`. **Runner memory, resolved at S2:** GitHub's runner reference gives standard Linux runners 16 GB for public repositories and 8 GB for private ones (fetched 2026-09-24), and this repository is public.
1. Bisect for the largest `new byte[n]` that succeeds, between 1 GiB and `Integer.MAX_VALUE`, to the exact byte.
2. Record which failure appears just above it: "Requested array size exceeds VM limit" (the VM ceiling) or "Java heap space" (the heap). Only the first names the platform ceiling.
3. Record the JVM version, vendor, GC and flags.

The result is a fact for §6.1 ("on JDK X / HotSpot, the largest `byte[]` is 2³¹−K"). It is not a conformance input and not a gate. If the runner cannot allocate near 2 GiB, the probe reports the heap limit it hit, and §6.1 says the ceiling was not observed.

### 6.5 Conformance-report entries (`docs/14` §4, as amended by G26)
- **`spec/3.5/length-bound` and `spec/3.5/length-bound#decrypt`:** `status: "pass"`, **`basis: "seam"`**, under `docs/14` §4's conditions, all met by §6.2's wiring test. The `method` states:
  - that the route is the seam;
  - the public surface it carries (`encrypt`, `decrypt`, `rotate` over `byte[]`);
  - that the guard is unreachable from the public byte API on this runtime.

  Proposed text: *"seam: `byte[]` length is `int`, so a 2³¹-byte operand is unrepresentable here and the guard is unreachable from the public `byte[]` API. The refusal is proven on synthetic operands (length 2³¹ for encrypt; implied plaintext length ≥ 2³¹ for decrypt) through the internal `Operand` pipeline that `encrypt`, `decrypt` and `rotate` all enter, with zero key-provider calls and zero operand reads (`BufferLimitsWiringTest`)."*
- **`docs/09/7.1/lone-surrogate-refusal`:** `status: "pass"`, `basis: "direct"`. Two distinct unpaired surrogates (`"a\uD800b"`, `"a\uDC00b"`) must be refused, and refused distinguishably (`docs/08` §5 item 9).
- **The `blind-index/` `refuse` vectors** are ordinary results, not out-of-band. They pass through `blindIndex(byte[])` (§4).
- **Every out-of-band entry carries `basis`.** A level claim quoted outside the report names the two `seam` entries (`docs/14` §4).
- **`pinned_decisions`:** all six mandatory keys (`docs/14` §4). This core may add a `platform-byte-buffer-max` key carrying the probe's figure.
- **`harness_notes`:** the near-maximum envelope asymmetry from §6.1.

## 7. Testing plan

- **The vector harness.** It reads `MANIFEST.files` only, never `held_out`, and verifies the hashes first. It takes `vector_suite_version` from the manifest rather than a constant, and runs both directions of `envelope/`. It emits the `docs/14` §4 report with `basis` on every out-of-band entry. An assertion shape it does not know is a recorded failure, never a skip.
- **jqwik properties** (the `docs/09` §4 fuzzing mandate):
  - `parse ∘ serialize` round trips;
  - `isCiphertext` is total over arbitrary bytes;
  - recognition over the length edges, computed as `long`: 0, 1, overhead−1, overhead, overhead+1, 2³¹−1, 2³¹, 2³², `Long.MAX_VALUE`;
  - guard totality: only typed errors ever escape;
  - `CachePolicy.maxUses` at its edges: 2³² accepted; 2³²+1, 0 and negatives refused.
- **Targeted tests:**
  - the §6.2 wiring test, with its bite check;
  - the provider-ownership test (§5.4);
  - the ArchUnit dependency test, with a bite check on an injected violation;
  - "production `encrypt` accepts no caller-supplied nonce or seed, in any form";
  - the strict-UTF-8 grep (§4);
  - `firstUnassigned` on astral-plane input.

## 8. Build stages

Relative sizing only; `docs/07` §3 rejects invented week numbers. These are stages *inside* WS-I, not the P2-M milestones of `docs/26` §3. Each ends in an observable gate.

**S0 — this document.** Merged to `dev`, and the implementer reads it rather than the draft design.

**S1 — Scaffold and CI.**
- The Gradle multi-project (`fieldseal-core`, `fieldseal-core-testing`), toolchains, `module-info.java` and the package skeleton.
- The ArchUnit dependency test.
- The `java-core` job, with an empty harness that iterates `MANIFEST.files`.
- *Exit:* CI green, and the ArchUnit test fails on an injected violation.

**S2 — Capability audit (this document's [VERIFY] sweep).**
- GCM offsets and the tag-failure exception (§5.1).
- HKDF over `Mac` against `kdf/`, including the empty-salt trap (§5.2).
- The strict UTF-8 decoder.
- BouncyCastle's Argon2id against `blind-index/argon2id.json`, and its salt-copy behaviour.
- The decrypt allocation multiplier (§6.3), and the probe (§6.4).
- *Exit:* `CapabilitiesTest` green. Every [VERIFY] is confirmed or corrected here, with a `docs/07` §7 entry, and deviations are noted (`docs/17` §5 item 5).
- *Built 2026-09-24.* `CapabilitiesTest` (in the testing module's test sources) and `BufferMaxProbe`; the results are in the sections above and in `docs/07` §7. The strict decoder is checked against the four `refuse` preimages and an RFC 3629 table of malformed and boundary inputs.

**S3 — Envelope codec, registry, errors, `BufferLimits`.**
- Recognition, serialization and `isCiphertext`.
- The registry: `0xFF01` in full; `0xFF02` registered and unbuilt.
- The §9 error taxonomy.
- The `Operand` seam and its wiring test (§6.2).
- Codec fuzzing.
- *Exit:* `envelope/` and `errors/` green through the harness, and the wiring test passes and bites.
- *Built 2026-09-24, with the exit read as far as a codec reaches it.* There is no client or key provider before S4, so:
  - **`envelope/`:** all nine envelopes parse to their vectors' fields and re-serialize byte for byte (`CodecVectorsTest`).
  - **`errors/`:** the recognition half runs to its expected outcome. That is 40 of 41 `format` vectors and 4 of 16 `policy` vectors: every `is_ciphertext` case, and every decrypt or rotate outcome that recognition and the read mode decide. Every other decrypt vector is asserted to be recognized and within the bound, and its outcome waits for S4. A pinned count per file keeps the split from moving silently, and both families are enumerated from `MANIFEST.files`, so a new file in either fails until it is pinned. The read-mode mapping the test applies is spec §3.4 and §10.3's tables; in the core it belongs to the client.
  - **The wiring test** (`BufferLimitsWiringTest`) is the codec half: the guard refuses synthetic operands of 2³¹, 2³² and near-`Long.MAX_VALUE` lengths before any byte past the three recognition bytes is read, and passes exactly the bound. The zero-provider-calls half needs a provider, and S4 adds it by driving the same operands through `encrypt`, `decrypt` and `rotate`.
  - **The decrypt front** (`EnvelopeCodec.frontOfDecrypt`) fixes the order recognition, then the guard, then the parse, so the guard reads the length only and runs before any field is copied.
  - **Codec fuzzing:** jqwik 1.10.1 properties for `parse ∘ serialize`, `isCiphertext` against spec §3.4's first row, totality of the decrypt front, and the §7 length edges.
  - **Bite checks:** each of these turns the build red: moving the guard after the parse, the suite minimum off by one, the reserved-version floor off by one, `0xFF02` unregistered, and the encrypt bound off by one.

**S4 — Crypto pipeline.**
- KDF, AEAD, commitment, context and AAD.
- The three key providers, with a `Wrapper` seam.
- `DekCache`: max-age, max-uses as a `long`, capacity LRU, single-flight, erase on eviction.
- Config validation and the reflection accessors.
- *Exit:* `kdf/`, `context/` and `commitment/` green; the `key-material-ownership` and `api-boundary-order` tests green.
- *S4a built 2026-09-25: the primitives, in their own PR.* The providers, the `DekCache`, config and the client are S4b's, with the two exit tests.
  - **`context`:** `canonical_context` and the AAD (spec §6.2), and the spec §6.1 purpose grammar. `encodeForIndexKey` drops `row_id`, as spec §7.2 requires. Lengths are summed as `long`; a total past any Java array is an `OutOfMemoryError`, as in the codec (§6.1).
  - **`kdf`:** HKDF-SHA-512 over `Mac` (§5.2), with the PRK and every expand block erased; `record_key` (spec §5.3) and `index_key` (spec §7.2).
  - **`aead`:** `0xFF01` in place (§5.1). A tag failure is returned as an outcome, not thrown, so that the client maps it to `TAG_INVALID` only after the commitment has verified.
  - **`commitment`:** spec §4.6 over an injected KDF. `docs/09` §1 forbids `commitment` → `kdf`, and the maintainer chose injection over amending `docs/09` (`docs/07` §7, 2026-09-25); `blindindex` does the same at S5.
  - **Vectors:** `kdf/`, `context/` and `commitment/` green, with per-file counts pinned from `MANIFEST.files`; `envelope/` green in both directions composed from the primitives (`EnvelopeCryptoVectorsTest`). Every value passed on the first run: the mismatch list is empty.
  - **Still deferred, to S4b:** the `errors/` outcomes S3 deferred (all 12 of `crypto.json`, 12 of `policy.json`, 1 of `format.json`). The primitives can now produce `TAG_INVALID` and `COMMITMENT_INVALID`, but which code a vector expects depends on the read mode, the allow-list and the key lookup, which are the client's; `CodecVectorsTest`'s pinned counts are unchanged until S4b runs them through it.
  - **Bite checks:** twelve mutations each turn their tests red, among them an unsubstituted empty HKDF salt, a dropped length prefix, an absent `tenant_id` encoded as empty, `row_id` kept in the index-key `info` (caught by `CanonicalContextTest` only while the pinned `row-id-dropped` vector carried no `row_id`; since suite 0.9.0 `KdfVectorsTest` catches it too, #191), decryption through `update()`, which `open`'s allocation test catches at about 4× a 16 MiB operand, the commitment length check removed, and the AEAD's range check removed. Re-run at S4b with a working launcher and a green baseline (`docs/07` §7, 2026-09-25, S4b entry).
- *S4b built 2026-09-25: the providers, the `DekCache`, config and the client.*
  - **`keyprovider`:** the SPI (`KeyProvider`, `KeyRequest`, `EnvelopeHeader`, `KeyMaterial`, `Wrapper`, `WrappedKeyStore`). **api:** `Fieldseal` with its builder, `FieldContext`, `CachePolicy`, and `KeyProviders` with the static, derived and envelope providers (§3, §4). **`cache`:** `DekCache`, with max-age, max-uses as a `long`, capacity LRU, erasure on eviction and single-flight loads.
  - **Exit tests:** `KeyMaterialOwnershipTest` (provider arrays byte-identical after every operation and failure path; every derived `record_key` zeroed) and `ApiBoundaryOrderTest` (each pair's precedence observed, and whether the provider was reached). `SeamWiringTest` is the wiring test's provider half (§6.2). `PublicSurfaceTest` pins the client's public methods, so a nonce or seed parameter cannot appear unnoticed (§7).
  - **Vectors through the client** (`ClientVectorsTest`): every `errors/` vector but the two `blind_index` ones (S5), that is 41, 12 and 14 of `format`, `crypto` and `policy`, and `envelope/` decrypted. `CodecVectorsTest` keeps its restatement until S6.
  - **Bite checks:** `core/java/scripts/bite_checks.py` holds every S4a, S4b and review mutation. It runs each target test green first as a control, counts a mutation as biting only when Gradle reports failing tests, and restores every file. On the final S4b head, 37 mutations bite and the one below changes nothing, as stated. Later changes add their own entries, and each PR states the count on its head; the script's output is the live count, one `RED (bites)` line per mutation and test task, so a mutation that names two tasks prints two.
  - **Not testable yet:** that `decrypt` takes the context's `suite_id` from the header and not from `writeSuite` (`docs/09` §3.2 step 4). With `0xFF01` the only suite this core can be configured with, the two are always equal; the mutation was run and changes no outcome. It becomes testable when a second suite is built.

**S5 — Blind indexes and normalizers.**
- A Java emitter for `tools/ucd-gen`, so that CI's `--check` covers the Java tables. Decide it jointly with WS-J; one shared, hashed resource is the alternative.
- `nfc-casefold-v1` on Unicode 17.0.0 (`docs/09` §7.1), refusing unassigned code points and lone surrogates, with `firstUnassigned` offsets in code points and `UNICODE_VERSION`.
- `identity` and `digits-only-v1`.
- `IndexDeclaration` validation, the §7.4 band, the §7.6 cardinality gate and `on_unindexable`.
- *Exit:* `blind-index/` green, including `argon2id.json` at every cost point it pins and the four `refuse` vectors; the lone-surrogate entry passes.

**S6 — Testing artifact, full harness, report.**
- `encrypt_with_materials` in the testing artifact, armed only by `FIELDSEAL_TEST_MODE=1`.
- The full harness and the report.
- `java` added to `cross-core-result-ids` (§1).
- *Exit:* `summary.fail == 0`, the report validates, and `compare_result_ids.py --cores python,typescript,java` reports identical ids.

**S7 — Cross-implementation CI.**
- A producer leg that emits `cross/` output through the real production path (CSPRNG, no injection).
- A consumer leg that decrypts every producer's file, its own included.
- Both joined per §1.
- *Exit:* the matrix is green in both directions, self-pair included.

**S8 — This document as built, and the divergence report.**
- The S2 results, the probe figure and the measured decrypt multiplier recorded here.
- The divergence and ambiguity report (`docs/17` §5 item 4), even if empty. Its isolation statement names this document, and its single-implementer statement takes the form of `docs/18` §1 (`docs/26` §2.2).
- The `AGENTS.md` layout and build section, and the `core/java/README.md` honest limitations (PRD §8 condition 4).
- *Exit:* `docs/07` §4's definition of done, including a no-overclaim read by someone other than the author, and `docs/26` §4's additions for a core.

## 9. Verification gates

**A. Buffer bound (this core's share of `docs/09` §4's obligation).**
1. The §6.2 wiring test proves `LENGTH_EXCEEDED` on synthetic operands of length 2³¹ and of implied length ≥ 2³¹, with zero provider calls and zero operand reads, and fails when the guard is moved.
2. The `BufferLimits` value table and the long-typed fuzz pass are green.
3. Both length-bound entries record `pass`, `basis: "seam"`, with §6.5's method text.
4. §6.1 states the type argument, the probe figure (or that the ceiling was not observed), and §6.3 the decrypt multiplier.

**B. L0.** A report with `fail: 0`, and every out-of-band entry `pass` with its basis. Every `errors/` case yields its typed §9 error, and every `refuse` vector yields `INVALID_ARGUMENT`. The fuzz pass is green.

**C. Cross-language.** The S7 matrix is green, self-pair included, compared byte for byte.

**D. Report integrity.** The report validates against `docs/14` §4:
- `held_out` mirrors the manifest;
- `provisional_suites: true` and `async_companions: false`;
- all six `pinned_decisions` keys are present;
- a vector-suite version bump fails loudly.

## 10. Risks and non-goals

| Risk | Mitigation |
|---|---|
| The JDK 21 floor still excludes part of the Hibernate audience | A recorded decision (§0.3). A JDK 17 floor would change nothing in the crypto either, since the HKDF is written over `Mac` |
| The empty-salt trap (§5.2) mismatches `kdf/` | Caught at S2 by the KAT; the fix is the RFC 5869 substitution, which the spec already states |
| BouncyCastle's Argon2 differs from the vectors, or copies and keeps its salt | Caught by the S2 KAT; the salt behaviour is documented, not claimed |
| SunJCE's GCM buffering makes large decrypts memory-heavy | Measured at S2 (§6.3): it buffers through `update()` only, so the core decrypts in one `doFinal`. Spec §3.5 makes an out-of-memory failure conformant |
| `tools/ucd-gen` has no Java emitter | S5 work, shared with WS-J; CI's `--check` stays the single gate |
| One implementer writes the JVM and .NET cores | `docs/17`'s rule: say so in both reports. The claim is weakened, not invalidated. The cores are sequenced, never interleaved (`docs/26` §2.2) |
| This document leaks reference-core facts to the implementer | Facts are cited to documents, not code, and the isolation statement names this document (header) |
| The memory probe destabilises CI | A separate job and tagged tests; no gate depends on it |

**Non-goals:**
- `0xFF02` (registered and unbuilt; the `unimplemented-registered-suite` pin);
- async companions;
- BouncyCastle beyond Argon2id;
- PKCS#11;
- a streaming API;
- 32-bit claims;
- the Hibernate adapter, which is WS-N, built right after this core (`docs/26` §5 item 3);
- publication outside PRD §8's experimental-release conditions.

**References:** spec §3.1, §3.5, §4.6, §5.3, §5.5, §6.1, §7.3, §8, §9, §11.1–§11.2; `docs/08` §4.4, §4.6, §5, §6; `docs/09` §1–§4, §7.1, §8.3, §9–§12; `docs/14` §2–§4; `docs/17` §1–§6; `docs/18` §1, §4; `docs/26` §2.2, §4, §5; PRD §8 (phases, experimental releases); G17, G18, G22, G26; JEP 510; `openjdk/jdk` `ArraysSupport.java`, `HKDFParameterSpec.java`, `KDF.java` (fetched 2026-09-19); RFC 5869; RFC 9106.
