# fieldseal (Java core)

Field-level encryption for JVM applications, with a format that other languages can read.

> **Under construction: not released, and no blind indexes yet.**
> The client encrypts, decrypts and rotates values with the three key providers, and passes the shared test vectors for those operations. Blind indexes, the conformance report and the cross-implementation checks are still to come ([`docs/27`](../../docs/27-core-java.md) §8, stages S5–S8). Nothing is published to Maven Central. When it ships, it will ship as an experimental pre-1.0 release under the same terms as the other cores: not independently reviewed, not for production data ([PRD §8](../../docs/01-prd.md)).

This library encrypts individual database values, one field at a time, into a self-describing **envelope**: bytes in, bytes out. Every envelope is bound to the table and column it belongs to, and to the tenant and row when you supply them, so a value copied to the wrong place fails to decrypt instead of decrypting silently.

It implements the [Fieldseal specification](../../docs/02-spec-v0.1.md). Envelopes it writes are meant to be readable by the Python and TypeScript cores, and theirs by it; cross-implementation CI checks that in both directions once the core is complete. Most applications will not call this core directly: they will use the Hibernate adapter, which is planned right after it.

## Features

The design this core is built against ([`docs/27`](../../docs/27-core-java.md)). Everything here but blind indexes works now; blind indexes arrive at stage S5.

- **One cipher suite, no knobs.** Suite `0xFF01` is AES-256-GCM with HKDF-SHA-512 and an explicit key commitment. There is no algorithm parameter to get wrong.
- **A fresh key for every write.** Each encryption draws a new 32-byte seed and derives a key from it that is used once and never again, updates included (spec §5.3).
- **Key commitment.** A ciphertext cannot be made to decrypt under two different keys. The construction is provisional until review (spec §4.6).
- **Context binding.** Table, column, tenant and (optionally) row identifiers are bound into every envelope.
- **Blind indexes for equality search.** Argon2id or HMAC-SHA-512, truncated to a declared length, with a cardinality gate that refuses to index low-cardinality columns by default.
- **Synchronous, I/O-free operations.** Safe to call from an ORM converter, which cannot wait on a network call.

## Requirements

JDK 21 or later. The only runtime dependency will be BouncyCastle (`bcprov-jdk18on`), used for Argon2id and nothing else; everything else is the JDK's own cryptography.

## Install

Not published yet. To build from source:

```
git clone https://github.com/fieldseal-dev/fieldseal-spec.git
cd fieldseal-spec/core/java
./gradlew build
```

The Gradle wrapper downloads Gradle 9.7.1 and checks its checksum.

## Quickstart

This runs today, except `blindIndex`, which arrives at stage S5 ([`docs/27`](../../docs/27-core-java.md) §4).

```java
Fieldseal fs = Fieldseal.builder()
    .keyProvider(provider)                 // where your keys come from (see Keys)
    .allowedSuites(Set.of(0xFF01))         // which suites this client may decrypt
    .writeSuite(0xFF01)                    // which suite it writes
    .readMode(ReadMode.STRICT)             // see Read modes
    .armProvisionalSuites(true)            // required to write under 0xFF01 (see Arming)
    .build();                              // validates everything; immutable afterwards

byte[] envelope  = fs.encrypt("123-45-6789".getBytes(UTF_8), ctx);   // 11 bytes in, 122 out
byte[] plaintext = fs.decrypt(envelope, ctx);
boolean isEnc    = fs.isCiphertext(envelope);                        // true
byte[] index     = fs.blindIndex("123-45-6789", indexCtx);           // store beside the envelope
byte[] rotated   = fs.rotate(envelope, ctx);                         // re-encrypt under the current key
```

Store the envelope in a binary column (`BYTEA`, `VARBINARY`, `BLOB`), and the blind index in its own binary column.

## Blind indexes

A blind index lets you find rows by an encrypted value's equality without decrypting the column. You declare each index up front (table, column, index id, derivation function, truncation length); the core then derives a short, keyed, deterministic value you store alongside the envelope.

To look a value up, compute its index, query the index column, then decrypt the candidates and compare. The index is a filter, never an answer: truncation makes collisions deliberate. See spec [§7](../../docs/02-spec-v0.1.md) for what an index does and does not hide.

## Concepts

### Contexts

A context (`FieldContext`) names where a value lives: a table UUID, a column UUID, an optional tenant id and an optional row id. The core adds the suite and the purpose itself. The same context must be supplied to decrypt as to encrypt. A mismatch is refused, not silently tolerated.

### Operations

| Method | What it does |
|---|---|
| `encrypt(plaintext, ctx)` | Plaintext bytes to an envelope |
| `decrypt(envelope, ctx)` | An envelope back to plaintext |
| `isCiphertext(bytes)` | Whether bytes are an envelope this core recognizes; never decrypts |
| `blindIndex(value, ctx)` | The index value for an equality lookup |
| `rotate(envelope, ctx)` | Re-encrypts under the current write suite and key |
| `warm(contexts)` | Fetches and caches keys ahead of time, off the value path |

### Keys

A `KeyProvider` supplies keys, and `KeyProviders` has the three the specification requires:

- `staticKeys(dek, indexKey, keyId)`: for tests and development only. A client built with it warns unless `FIELDSEAL_TEST_MODE=1`.
- `derived(rootSecret)`: per-tenant keys derived from one root secret, with no I/O.
- `envelope(wrapper, store)`: the production path. Your `Wrapper` unwraps keys from your KMS, and only inside `warm()`; encryption and decryption read an in-memory cache and never wait on the KMS.

The envelope provider needs a `CachePolicy`: a maximum age, a maximum number of encryptions per key, and a capacity. None of them has a default. **They are security parameters, not performance tuning:** every cached key is plaintext key material in your process's memory for as long as it stays there. Use the smallest values your cost and latency allow. When a key is not in the cache, encryption and decryption fail closed with `KEY_UNAVAILABLE`, so call `warm()` ahead of the traffic that needs it.

You can implement `KeyProvider` yourself.

### Arming

Suite `0xFF01` is provisional until the specification's cryptographic review closes. Writing under it requires arming, either in code (`armProvisionalSuites(true)`) or with the environment variable `FIELDSEAL_ARM_PROVISIONAL_SUITES=1`. Without it, `encrypt` and `rotate` fail with `SUITE_PROVISIONAL`. Decrypting needs no arming.

### Read modes

`STRICT` (the default) refuses non-envelope input on decrypt. `PERMISSIVE` returns it as-is, for migrations where some rows are still plaintext. `READONLY` does the same and also refuses `encrypt` and `rotate`, for replicas and analytics jobs.

### Errors

Every failure is a subclass of `FieldsealError`, which is unchecked and sealed. Its `code()` returns one of the specification's codes: `UNKNOWN_FORMAT_VERSION`, `SUITE_NOT_ALLOWED`, `KEY_UNAVAILABLE`, `AAD_MISMATCH`, `TAG_INVALID`, `COMMITMENT_INVALID`, `NOT_CIPHERTEXT`, `MODE_VIOLATION`, `LENGTH_EXCEEDED` or `SUITE_PROVISIONAL`. There are two more: `INVALID_ARGUMENT` for a refused operand, and `CONFIGURATION_ERROR` for a client that fails validation. Messages never contain plaintext or key material. **These types exist today.**

## Limitations

The specification requires every implementation to state these.

- **Not released, and no blind indexes yet.** See the box at the top.
- **No protection against a compromised application process.** The keys are in that process.
- **Storage overhead is real.** Every envelope is 111 bytes plus the plaintext: an 11-byte SSN becomes 122 bytes.
- **Your key service becomes a hard dependency of every read.** A KMS outage fails every query on an encrypted field once the cached keys age out. The envelope provider's degradation mode is fail-closed: what the cache cannot serve is `KEY_UNAVAILABLE`.
- **Cached keys are exposed in memory.** The DEK cache holds plaintext keys, which memory dumps, core files and swap can capture. The core zeroes a key when it evicts it, but cannot lock memory against swapping.
- **Argon2id blind indexes cost roughly 10–100 ms per lookup term.** That is a product constraint, not tuning.
- **Database query logs are sensitive.** Index values and envelopes that reach them are in scope for your threat model.
- **The JVM's array limit.** A Java `byte[]` holds at most 2³¹−3 bytes on HotSpot, so the largest plaintext this core can encrypt is 2,147,483,534 bytes, a little under the specification's 2³¹−1 bound. Values that large indicate a design problem anyway.
- **Best-effort erasure only.** The core overwrites the keys it derives, but the JVM can leave copies it cannot reach (JIT, garbage collection, the JDK's own cipher objects).

## Learn more

- [`docs/27-core-java.md`](../../docs/27-core-java.md): this core's design, and the stage it is at
- [The specification](../../docs/02-spec-v0.1.md)
- [The reviewer brief](../../docs/16-reviewer-brief.md): what the independent review is asked to check
- [Issues](https://github.com/fieldseal-dev/fieldseal-spec/issues)
- [SECURITY.md](../../SECURITY.md): how to report a vulnerability

## Contributing to this core

It is built in stages (`docs/27` §8). S1–S4 are done: the Gradle scaffold and CI, an audit of the JDK and BouncyCastle against the test vectors, the envelope codec, registry and error types, and the crypto pipeline, key providers and client. Next is S5, blind indexes.

```
./gradlew build          # compile (-Xlint:all -Werror) and run every test
./gradlew -q vectors     # verify the pinned test-vector suite's hashes and structure
./gradlew memoryProbe    # informational: the largest byte[] this JVM allocates (~6 GiB heap)
```

CI runs these in the `java-core` and `java-memory-probe` jobs of `.github/workflows/conformance.yml`. This core is built without reading the other cores' source: the reading path is at the top of `docs/27`.
