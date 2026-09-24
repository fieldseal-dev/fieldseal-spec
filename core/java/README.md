# Fieldseal Java core

**Status: stage S2 of `docs/27` §8 (the capability audit). It encrypts nothing.** The core holds no cryptographic code yet: S2 checked the platform and library calls the core will make, not the core. The vector harness runs no vector, and no conformance report is emitted. Nothing is published. The design this core is built against is [`docs/27-core-java.md`](../../docs/27-core-java.md), the Java binding of [`docs/09`](../../docs/09-core-architecture.md).

## What exists

- A Gradle multi-project with two JPMS modules (`docs/27` §3):
  - `fieldseal-core`: module `dev.fieldseal.core`. It exports `dev.fieldseal.core`, `.errors` and `.keyprovider`, and nothing else. Every other package sits under `internal` and is unexported.
  - `fieldseal-core-testing`: module `dev.fieldseal.core.testing`, the future home of `encrypt_with_materials` (`docs/08` §6). It exports nothing until S6.
- One `package-info.java` per `docs/09` §1 module, stating its responsibility and what it may depend on. The only types are those the exported packages need to exist: `ReadMode`, the `FieldsealError` base and an empty `KeyProvider` SPI.
- Tests:
  - `ModuleDescriptorTest` pins the compiled module's exports and requires.
  - `DependencyRulesTest` holds the main classes to `docs/09` §1's dependency rule (ArchUnit). It imports the module's whole classes directory, so a class in any package, including a sibling such as `dev.fieldseal.corex`, falls under the layout rule. It also injects one violation per rule from the test sources and asserts that each rule reports it, so a rule that stops biting fails the build.
  - `VectorHarnessTest` walks the pinned suite, and breaks a synthetic suite one input at a time to exercise each guard.
  - `CapabilitiesTest` (S2) checks, against the pinned vectors, each platform and library claim `docs/27` marked [VERIFY]: AES-256-GCM through JCA at the envelope offsets, HKDF-SHA-512 over `Mac` with the empty-salt substitution, the strict UTF-8 decoder, BouncyCastle's Argon2id and how it holds the salt, and what SunJCE's GCM allocates. `docs/07` §7 (2026-09-24) has the results.
  - `BufferMaxProbe` (tag `memory`) bisects for the largest `byte[]` the JVM allocates. It runs only by `./gradlew memoryProbe`, and is informational (`docs/27` §6.4).
- The harness (`VectorHarness`, in the testing module's test sources) reads `vectors/MANIFEST.json` and iterates `files` only, never `held_out`. For each file it checks the byte length and SHA-256, and the `docs/08` §4 wrapper. It checks that every vector has a unique, well-formed id, a `description` and a `spec_ref`, and that every `retired` entry has a well-formed id and a reason. **It executes no vector.**

## Building

JDK 21 or later (the floor is 21, `docs/27` §1); the Gradle wrapper fetches Gradle 9.7.1 and checks its checksum.

```
./gradlew build          # compile (-Xlint:all -Werror) and run every test
./gradlew -q vectors     # walk the pinned suite; exit 1 on any integrity problem
./gradlew memoryProbe    # the largest byte[] this JVM allocates; needs about 6 GiB of heap
```

CI runs the first two in the `java-core` job of `.github/workflows/conformance.yml`, and the probe in `java-memory-probe`. It uses Temurin 21.0.12 on push and PR, and the latest 21 on the nightly.

## Honest limitations

- **Not a conformant implementation of anything yet.** S3 through S8 (`docs/27` §8) build the codec, the crypto pipeline, blind indexes, the testing seam, the report and the cross-implementation legs.
- `docs/08` §5 item 2's schema validation is not performed, because `vectors/schema/` does not exist.
- The group id `dev.fieldseal` has not been verified on Maven Central (`docs/27` §0.3).
