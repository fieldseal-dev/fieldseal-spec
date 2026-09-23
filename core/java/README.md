# Fieldseal Java core

**Status: stage S1 of `docs/27` §8 (scaffold and CI). It encrypts nothing.** There is no cryptographic code here yet, the vector harness runs no vector, and no conformance report is emitted. Nothing is published. The design this core is built against is [`docs/27-core-java.md`](../../docs/27-core-java.md), the Java binding of [`docs/09`](../../docs/09-core-architecture.md).

## What exists

- A Gradle multi-project with two JPMS modules (`docs/27` §3):
  - `fieldseal-core`: module `dev.fieldseal.core`. It exports `dev.fieldseal.core`, `.errors` and `.keyprovider`, and nothing else. Every other package sits under `internal` and is unexported.
  - `fieldseal-core-testing`: module `dev.fieldseal.core.testing`, the future home of `encrypt_with_materials` (`docs/08` §6). It exports nothing until S6.
- One `package-info.java` per `docs/09` §1 module, stating its responsibility and what it may depend on. The only types are those the exported packages need to exist: `ReadMode`, the `FieldsealError` base and an empty `KeyProvider` SPI.
- Tests:
  - `ModuleDescriptorTest` pins the compiled module's exports and requires.
  - `DependencyRulesTest` holds the main classes to `docs/09` §1's dependency rule (ArchUnit). It also injects one violation per rule from the test sources and asserts that each rule reports it, so a rule that stops biting fails the build.
  - `VectorHarnessTest` walks the pinned suite, and breaks a synthetic suite one input at a time to exercise each guard.
- The harness (`VectorHarness`, in the testing module's test sources) reads `vectors/MANIFEST.json` and iterates `files` only, never `held_out`. For each file it checks the byte length and SHA-256, the `docs/08` §4 wrapper, and every id's grammar and uniqueness. **It executes no vector.**

## Building

JDK 21 or later (the floor is 21, `docs/27` §1); the Gradle wrapper fetches Gradle 9.7.1 and checks its checksum.

```
./gradlew build          # compile (-Xlint:all -Werror) and run every test
./gradlew -q vectors     # walk the pinned suite; exit 1 on any integrity problem
```

CI runs both in the `java-core` job of `.github/workflows/conformance.yml`. It uses Temurin 21.0.12 on push and PR, and the latest 21 on the nightly.

## Honest limitations

- **Not a conformant implementation of anything yet.** S2 through S8 (`docs/27` §8) build the capability audit, the codec, the crypto pipeline, blind indexes, the testing seam, the report and the cross-implementation legs.
- `docs/08` §5 item 2's schema validation is not performed, because `vectors/schema/` does not exist.
- The group id `dev.fieldseal` has not been verified on Maven Central (`docs/27` §0.3).
