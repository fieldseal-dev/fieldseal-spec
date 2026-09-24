// The Java core (WS-I, docs/27). Two published modules and nothing else:
// fieldseal-core (module dev.fieldseal.core) and fieldseal-core-testing
// (module dev.fieldseal.core.testing), docs/27 §3.
plugins {
    // Resolves the JDK 21 toolchain (docs/27 §1) where none is installed.
    // CI installs the pinned patch with setup-java and runs Gradle on it, so
    // there the toolchain is the running JVM and nothing is downloaded.
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "fieldseal-java"

include("fieldseal-core", "fieldseal-core-testing")
