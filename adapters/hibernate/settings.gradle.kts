// The Hibernate adapter (WS-N, docs/29). One published module, fieldseal-hibernate,
// built against the Java core in this checkout, never a published one: the core is
// included as a build, so Gradle substitutes its project for the dependency below.
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "fieldseal-hibernate"

includeBuild("../../core/java")
