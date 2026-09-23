// Settings shared by both modules. Each module's own build file adds only
// what differs.
subprojects {
    apply(plugin = "java-library")

    group = "dev.fieldseal"
    // Coordinates are unsettled (docs/27 §0.3) and nothing is published
    // outside PRD §8's experimental-release conditions.
    version = "0.0.0-SNAPSHOT"

    repositories { mavenCentral() }

    configure<JavaPluginExtension> {
        // docs/27 §1: JDK 21 (LTS) floor, decided 2026-09-22.
        toolchain { languageVersion = JavaLanguageVersion.of(21) }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.release = 21
        options.encoding = "UTF-8"
        // -Xpkginfo:always emits package-info.class for every package, so a
        // package that holds only its package-info still exists for the
        // dependency rules (DependencyRulesTest) while the skeleton is empty.
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror", "-Xpkginfo:always"))
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        // The vector suite lives at the repository root, two levels up.
        systemProperty("fieldseal.vectors", rootDir.resolve("../../vectors").canonicalPath)
        testLogging { events("failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
    }
}
