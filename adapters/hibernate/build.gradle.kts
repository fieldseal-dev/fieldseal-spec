// fieldseal-hibernate (docs/29): the Hibernate ORM adapter over the Java core.
// Zero cryptographic code (spec §11.3, AD-1): CI greps src/main for crypto imports.
plugins {
    `java-library`
}

group = "dev.fieldseal"
// Coordinates are unsettled (docs/27 §0.3) and nothing is published outside
// PRD §8's experimental-release conditions.
version = "0.0.0-SNAPSHOT"

repositories { mavenCentral() }

java {
    // The core's floor (docs/27 §1); Hibernate 7 needs 17.
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    api(libs.fieldseal.core)
    api(libs.hibernate.core)
    compileOnly(libs.hibernate.models)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jackson.databind)
    testRuntimeOnly(libs.h2)
    testRuntimeOnly(libs.postgresql)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 21
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-processing", "-Xlint:-classfile", "-Werror"))
}

tasks.test {
    useJUnitPlatform()
    // The vector suite lives at the repository root, two levels up.
    systemProperty("fieldseal.vectors", rootDir.resolve("../../vectors").canonicalPath)
    // FIELDSEAL_TEST_DB=h2|postgres picks the database (docs/29 §8); h2 by default.
    environment("FIELDSEAL_TEST_DB", System.getenv("FIELDSEAL_TEST_DB") ?: "h2")
    environment.remove("FIELDSEAL_ARM_PROVISIONAL_SUITES")
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// The cross job's producer leg (docs/14 §3, docs/29 §8): rows written through the real
// session path, in a process without FIELDSEAL_TEST_MODE, which CrossProduce also refuses.
// `./gradlew -q crossProduce --args="--out <file>"`; relative paths are from adapters/hibernate.
tasks.register<JavaExec>("crossProduce") {
    description = "Writes a cross/v2 document of rows the adapter wrote"
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass = "dev.fieldseal.hibernate.CrossProduce"
    systemProperty("fieldseal.vectors", rootDir.resolve("../../vectors").canonicalPath)
    environment.remove("FIELDSEAL_TEST_MODE")
    workingDir = projectDir
}
