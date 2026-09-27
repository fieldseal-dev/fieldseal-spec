// module dev.fieldseal.core.testing (docs/27 §3): encrypt_with_materials (docs/08 §6). Its test
// sources hold the vector harness and the conformance report (docs/14 §4), which need both
// modules and the seam.
dependencies {
    api(project(":fieldseal-core"))

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jackson.databind)
    // The S2 capability audit (docs/27 §8) checks BouncyCastle's Argon2id against the vectors.
    testImplementation(libs.bcprov)
    // The report runs the harness's own tests through the launcher (ConformanceReport).
    testImplementation(libs.junit.platform.launcher)
}

// The report also runs four of fieldseal-core's tests, the out-of-band entries (docs/14 §4), so
// its classpath carries that module's test classes as well.
evaluationDependsOn(":fieldseal-core")
val coreTests = project(":fieldseal-core").the<SourceSetContainer>()["test"]

// docs/08 §6: encrypt_with_materials runs only under FIELDSEAL_TEST_MODE=1. The harness needs it
// for envelope/'s encrypt direction, and nothing else in this module's tests is changed by it.
val testMode = "FIELDSEAL_TEST_MODE"

// `./gradlew -q vectors`: the conformance report (docs/14 §4) on stdout, the counterpart of the
// other cores' report commands. Exit status 1 when a result fails or the report does not
// validate; the report is printed either way.
tasks.register<JavaExec>("vectors") {
    group = "verification"
    description = "Runs the pinned vector suite and prints the docs/14 §4 conformance report."
    classpath = sourceSets.test.get().runtimeClasspath + coreTests.runtimeClasspath
    mainClass = "dev.fieldseal.core.harness.ConformanceReport"
    args(rootDir.resolve("../../vectors").canonicalPath)
    systemProperty("fieldseal.vectors", rootDir.resolve("../../vectors").canonicalPath)
    systemProperty("fieldseal.version", project.version.toString())
    environment(testMode, "1")
}

// The platform-maximum probe (docs/27 §6.4) allocates arrays of nearly 2 GiB, so it is kept
// out of `build` and runs on its own: `./gradlew memoryProbe`. Informational, never a gate.
tasks.test {
    useJUnitPlatform { excludeTags("memory", "unarmed") }
    environment(testMode, "1")
    // GcmAllocation (docs/27 §6.3) holds about 400 MiB live at its peak: 192 MiB of caller
    // arrays over a 64 MiB operand plus the update() path's 3x internal buffering. Gradle's
    // default 512 MiB worker heap leaves that no headroom, and an OutOfMemoryError there would
    // fail this gating job for a reason the audit does not claim.
    maxHeapSize = "1g"
}

// docs/08 §6's negative test, in a process that is really unarmed: the variable is removed, not
// just left unset, so a developer's or runner's environment cannot arm it.
val unarmedTest = tasks.register<Test>("unarmedTest") {
    group = "verification"
    description = "encrypt_with_materials refuses without FIELDSEAL_TEST_MODE=1 (docs/08 §6)."
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform { includeTags("unarmed") }
    environment.remove(testMode)
}
tasks.check { dependsOn(unarmedTest) }

tasks.register<Test>("memoryProbe") {
    group = "verification"
    description = "Bisects for the largest byte[] this JVM allocates (docs/27 §6.4)."
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform { includeTags("memory") }
    // Heap well above 2 GiB, so that the VM's array limit, not the heap, is what stops the
    // bisection. GitHub's public-repository Linux runners have 16 GB (docs/27 §6.4).
    maxHeapSize = "6g"
    testLogging { showStandardStreams = true }
    outputs.upToDateWhen { false }
}
