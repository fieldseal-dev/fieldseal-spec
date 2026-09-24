// module dev.fieldseal.core.testing (docs/27 §3). Its test sources hold the
// vector harness, which needs both modules and, from S6, the seam.
dependencies {
    api(project(":fieldseal-core"))

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jackson.databind)
    // The S2 capability audit (docs/27 §8) checks BouncyCastle's Argon2id against the vectors.
    testImplementation(libs.bcprov)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// `./gradlew -q vectors`: the harness on its own, the counterpart of the
// other cores' report commands. At S1 it walks the suite and runs nothing.
tasks.register<JavaExec>("vectors") {
    group = "verification"
    description = "Walks the pinned vector suite (S1: integrity and enumeration only)."
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass = "dev.fieldseal.core.harness.VectorHarness"
    args(rootDir.resolve("../../vectors").canonicalPath)
}

// The platform-maximum probe (docs/27 §6.4) allocates arrays of nearly 2 GiB, so it is kept
// out of `build` and runs on its own: `./gradlew memoryProbe`. Informational, never a gate.
tasks.test {
    useJUnitPlatform { excludeTags("memory") }
    // GcmAllocation (docs/27 §6.3) holds about 400 MiB live at its peak: 192 MiB of caller
    // arrays over a 64 MiB operand plus the update() path's 3x internal buffering. Gradle's
    // default 512 MiB worker heap leaves that no headroom, and an OutOfMemoryError there would
    // fail this gating job for a reason the audit does not claim.
    maxHeapSize = "1g"
}

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
