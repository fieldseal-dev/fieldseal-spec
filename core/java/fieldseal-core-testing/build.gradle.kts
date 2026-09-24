// module dev.fieldseal.core.testing (docs/27 §3). Its test sources hold the
// vector harness, which needs both modules and, from S6, the seam.
dependencies {
    api(project(":fieldseal-core"))

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jackson.databind)
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
