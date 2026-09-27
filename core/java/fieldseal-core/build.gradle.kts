// module dev.fieldseal.core (docs/27 §3). One runtime dependency: BouncyCastle,
// for Argon2id only (docs/27 §2), since S5.
dependencies {
    implementation(libs.bcprov)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.archunit)
    // The codec fuzzing pass (docs/09 §4; docs/27 §7). jqwik is a JUnit Platform engine.
    testImplementation(libs.jqwik)
    // The exhaustive oracle for the vendored Unicode tables (docs/09 §7.1 clause 3). Test-only.
    testImplementation(libs.icu4j)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    // ModuleDescriptorTest reads the compiled descriptor from here, so it
    // tests this build's module-info rather than whatever a classpath
    // lookup of "module-info.class" finds first (every JUnit jar has one).
    systemProperty("fieldseal.mainClasses", sourceSets.main.get().java.destinationDirectory.get().asFile.path)
    // DependencyRulesTest imports whole directories, not packages, so a class
    // in any package at all is seen (a package-scoped import misses them).
    systemProperty("fieldseal.testClasses", sourceSets.test.get().java.destinationDirectory.get().asFile.path)
}
