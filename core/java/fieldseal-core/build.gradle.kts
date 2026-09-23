// module dev.fieldseal.core (docs/27 §3). No runtime dependencies yet:
// BouncyCastle arrives for Argon2id only, at S2/S5 (docs/27 §2).
dependencies {
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.archunit)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    // ModuleDescriptorTest reads the compiled descriptor from here, so it
    // tests this build's module-info rather than whatever a classpath
    // lookup of "module-info.class" finds first (every JUnit jar has one).
    systemProperty("fieldseal.mainClasses", sourceSets.main.get().java.destinationDirectory.get().asFile.path)
}
