package dev.fieldseal.core.arch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.EvaluationResult;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Holds the main classes to docs/09 §1's dependency rule, and proves that every rule bites.
 *
 * <p>The production check imports the main classes directory whole, not a package, so that a
 * class in any package is seen. The bite check adds the {@code BiteFixture} classes for one rule
 * from the test output, one rule at a time, and asserts that the rule reports each of them and
 * nothing else. A rule that stops biting (a pattern typo, a package rename) fails here
 * rather than passing silently: that is docs/27 §8's S1 exit, "the ArchUnit test fails on an
 * injected violation", kept as a test instead of done once by hand.
 */
class DependencyRulesTest {

    private static final String CORE = "dev.fieldseal.core.";

    /** For each rule, the fixture that violates it and the target the fixture depends on. */
    private static final Map<String, List<String>> BITES = new TreeMap<>(Map.ofEntries(
            // Two fixtures: a stray package under the root, and a sibling of the root, which a
            // subject scoped to "dev.fieldseal.core.." would miss.
            Map.entry("layout", List.of("stray.BiteFixture", "#dev.fieldseal.corex.BiteFixture")),
            Map.entry("envelope", fixture("internal.envelope", "keyprovider")),
            Map.entry("context", fixture("internal.context", "keyprovider")),
            Map.entry("kdf", fixture("internal.kdf", "keyprovider")),
            Map.entry("aead", fixture("internal.aead", "keyprovider")),
            Map.entry("commitment", fixture("internal.commitment", "keyprovider")),
            Map.entry("blindindex", fixture("internal.blindindex", "keyprovider")),
            Map.entry("keyprovider", fixture("keyprovider", "internal.registry")),
            Map.entry("cache", fixture("internal.cache", "internal.registry")),
            Map.entry("no-module-imports-api", fixture("internal.config", ""))));

    /** A leading '#' marks a fully qualified name outside {@code dev.fieldseal.core}. */
    private static String qualified(String name) {
        return name.startsWith("#") ? name.substring(1) : CORE + name;
    }

    private static Path classesDir(String property) {
        return Path.of(System.getProperty(property));
    }

    private static List<String> fixture(String fixturePackage, String targetPackage) {
        String target = targetPackage.isEmpty() ? "BiteTarget" : targetPackage + ".BiteTarget";
        return List.of(fixturePackage + ".BiteFixture", target);
    }

    private static JavaClasses mainClasses() {
        // The whole directory, so that a class in any package is seen, not only those under
        // the root package (the layout rule depends on it).
        return new ClassFileImporter().importPath(classesDir("fieldseal.mainClasses"));
    }

    @Test
    void mainClassesFollowTheDependencyRule() {
        JavaClasses main = mainClasses();
        // Every docs/09 §1 module has at least its package-info (-Xpkginfo:always), so no
        // rule is vacuous; ArchUnit also fails a rule that matches no class at all.
        for (String pattern : DependencyRules.modules().values()) {
            assertTrue(main.stream().anyMatch(c -> c.getPackageName().equals(
                            pattern.replace("..", ""))),
                    "no class in " + pattern);
        }
        DependencyRules.all().values().forEach(rule -> rule.check(main));
    }

    @Test
    void everyRuleHasABiteFixture() {
        assertEquals(new TreeMap<>(DependencyRules.all()).keySet(), BITES.keySet());
    }

    @TestFactory
    List<DynamicTest> everyRuleBitesOnAnInjectedViolation() {
        Map<String, ArchRule> rules = DependencyRules.all();
        return BITES.entrySet().stream().map(bite -> DynamicTest.dynamicTest(bite.getKey(), () -> {
            List<String> injected = bite.getValue().stream().map(DependencyRulesTest::qualified)
                    .toList();
            Path test = classesDir("fieldseal.testClasses");
            // Every main class, plus only the injected classes from the test output. Compared
            // as paths: ArchUnit's location URIs and Path.toUri() spell "file:" differently.
            JavaClasses withViolation = new ClassFileImporter()
                    .withImportOption(location -> !Path.of(location.asURI()).startsWith(test)
                            || injected.stream().anyMatch(name -> location.contains(
                                    name.replace('.', '/') + ".class")))
                    .importPaths(classesDir("fieldseal.mainClasses"), test);

            EvaluationResult result = rules.get(bite.getKey()).evaluate(withViolation);
            assertTrue(result.hasViolation(), bite.getKey() + " did not bite");
            List<String> fixtures = injected.stream().filter(n -> n.endsWith(".BiteFixture"))
                    .toList();
            List<String> details = result.getFailureReport().getDetails();
            for (String fixture : fixtures) {
                assertTrue(details.stream().anyMatch(d -> d.contains(fixture)),
                        bite.getKey() + " did not report " + fixture + ": " + details);
            }
            assertTrue(details.stream().allMatch(d -> fixtures.stream().anyMatch(d::contains)),
                    "violations other than the injected ones: " + details);

            // And without the fixture the same rule holds: the bite is the injection's.
            assertFalse(rules.get(bite.getKey()).evaluate(mainClasses()).hasViolation());
        })).toList();
    }
}
