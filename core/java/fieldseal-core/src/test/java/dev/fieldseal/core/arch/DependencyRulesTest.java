package dev.fieldseal.core.arch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.EvaluationResult;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Holds the main classes to docs/09 §1's dependency rule, and proves that every rule bites.
 *
 * <p>The production check imports main classes only. The bite check adds one {@code
 * BiteFixture} from the test sources to them, one rule at a time, and asserts that the rule
 * reports that fixture. A rule that stops biting (a pattern typo, a package rename) fails here
 * rather than passing silently: that is docs/27 §8's S1 exit, "the ArchUnit test fails on an
 * injected violation", kept as a test instead of done once by hand.
 */
class DependencyRulesTest {

    private static final String CORE = "dev.fieldseal.core.";

    /** For each rule, the fixture that violates it and the target the fixture depends on. */
    private static final Map<String, List<String>> BITES = new TreeMap<>(Map.ofEntries(
            Map.entry("layout", List.of("stray.BiteFixture")),
            Map.entry("envelope", fixture("internal.envelope", "keyprovider")),
            Map.entry("context", fixture("internal.context", "keyprovider")),
            Map.entry("kdf", fixture("internal.kdf", "keyprovider")),
            Map.entry("aead", fixture("internal.aead", "keyprovider")),
            Map.entry("commitment", fixture("internal.commitment", "keyprovider")),
            Map.entry("blindindex", fixture("internal.blindindex", "keyprovider")),
            Map.entry("keyprovider", fixture("keyprovider", "internal.registry")),
            Map.entry("cache", fixture("internal.cache", "internal.registry")),
            Map.entry("no-module-imports-api", fixture("internal.config", ""))));

    private static List<String> fixture(String fixturePackage, String targetPackage) {
        String target = targetPackage.isEmpty() ? "BiteTarget" : targetPackage + ".BiteTarget";
        return List.of(fixturePackage + ".BiteFixture", target);
    }

    private static JavaClasses mainClasses() {
        return new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages(DependencyRules.ROOT);
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
            List<String> injected = bite.getValue().stream().map(s -> CORE + s).toList();
            JavaClasses withViolation = new ClassFileImporter()
                    .withImportOption(location ->
                            ImportOption.Predefined.DO_NOT_INCLUDE_TESTS.includes(location)
                                    || injected.stream().anyMatch(name -> location.contains(
                                            name.replace('.', '/') + ".class")))
                    .importPackages(DependencyRules.ROOT);

            EvaluationResult result = rules.get(bite.getKey()).evaluate(withViolation);
            assertTrue(result.hasViolation(), bite.getKey() + " did not bite");
            String fixture = injected.get(0);
            assertTrue(result.getFailureReport().getDetails().stream()
                            .allMatch(detail -> detail.contains(fixture)),
                    "violations other than the injected one: " + result.getFailureReport());

            // And without the fixture the same rule holds: the bite is the injection's.
            assertFalse(rules.get(bite.getKey()).evaluate(mainClasses()).hasViolation());
        })).toList();
    }
}
