package dev.fieldseal.core.arch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.lang.ArchRule;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * docs/09 §1's dependency rule, as ArchUnit rules (docs/27 §3):
 *
 * <blockquote>{@code api} → everything; {@code envelope}/{@code context}/{@code kdf}/{@code
 * aead}/{@code commitment}/{@code blindindex} → {@code registry} + {@code errors} only;
 * {@code keyprovider}/{@code cache} → {@code errors} only. No module imports {@code
 * api}.</blockquote>
 *
 * <p>docs/09 §1 constrains nothing else, so neither does this class: {@code registry}, {@code
 * config} and {@code errors} have no rule of their own. Its last clause, "nothing imports {@code
 * testing}", is enforced by the build instead: {@code testing} is a separate module that this one
 * does not declare, so no class here can name it.
 *
 * <p>One rule is added: every class lives in a known module's package. Without it, a class in a
 * new package would sit outside every rule above and pass them all. Its subject is every class
 * imported, not the classes under {@link #ROOT}: ArchUnit's {@code "dev.fieldseal.core.."}
 * does not match a sibling such as {@code dev.fieldseal.corex}, and a class there, or in any
 * other package, would otherwise escape it. That holds only because the test imports the
 * module's whole classes directory rather than a package (DependencyRulesTest).
 */
final class DependencyRules {

    static final String ROOT = "dev.fieldseal.core";

    /** docs/09 §1's six modules that may depend on {@code registry} and {@code errors} only. */
    static final List<String> PRIMITIVES =
            List.of("envelope", "context", "kdf", "aead", "commitment", "blindindex");

    /** docs/09 §1's two modules that may depend on {@code errors} only. */
    static final List<String> ERRORS_ONLY = List.of("keyprovider", "cache");

    private DependencyRules() {}

    /** Module name to the ArchUnit package pattern its classes live under (docs/27 §3). */
    static Map<String, String> modules() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("api", ROOT); // exactly the root package, not its subpackages
        m.put("errors", ROOT + ".errors..");
        m.put("keyprovider", ROOT + ".keyprovider..");
        for (String internal :
                List.of("envelope", "registry", "context", "kdf", "aead", "commitment",
                        "blindindex", "cache", "config")) {
            m.put(internal, ROOT + ".internal." + internal + "..");
        }
        return m;
    }

    /** Every rule, keyed by a name the bite test uses to inject one violation per rule. */
    static Map<String, ArchRule> all() {
        Map<String, String> modules = modules();
        Map<String, ArchRule> rules = new LinkedHashMap<>();

        rules.put("layout",
                classes()
                        .should().resideInAnyPackage(modules.values().toArray(String[]::new))
                        .because("docs/27 §3: a class outside the known modules escapes every"
                                + " dependency rule"));

        for (String m : PRIMITIVES) {
            rules.put(m, onlyDependsOn(m, Set.of("registry", "errors"), modules));
        }
        for (String m : ERRORS_ONLY) {
            rules.put(m, onlyDependsOn(m, Set.of("errors"), modules));
        }

        rules.put("no-module-imports-api",
                noClasses().that().resideInAPackage(ROOT + ".*..")
                        .should().dependOnClassesThat().resideInAPackage(ROOT)
                        .because("docs/09 §1: no module imports api"));
        return rules;
    }

    /**
     * {@code module} may depend on {@code allowed} and on itself. Every other module is
     * forbidden, which is how "X only" reads: dependencies on the JDK and on third-party
     * libraries are not what docs/09 §1 constrains.
     */
    private static ArchRule onlyDependsOn(
            String module, Set<String> allowed, Map<String, String> modules) {
        List<String> forbidden = new ArrayList<>();
        modules.forEach((name, pattern) -> {
            if (!name.equals(module) && !allowed.contains(name)) {
                forbidden.add(pattern);
            }
        });
        return noClasses().that().resideInAPackage(modules.get(module))
                .should().dependOnClassesThat().resideInAnyPackage(forbidden.toArray(String[]::new))
                .because("docs/09 §1: " + module + " depends on " + String.join(" + ", allowed.stream().sorted().toList()) + " only");
    }
}
