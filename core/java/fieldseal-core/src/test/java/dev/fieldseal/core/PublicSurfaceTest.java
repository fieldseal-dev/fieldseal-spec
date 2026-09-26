package dev.fieldseal.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * docs/27 §7: "production {@code encrypt} accepts no caller-supplied nonce or seed, in any form"
 * (spec §4.4; docs/08 §6). Pinned as the client's whole public method list: a new parameter, an
 * overload or a new method changes this set, and the change must be made here on purpose. The
 * one place fixed materials enter is {@code encrypt_with_materials} in the testing module (S6).
 */
class PublicSurfaceTest {

    @Test
    void theClientsPublicMethodsAreExactlyThese() {
        Set<String> expected = new TreeSet<>(Set.of(
                "allowedSuites()",
                "builder()",
                "decrypt(byte[],FieldContext)",
                "encrypt(byte[],FieldContext)",
                "isCiphertext(byte[])",
                "provisionalArmed()",
                "readMode()",
                "rotate(byte[],FieldContext)",
                "warm(Collection)",
                "writeSuite()"));
        assertEquals(expected, signatures(Fieldseal.class));
    }

    @Test
    void theBuildersPublicMethodsTakeNoEntropy() {
        assertEquals(new TreeSet<>(Set.of("allowedSuites(Set)", "armProvisionalSuites(boolean)",
                "build()", "keyProvider(KeyProvider)", "onWarning(Consumer)",
                "readMode(ReadMode)", "writeSuite(int)")),
                signatures(Fieldseal.Builder.class));
    }

    /** #192 item 3: the envelope provider takes its cache policy and warm executor itself. */
    @Test
    void theShippedProvidersAreExactlyThese() {
        assertEquals(new TreeSet<>(Set.of("derived(byte[])",
                "envelope(Wrapper,WrappedKeyStore,CachePolicy)",
                "envelope(Wrapper,WrappedKeyStore,CachePolicy,Executor)",
                "staticKeys(byte[],byte[],byte[])")),
                signatures(KeyProviders.class));
    }

    private static Set<String> signatures(Class<?> c) {
        return Arrays.stream(c.getDeclaredMethods())
                .filter(m -> Modifier.isPublic(m.getModifiers()) && !m.isSynthetic())
                .map(PublicSurfaceTest::signature)
                .collect(Collectors.toCollection(TreeSet::new));
    }

    private static String signature(Method m) {
        return m.getName() + Arrays.stream(m.getParameterTypes()).map(Class::getSimpleName)
                .collect(Collectors.joining(",", "(", ")"));
    }
}
