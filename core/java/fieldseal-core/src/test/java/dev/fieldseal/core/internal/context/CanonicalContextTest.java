package dev.fieldseal.core.internal.context;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.InvalidArgumentError;
import java.util.Arrays;
import java.util.HexFormat;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.junit.jupiter.api.Test;

/**
 * spec §6.1 and §6.2 at the edges the {@code context/} vectors leave implicit: reserved presence
 * bits, UUID sizes, the purpose grammar's bounds, and injectivity as a property.
 */
class CanonicalContextTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] T = HEX.parseHex("3f2504e04f8911d39a0c0305e82c3301");
    private static final byte[] C = HEX.parseHex("7d4448409dc011d1b2455ffdce74fad2");

    private static ContextFields ctx(byte[] tenant, byte[] row, String purpose) {
        return new ContextFields(0xFF01, T, C, tenant, row, purpose);
    }

    /** spec §6.2 read directly: 1 + (8+2) + (8+16) + (8+16) + (8+7). */
    @Test
    void bothAbsentLayoutByHand() {
        byte[] cc = CanonicalContext.encode(ctx(null, null, "encrypt"));
        assertEquals(74, cc.length);
        assertEquals("00" + "0000000000000002" + "ff01" + "0000000000000010" + HEX.formatHex(T)
                + "0000000000000010" + HEX.formatHex(C) + "0000000000000007"
                + HEX.formatHex("encrypt".getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
                HEX.formatHex(cc));
    }

    @Test
    void presenceBitsAndReservedBitsZero() {
        byte[] one = {1};
        assertEquals(0x00, CanonicalContext.encode(ctx(null, null, "encrypt"))[0]);
        assertEquals(0x01, CanonicalContext.encode(ctx(one, null, "encrypt"))[0]);
        assertEquals(0x02, CanonicalContext.encode(ctx(null, one, "encrypt"))[0]);
        assertEquals(0x03, CanonicalContext.encode(ctx(one, one, "encrypt"))[0]);
    }

    @Test
    void absentAndZeroLengthDiffer() {
        assertFalse(Arrays.equals(CanonicalContext.encode(ctx(null, null, "encrypt")),
                CanonicalContext.encode(ctx(new byte[0], null, "encrypt"))));
        assertFalse(Arrays.equals(CanonicalContext.encode(ctx(null, null, "encrypt")),
                CanonicalContext.encode(ctx(null, new byte[0], "encrypt"))));
        assertFalse(Arrays.equals(CanonicalContext.encode(ctx(new byte[0], null, "encrypt")),
                CanonicalContext.encode(ctx(null, new byte[0], "encrypt"))));
    }

    @Test
    void indexKeyInfoDropsRowId() {
        assertArrayEquals(CanonicalContext.encode(ctx(new byte[] {7}, null, "index:a")),
                CanonicalContext.encodeForIndexKey(ctx(new byte[] {7}, new byte[] {9}, "index:a")));
    }

    @Test
    void aadIsLengthPrefixedHeaderThenContext() {
        byte[] cc = {(byte) 0xCC};
        byte[] aad = CanonicalContext.aad(1, new byte[16], new byte[32], cc);
        assertEquals(8 + 1 + 8 + 16 + 8 + 32 + 1, aad.length);
        assertEquals("000000000000000101" + "0000000000000010", HEX.formatHex(aad, 0, 17));
        assertEquals((byte) 0xCC, aad[aad.length - 1]);
        for (int bad : new int[] {-1, 0x100}) {
            assertThrows(IllegalArgumentException.class,
                    () -> CanonicalContext.aad(bad, new byte[16], new byte[32], cc), "fmt_ver " + bad);
        }
    }

    @Test
    void uuidsMustBe16Bytes() {
        for (byte[] bad : new byte[][] {null, new byte[15], new byte[17], new byte[0]}) {
            assertThrows(InvalidArgumentError.class,
                    () -> new ContextFields(0xFF01, bad, C, null, null, "encrypt"));
            assertThrows(InvalidArgumentError.class,
                    () -> new ContextFields(0xFF01, T, bad, null, null, "encrypt"));
        }
        assertThrows(InvalidArgumentError.class,
                () -> new ContextFields(0x10000, T, C, null, null, "encrypt"));
    }

    /** spec §6.1: {@code index-id = 1*32( %x61-7A / %x30-39 / "-" )}. */
    @Test
    void purposeGrammar() {
        String x32 = "a".repeat(32);
        for (String ok : new String[] {"encrypt", "index:a", "index:" + x32, "index:email-eq",
                "index:0", "index:-"}) {
            assertTrue(Purpose.isValid(ok), ok);
        }
        for (String bad : new String[] {"", "Encrypt", "encrypt ", "index:", "index:" + x32 + "a",
                "index:Exact", "index:é", "index:a_b", "index:a.b", "index", "idx:a", null}) {
            assertFalse(Purpose.isValid(bad), String.valueOf(bad));
        }
        assertThrows(IllegalArgumentException.class,
                () -> CanonicalContext.encode(ctx(null, null, "index:Exact")));
    }

    @Provide
    Arbitrary<ContextFields> contexts() {
        Arbitrary<byte[]> opt = Arbitraries.bytes().array(byte[].class).ofMaxSize(20)
                .injectNull(0.3);
        Arbitrary<String> purpose = Arbitraries.oneOf(Arbitraries.just("encrypt"),
                Arbitraries.strings().withChars("abc-09").ofMinLength(1).ofMaxLength(32)
                        .map(s -> "index:" + s));
        return Combinators.combine(Arbitraries.of(0xFF01, 0xFF02),
                Arbitraries.bytes().array(byte[].class).ofSize(16),
                Arbitraries.bytes().array(byte[].class).ofSize(16), opt, opt, purpose)
                .as(ContextFields::new);
    }

    /**
     * The injectivity argument of spec §6.2, as a property over small contexts: two contexts
     * encode equally only when every field is equal, absent counting as distinct from empty.
     */
    @Property
    void encodingIsInjective(@ForAll("contexts") ContextFields a,
            @ForAll("contexts") ContextFields b) {
        boolean same = a.suiteId() == b.suiteId() && Arrays.equals(a.tableUuid(), b.tableUuid())
                && Arrays.equals(a.columnUuid(), b.columnUuid())
                && Arrays.equals(a.tenantId(), b.tenantId()) && Arrays.equals(a.rowId(), b.rowId())
                && a.purpose().equals(b.purpose());
        assertEquals(same, Arrays.equals(CanonicalContext.encode(a), CanonicalContext.encode(b)));
        // Independent draws are almost never equal, so the equal half is exercised directly.
        assertArrayEquals(CanonicalContext.encode(a), CanonicalContext.encode(copy(a)));
    }

    private static ContextFields copy(ContextFields c) {
        return new ContextFields(c.suiteId(), c.tableUuid().clone(), c.columnUuid().clone(),
                c.tenantId() == null ? null : c.tenantId().clone(),
                c.rowId() == null ? null : c.rowId().clone(), new String(c.purpose()));
    }
}
