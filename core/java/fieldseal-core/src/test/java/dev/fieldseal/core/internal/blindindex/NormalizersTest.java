package dev.fieldseal.core.internal.blindindex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.internal.blindindex.Normalizers.Id;
import dev.fieldseal.core.internal.blindindex.Normalizers.Result;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** The normalizers (docs/09 §7, §7.1) and truncation (spec §7.2), below the client. */
class NormalizersTest {

    private static byte[] value(Result r) {
        return assertInstanceOf(Result.Value.class, r).bytes();
    }

    private static String refused(Result r) {
        return assertInstanceOf(Result.Refused.class, r).reason();
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // --- nfc-casefold-v1 ------------------------------------------------------------------------

    @Test
    void foldsCaseAndComposes() {
        assertArrayEquals(utf8("ada@example.com"),
                value(Normalizers.apply(Id.NFC_CASEFOLD_V1, "Ada@Example.COM")));
        assertArrayEquals(utf8("strasse"), value(Normalizers.apply(Id.NFC_CASEFOLD_V1, "Straße")),
                "full folding: ß to ss, not ß");
        assertArrayEquals(utf8("é"), value(Normalizers.apply(Id.NFC_CASEFOLD_V1,
                "É")), "decomposed E-acute folds and composes to U+00E9");
    }

    /** docs/09 §7.1 clause 4: the pair that needs the second NFC. */
    @Test
    void theSecondNfcCollapsesTheGreekPair() {
        assertArrayEquals(value(Normalizers.apply(Id.NFC_CASEFOLD_V1, "ΐ")),
                value(Normalizers.apply(Id.NFC_CASEFOLD_V1, "Ϊ́")));
    }

    @Test
    void noTurkicFolding() {
        assertArrayEquals(utf8("i̇"), value(Normalizers.apply(Id.NFC_CASEFOLD_V1, "İ")),
                "U+0130 folds under F to i + combining dot, never to a dotless or plain i");
        assertArrayEquals(utf8("i"), value(Normalizers.apply(Id.NFC_CASEFOLD_V1, "I")));
    }

    @Test
    void textAndItsOwnEncodingGiveTheSameBytes() {
        for (String s : new String[] {"Ada", "Ζεύς", "😀 smile", "각",
            "�"}) {
            assertArrayEquals(value(Normalizers.apply(Id.NFC_CASEFOLD_V1, s)),
                    value(Normalizers.apply(Id.NFC_CASEFOLD_V1, utf8(s))), s);
        }
    }

    @Test
    void refusesAnUnassignedCodePointNamingItAndItsOffset() {
        String r = refused(Normalizers.apply(Id.NFC_CASEFOLD_V1, "a͸b"));
        assertTrue(r.contains("U+0378") && r.contains("offset 1") && r.contains("17.0.0"), r);
        assertTrue(!r.contains("a͸b"), "a refusal never echoes the value");
    }

    /** docs/09/7.1/lone-surrogate-refusal (docs/08 §5 item 9): refused, and refused apart. */
    @Test
    void refusesTwoDistinctLoneSurrogatesDistinguishably() {
        String high = refused(Normalizers.apply(Id.NFC_CASEFOLD_V1, "a\uD800b"));
        String low = refused(Normalizers.apply(Id.NFC_CASEFOLD_V1, "a\uDC00b"));
        assertNotEquals(high, low);
        assertTrue(high.contains("U+D800") && high.contains("lone surrogate"), high);
        assertTrue(low.contains("U+DC00") && low.contains("lone surrogate"), low);
    }

    /** docs/09 §7.1 clause 5: strict UTF-8, naming the byte offset and at most four bytes. */
    @Test
    void refusesMalformedUtf8NeverReplacing() {
        String[][] cases = {{"61eda08062", "offset 1", "EDA080"}, {"61c0af", "offset 1", "C0"},
            {"61ff", "offset 1", "FF"}, {"e282", "offset 0", "E282"}};
        for (String[] c : cases) {
            String r = refused(Normalizers.apply(Id.NFC_CASEFOLD_V1,
                    HexFormat.of().parseHex(c[0])));
            assertTrue(r.contains(c[1]) && r.contains(c[2]), c[0] + ": " + r);
        }
    }

    // --- identity and digits-only-v1 ------------------------------------------------------------

    @Test
    void identityIsTheBytesOrTheEncoding() {
        byte[] in = {(byte) 0xFF, 0, 'A'};
        byte[] out = value(Normalizers.apply(Id.IDENTITY, in));
        assertArrayEquals(in, out);
        out[0] = 1;
        assertEquals((byte) 0xFF, in[0], "identity returns a copy the caller may erase");
        assertArrayEquals(utf8("Ada͸"), value(Normalizers.apply(Id.IDENTITY, "Ada͸")),
                "identity consults no Unicode table");
        assertTrue(refused(Normalizers.apply(Id.IDENTITY, "a\uD800")).contains("U+D800"),
                "a lone surrogate has no encoding to hand on");
    }

    @Test
    void digitsOnlyKeepsTheAsciiDigits() {
        assertArrayEquals(utf8("5551234567"),
                value(Normalizers.apply(Id.DIGITS_ONLY_V1, "+1 (555) 123-4567".substring(3))));
        assertArrayEquals(utf8("123"), value(Normalizers.apply(Id.DIGITS_ONLY_V1,
                "1٢ 2\uD800 3")), "an Arabic-Indic digit and a lone surrogate are not ASCII digits");
        assertArrayEquals(utf8("12"), value(Normalizers.apply(Id.DIGITS_ONLY_V1,
                new byte[] {'1', (byte) 0xED, (byte) 0xA0, (byte) 0x80, '2'})), "on bytes, as they are");
    }

    // --- firstUnassigned ------------------------------------------------------------------------

    /** docs/27 §7: the offset counts code points, and astral input is where UTF-16 differs. */
    @Test
    void firstUnassignedCountsCodePointsNotUtf16Units() {
        int[] u = Normalizers.firstUnassigned("😀😀͸");
        assertArrayEquals(new int[] {0x0378, 2}, u, "two emoji are two code points, four units");
        assertArrayEquals(new int[] {0xDC00, 1}, Normalizers.firstUnassigned("a\uDC00"));
        assertArrayEquals(new int[] {0xE0080, 1}, Normalizers.firstUnassigned("a󠂀"),
                "an unassigned astral code point");
        assertNull(Normalizers.firstUnassigned("Ada 😀 �"));
    }

    // --- truncation ------------------------------------------------------------------------------

    @Test
    void truncatesMsbFirst() {
        byte[] raw = HexFormat.of().parseHex("abcdef");
        assertEquals("abc0", HexFormat.of().formatHex(Idf.truncate(raw, 12)), "spec §7.2's example");
        assertEquals("abcc", HexFormat.of().formatHex(Idf.truncate(raw, 15)));
        assertEquals("abcd", HexFormat.of().formatHex(Idf.truncate(raw, 16)));
        assertEquals("80", HexFormat.of().formatHex(Idf.truncate(raw, 1)));
        assertThrows(IllegalArgumentException.class, () -> Idf.truncate(raw, 25));
        assertThrows(IllegalArgumentException.class, () -> Idf.truncate(raw, 0));
    }

    @Test
    void theReservedPreimageIsAFreshCopy() {
        byte[] p = Normalizers.reservedPreimage();
        assertEquals("ff6669656c647365616c2d756e696e64657861626c652d7631", HexFormat.of().formatHex(p));
        p[0] = 0;
        assertEquals((byte) 0xFF, Normalizers.reservedPreimage()[0]);
    }
}
