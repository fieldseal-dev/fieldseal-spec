package dev.fieldseal.core.internal.blindindex;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ibm.icu.lang.UCharacter;
import com.ibm.icu.lang.UCharacterCategory;
import com.ibm.icu.text.Normalizer2;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * docs/09 §7.1 clause 3: the vendored tables and this core's own transcription of UAX #15 agree
 * with an independent implementation, exhaustively. ICU4J is that implementation, test-only, and
 * only at the pinned Unicode version: a newer ICU would disagree on characters assigned after the
 * pin, which this core refuses, so the version is checked first and a mismatch fails rather than
 * skips.
 *
 * <p>Every code point is compared, not a sample: the assigned set, NFD, NFC, full case folding
 * (statuses C and F, which is ICU's default, non-Turkic folding) and the whole of {@code
 * nfc-casefold-v1}. Random strings then reach what single code points cannot: canonical ordering
 * across marks, composition across a run, and Hangul.
 */
class UnicodeAgreementTest {

    private static final Normalizer2 NFC = Normalizer2.getNFCInstance();
    private static final Normalizer2 NFD = Normalizer2.getNFDInstance();

    private static UnicodeTables tables;

    @BeforeAll
    static void load() {
        tables = UnicodeTables.get();
    }

    @Test
    void icuIsAtThePin() {
        com.ibm.icu.util.VersionInfo v = UCharacter.getUnicodeVersion();
        assertEquals(UnicodeTables.VERSION, v.getMajor() + "." + v.getMinor() + "." + v.getMilli(),
                "ICU4J's Unicode version is not the pin; move both together");
    }

    @Test
    void theAssignedSetIsIcus() {
        List<String> diffs = new ArrayList<>();
        for (int cp = 0; cp <= Character.MAX_CODE_POINT; cp++) {
            boolean icu = UCharacter.getType(cp) != UCharacterCategory.UNASSIGNED;
            if (icu != tables.isAssigned(cp) && diffs.size() < 20) {
                diffs.add(String.format("U+%04X icu=%s ours=%s", cp, icu, !icu));
            }
        }
        assertEquals(List.of(), diffs);
    }

    @Test
    void everyAssignedCodePointNormalizesAndFoldsAsIcuDoes() {
        List<String> diffs = new ArrayList<>();
        int compared = 0;
        for (int cp = 0; cp <= Character.MAX_CODE_POINT; cp++) {
            if (!tables.isAssigned(cp) || isSurrogate(cp)) {
                continue;
            }
            compared++;
            int[] one = {cp};
            String s = new String(one, 0, 1);
            check(diffs, cp, "NFD", NFD.normalize(s), Nfc.nfd(one));
            check(diffs, cp, "NFC", NFC.normalize(s), Nfc.nfc(one));
            check(diffs, cp, "fold", UCharacter.foldCase(s, UCharacter.FOLD_CASE_DEFAULT),
                    Nfc.casefold(one));
            check(diffs, cp, "nfc-casefold-v1", icuNfcCasefold(s),
                    Nfc.nfc(Nfc.casefold(Nfc.nfc(one))));
        }
        assertTrue(compared > 150_000, "compared only " + compared + " code points");
        assertEquals(List.of(), diffs);
    }

    /**
     * Strings of up to eight code points, drawn so that most of them are combining marks, Hangul
     * jamo and syllables, or letters with canonical decompositions: the inputs where ordering and
     * composition have work to do. Seeded, so a failure reproduces.
     */
    @Test
    void randomStringsAgreeWithIcu() {
        int[] pool = interestingCodePoints();
        Random r = new Random(0x5EA1_2026L);
        List<String> diffs = new ArrayList<>();
        for (int i = 0; i < 200_000 && diffs.size() < 20; i++) {
            int[] cps = new int[1 + r.nextInt(8)];
            for (int j = 0; j < cps.length; j++) {
                cps[j] = pool[r.nextInt(pool.length)];
            }
            String s = new String(cps, 0, cps.length);
            check(diffs, cps[0], "NFC " + hex(cps), NFC.normalize(s), Nfc.nfc(cps));
            check(diffs, cps[0], "NFD " + hex(cps), NFD.normalize(s), Nfc.nfd(cps));
            check(diffs, cps[0], "nfc-casefold-v1 " + hex(cps), icuNfcCasefold(s),
                    Nfc.nfc(Nfc.casefold(Nfc.nfc(cps))));
        }
        assertEquals(List.of(), diffs);
    }

    private static String icuNfcCasefold(String s) {
        return NFC.normalize(UCharacter.foldCase(NFC.normalize(s), UCharacter.FOLD_CASE_DEFAULT));
    }

    private static int[] interestingCodePoints() {
        List<Integer> out = new ArrayList<>();
        for (int cp = 0; cp <= Character.MAX_CODE_POINT; cp++) {
            if (!tables.isAssigned(cp) || isSurrogate(cp)) {
                continue;
            }
            boolean hangul = (cp >= 0x1100 && cp <= 0x11FF) || (cp >= 0xAC00 && cp <= 0xD7A3);
            if (tables.combiningClass(cp) != 0 || tables.decomp.containsKey(cp)
                    || tables.casefold.containsKey(cp) || hangul) {
                out.add(cp);
            }
        }
        // Plain ASCII letters too, as bases.
        for (int cp = 'A'; cp <= 'z'; cp++) {
            out.add(cp);
        }
        return out.stream().mapToInt(Integer::intValue).toArray();
    }

    private static void check(List<String> diffs, int cp, String what, String icu, int[] ours) {
        String o = new String(ours, 0, ours.length);
        if (!icu.equals(o) && diffs.size() < 20) {
            diffs.add(String.format("U+%04X %s: icu=%s ours=%s", cp, what,
                    hex(icu.codePoints().toArray()), hex(ours)));
        }
    }

    private static String hex(int[] cps) {
        StringBuilder b = new StringBuilder();
        for (int c : cps) {
            b.append(String.format("%04X ", c));
        }
        return b.toString().trim();
    }

    private static boolean isSurrogate(int cp) {
        return cp >= 0xD800 && cp <= 0xDFFF;
    }
}
