package dev.fieldseal.core.internal.blindindex;

import java.util.Arrays;

/**
 * UAX #15 canonical decomposition, canonical ordering and canonical composition, and UAX #44 full
 * case folding, over the vendored tables ({@link UnicodeTables}). This is the Java core's own
 * transcription of the algorithms; the data is the only thing it shares with the other cores
 * ({@code tools/ucd-gen/README.md}).
 *
 * <p>Inputs and outputs are code point arrays. Callers check assignment and surrogates first
 * ({@link Normalizers}): the algorithms here are total, and would pass an unassigned code point
 * through unchanged, which is exactly what docs/09 §7.1 clause 1 forbids a caller to rely on.
 */
final class Nfc {

    // UAX #15 §16 / Unicode §3.12: Hangul syllables are decomposed and composed by arithmetic.
    private static final int S_BASE = 0xAC00;
    private static final int L_BASE = 0x1100;
    private static final int V_BASE = 0x1161;
    private static final int T_BASE = 0x11A7;
    private static final int L_COUNT = 19;
    private static final int V_COUNT = 21;
    private static final int T_COUNT = 28;
    private static final int N_COUNT = V_COUNT * T_COUNT;
    private static final int S_COUNT = L_COUNT * N_COUNT;

    private Nfc() {}

    /** NFC: canonical decomposition, canonical ordering, then canonical composition. */
    static int[] nfc(int[] cps) {
        return compose(nfd(cps));
    }

    /** NFD: full canonical decomposition, then canonical ordering. */
    static int[] nfd(int[] cps) {
        UnicodeTables t = UnicodeTables.get();
        IntBuffer out = new IntBuffer(cps.length + 8);
        for (int cp : cps) {
            decompose(t, cp, out);
        }
        int[] d = out.toArray();
        order(t, d);
        return d;
    }

    /** Full case folding, statuses C and F (docs/09 §7.1 clause 2); no T, no S. */
    static int[] casefold(int[] cps) {
        UnicodeTables t = UnicodeTables.get();
        IntBuffer out = new IntBuffer(cps.length + 8);
        for (int cp : cps) {
            int[] f = t.casefold.get(cp);
            if (f == null) {
                out.add(cp);
            } else {
                for (int c : f) {
                    out.add(c);
                }
            }
        }
        return out.toArray();
    }

    private static void decompose(UnicodeTables t, int cp, IntBuffer out) {
        int s = cp - S_BASE;
        if (s >= 0 && s < S_COUNT) {
            out.add(L_BASE + s / N_COUNT);
            out.add(V_BASE + (s % N_COUNT) / T_COUNT);
            int trail = s % T_COUNT;
            if (trail != 0) {
                out.add(T_BASE + trail);
            }
            return;
        }
        int[] d = t.decomp.get(cp);
        if (d == null) {
            out.add(cp);
            return;
        }
        for (int c : d) {
            decompose(t, c, out);
        }
    }

    /** Canonical ordering: a stable sort of each run of non-starters by combining class. */
    private static void order(UnicodeTables t, int[] d) {
        for (int i = 1; i < d.length; i++) {
            int c = d[i];
            int cc = t.combiningClass(c);
            if (cc == 0) {
                continue;
            }
            int j = i;
            while (j > 0 && t.combiningClass(d[j - 1]) > cc) {
                d[j] = d[j - 1];
                j--;
            }
            d[j] = c;
        }
    }

    /**
     * Canonical composition over a string already in NFD (UAX #15 §1.3, the reference sample's
     * shape). A character composes with the last starter unless something between them blocks it:
     * a character of equal or higher combining class, or a starter.
     */
    private static int[] compose(int[] d) {
        if (d.length == 0) {
            return d;
        }
        UnicodeTables t = UnicodeTables.get();
        int[] out = d.clone();
        int starterPos = 0;
        int starter = out[0];
        // A leading non-starter has no starter to compose with: block everything until one.
        int lastClass = t.combiningClass(starter) == 0 ? 0 : 256;
        int kept = 1;
        for (int i = 1; i < d.length; i++) {
            int c = d[i];
            int cc = t.combiningClass(c);
            int composite = lastClass == 256 ? -1 : primary(t, starter, c);
            if (composite >= 0 && (lastClass < cc || lastClass == 0)) {
                out[starterPos] = composite;
                starter = composite;
                continue;
            }
            if (cc == 0) {
                starterPos = kept;
                starter = c;
            }
            lastClass = cc;
            out[kept++] = c;
        }
        return Arrays.copyOf(out, kept);
    }

    /** The primary composite of {@code first} and {@code second}, or -1. */
    private static int primary(UnicodeTables t, int first, int second) {
        int l = first - L_BASE;
        if (l >= 0 && l < L_COUNT) {
            int v = second - V_BASE;
            return v >= 0 && v < V_COUNT ? S_BASE + (l * V_COUNT + v) * T_COUNT : -1;
        }
        int s = first - S_BASE;
        if (s >= 0 && s < S_COUNT && s % T_COUNT == 0) {
            int tr = second - T_BASE;
            return tr > 0 && tr < T_COUNT ? first + tr : -1;
        }
        Integer c = t.compose.get(UnicodeTables.pair(first, second));
        return c == null ? -1 : c;
    }

    /** A growable int array: the only collection these loops need. */
    private static final class IntBuffer {
        private int[] a;
        private int n;

        IntBuffer(int capacity) {
            a = new int[Math.max(capacity, 4)];
        }

        void add(int v) {
            if (n == a.length) {
                a = Arrays.copyOf(a, n * 2);
            }
            a[n++] = v;
        }

        int[] toArray() {
            return Arrays.copyOf(a, n);
        }
    }
}
