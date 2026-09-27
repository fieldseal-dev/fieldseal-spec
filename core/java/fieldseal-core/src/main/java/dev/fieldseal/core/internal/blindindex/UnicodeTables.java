package dev.fieldseal.core.internal.blindindex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The vendored Unicode data {@code nfc-casefold-v1} is defined over (docs/09 §7.1), read from the
 * resource {@code tools/ucd-gen} generates. The platform's own tables are never consulted: JDK 21's
 * {@code java.text.Normalizer} is at Unicode 15.1, below the pin, and docs/09 §7.1 clause 3 forbids
 * taking normalization from a platform below it.
 *
 * <p>Loaded once, on first use, by the holder idiom: a client that declares no text index never
 * reads the file. The resource is in this non-exported package, so JPMS keeps it private to the
 * module. A missing or malformed resource is a broken build, not a caller's error, and is thrown
 * as {@link IllegalStateException}.
 */
final class UnicodeTables {

    static final String VERSION = "17.0.0";

    private static final String RESOURCE = "ucd-" + VERSION + ".txt";

    /** Code point to its full case folding (statuses C and F). */
    final Map<Integer, int[]> casefold;
    /** Assigned code points as sorted, disjoint, inclusive ranges: lo0, hi0, lo1, hi1, ... */
    final int[] assigned;
    /** Non-zero canonical combining classes. */
    final Map<Integer, Integer> ccc;
    /** Canonical decompositions, one level (the loader does not expand them). */
    final Map<Integer, int[]> decomp;
    /** Primary composites: (first, second) to the composed code point. */
    final Map<Long, Integer> compose;

    private UnicodeTables(Map<String, String> sections, String counts) {
        this.casefold = parseMap(sections.get("casefold"));
        this.assigned = parseRanges(sections.get("assigned"));
        this.ccc = parseCcc(sections.get("ccc"));
        this.decomp = parseMap(sections.get("decomp"));
        int[] excluded = parseSet(sections.get("exclusions"));
        String actual = "casefold=" + casefold.size() + " assigned=" + assigned.length / 2
                + " ccc=" + ccc.size() + " decomp=" + decomp.size() + " exclusions="
                + excluded.length;
        if (!actual.equals(counts)) {
            throw new IllegalStateException(RESOURCE + " declares " + counts + " but holds "
                    + actual);
        }
        Map<Long, Integer> c = new HashMap<>();
        for (Map.Entry<Integer, int[]> e : decomp.entrySet()) {
            int[] d = e.getValue();
            if (d.length == 2 && Arrays.binarySearch(excluded, e.getKey()) < 0) {
                c.put(pair(d[0], d[1]), e.getKey());
            }
        }
        this.compose = c;
    }

    static UnicodeTables get() {
        return Holder.TABLES;
    }

    static long pair(int first, int second) {
        return ((long) first << 21) | second;
    }

    boolean isAssigned(int cp) {
        int lo = 0;
        int hi = assigned.length / 2 - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (cp < assigned[2 * mid]) {
                hi = mid - 1;
            } else if (cp > assigned[2 * mid + 1]) {
                lo = mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }

    int combiningClass(int cp) {
        return ccc.getOrDefault(cp, 0);
    }

    private static final class Holder {
        static final UnicodeTables TABLES = load();
    }

    private static UnicodeTables load() {
        try (InputStream in = UnicodeTables.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("the vendored Unicode tables (" + RESOURCE
                        + ") are missing from the module");
            }
            BufferedReader r = new BufferedReader(new InputStreamReader(in,
                    StandardCharsets.US_ASCII));
            Map<String, StringBuilder> sections = new LinkedHashMap<>();
            StringBuilder current = null;
            String version = null;
            String counts = null;
            for (String line; (line = r.readLine()) != null; ) {
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                if (line.startsWith("version ")) {
                    version = line.substring("version ".length());
                } else if (line.startsWith("counts ")) {
                    counts = line.substring("counts ".length());
                } else if (line.startsWith("[") && line.endsWith("]")) {
                    current = new StringBuilder();
                    sections.put(line.substring(1, line.length() - 1), current);
                } else if (current != null) {
                    current.append(line);
                } else {
                    throw new IllegalStateException(RESOURCE + ": data before any section");
                }
            }
            if (!VERSION.equals(version)) {
                throw new IllegalStateException(RESOURCE + " is Unicode " + version
                        + ", not the pinned " + VERSION);
            }
            Map<String, String> text = new HashMap<>();
            for (String name : new String[] {"casefold", "assigned", "ccc", "decomp",
                "exclusions"}) {
                StringBuilder s = sections.get(name);
                if (s == null) {
                    throw new IllegalStateException(RESOURCE + " has no [" + name + "] section");
                }
                text.put(name, s.toString());
            }
            return new UnicodeTables(text, counts);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // "cp>m1,m2;..." in hex.
    private static Map<Integer, int[]> parseMap(String s) {
        Map<Integer, int[]> out = new HashMap<>();
        for (String entry : s.split(";")) {
            int gt = entry.indexOf('>');
            String[] to = entry.substring(gt + 1).split(",");
            int[] cps = new int[to.length];
            for (int i = 0; i < to.length; i++) {
                cps[i] = Integer.parseInt(to[i], 16);
            }
            out.put(Integer.parseInt(entry.substring(0, gt), 16), cps);
        }
        return out;
    }

    // "lo-hi;cp;..." in hex, ascending.
    private static int[] parseRanges(String s) {
        String[] entries = s.split(";");
        int[] out = new int[entries.length * 2];
        for (int i = 0; i < entries.length; i++) {
            int dash = entries[i].indexOf('-');
            out[2 * i] = Integer.parseInt(dash < 0 ? entries[i] : entries[i].substring(0, dash),
                    16);
            out[2 * i + 1] = dash < 0 ? out[2 * i]
                    : Integer.parseInt(entries[i].substring(dash + 1), 16);
            if (i > 0 && out[2 * i] <= out[2 * i - 1]) {
                throw new IllegalStateException(RESOURCE + ": assigned ranges out of order");
            }
        }
        return out;
    }

    // "cp:class;..." in hex.
    private static Map<Integer, Integer> parseCcc(String s) {
        Map<Integer, Integer> out = new HashMap<>();
        for (String entry : s.split(";")) {
            int colon = entry.indexOf(':');
            out.put(Integer.parseInt(entry.substring(0, colon), 16),
                    Integer.parseInt(entry.substring(colon + 1), 16));
        }
        return out;
    }

    // "cp;cp;..." in hex; sorted for binarySearch.
    private static int[] parseSet(String s) {
        return Arrays.stream(s.split(";")).mapToInt(h -> Integer.parseInt(h, 16)).sorted()
                .toArray();
    }
}
