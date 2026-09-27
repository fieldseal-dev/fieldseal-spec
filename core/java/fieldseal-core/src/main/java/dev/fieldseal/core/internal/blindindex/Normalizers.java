package dev.fieldseal.core.internal.blindindex;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;

/**
 * The closed, versioned normalizer set of docs/09 §7: {@code identity}, {@code nfc-casefold-v1}
 * and {@code digits-only-v1}. Each takes the language's text type or bytes (docs/09 §7.1, "where
 * the refusal has to live") and returns a fresh array the caller owns and erases.
 *
 * <p>A value a normalizer cannot fingerprint is a {@link Result.Refused}, not an exception, so that
 * the client decides between {@code INVALID_ARGUMENT} and the reserved marker (docs/09 §7.2). A
 * refusal's reason names the offending code point or byte sequence and its offset, and nothing
 * around it: error text is routinely logged, and spec §9 keeps plaintext out of it (docs/08 §5
 * item 9 bounds a malformed sequence at four bytes).
 */
public final class Normalizers {

    /** The Unicode version {@code nfc-casefold-v1} is pinned to (docs/09 §7.1 clause 1). */
    public static final String UNICODE_VERSION = UnicodeTables.VERSION;

    /** docs/09 §7.2: {@code 0xFF || "fieldseal-unindexable-v1"}, 25 bytes. */
    private static final byte[] RESERVED_PREIMAGE = preimage();

    private static final HexFormat HEX = HexFormat.of().withUpperCase();

    /** The identifiers; each is its own definition (docs/09 §7.1 preamble). */
    public enum Id {
        IDENTITY("identity", false),
        NFC_CASEFOLD_V1("nfc-casefold-v1", true),
        DIGITS_ONLY_V1("digits-only-v1", false);

        private final String wire;
        private final boolean consultsUnicode;

        Id(String wire, boolean consultsUnicode) {
            this.wire = wire;
            this.consultsUnicode = consultsUnicode;
        }

        public String wire() {
            return wire;
        }

        /**
         * Whether this normalizer can refuse well-formed text, a sequence of Unicode scalar
         * values: only one that consults a Unicode table can (docs/09 §7.2), so only it can take
         * {@code on_unindexable = bucket}. Every normalizer refuses text that is <em>not</em>
         * well formed (a lone surrogate, which has no UTF-8 encoding), and that refusal is not
         * what {@code bucket} is for: spec §3.6 has an adapter refuse to store such a value at
         * all, so there is no row for a marker to keep findable.
         */
        public boolean canRefuseWellFormedText() {
            return consultsUnicode;
        }
    }

    /** A normalization's outcome. */
    public sealed interface Result {
        /** The normalized bytes; the caller owns and erases them. */
        record Value(byte[] bytes) implements Result {}

        /** Not fingerprintable under this normalizer; {@code reason} is safe to log. */
        record Refused(String reason) implements Result {}
    }

    private Normalizers() {}

    /** Normalizes text. {@code value} must be non-null. */
    public static Result apply(Id id, String value) {
        return switch (id) {
            case IDENTITY -> utf8(value);
            case NFC_CASEFOLD_V1 -> nfcCasefold(value);
            case DIGITS_ONLY_V1 -> digitsOnly(value);
        };
    }

    /**
     * Normalizes bytes. {@code identity} and {@code digits-only-v1} are defined on bytes and read
     * them as they are; {@code nfc-casefold-v1} first decodes them as strict UTF-8 (docs/09 §7.1
     * clause 5), and a decoding failure is a refusal, never a replacement character.
     */
    public static Result apply(Id id, byte[] value) {
        return switch (id) {
            case IDENTITY -> new Result.Value(value.clone());
            case DIGITS_ONLY_V1 -> new Result.Value(digits(value));
            case NFC_CASEFOLD_V1 -> {
                Object decoded = strictUtf8(value);
                yield decoded instanceof String s ? nfcCasefold(s) : (Result) decoded;
            }
        };
    }

    /**
     * The first code point {@code nfc-casefold-v1} would refuse, as {@code {codePoint, offset}}
     * with the offset counted in code points, not UTF-16 units (docs/09 §12); null if none. A lone
     * surrogate is reported too: it is refused on the same terms (docs/09 §7.1 clause 1).
     */
    public static int[] firstUnassigned(CharSequence text) {
        UnicodeTables t = UnicodeTables.get();
        int offset = 0;
        for (int i = 0; i < text.length(); offset++) {
            int cp = Character.codePointAt(text, i);
            if (isSurrogate(cp) || !t.isAssigned(cp)) {
                return new int[] {cp, offset};
            }
            i += Character.charCount(cp);
        }
        return null;
    }

    /** The docs/09 §7.2 reserved preimage; a copy. */
    public static byte[] reservedPreimage() {
        return RESERVED_PREIMAGE.clone();
    }

    private static byte[] preimage() {
        byte[] label = "fieldseal-unindexable-v1".getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[1 + label.length];
        out[0] = (byte) 0xFF;
        System.arraycopy(label, 0, out, 1, label.length);
        return out;
    }

    /** A surrogate code point: in a {@link String}, one that {@code codePointAt} left unpaired. */
    private static boolean isSurrogate(int cp) {
        return cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE;
    }

    // ----------------------------------------------------------------------------------------

    /** docs/09 §7.1: {@code NFC(toCasefold(NFC(X)))}, UTF-8 encoded, after clause 1's check. */
    private static Result nfcCasefold(String value) {
        int[] bad = firstUnassigned(value);
        if (bad != null) {
            return new Result.Refused(describe(bad[0], bad[1]));
        }
        int[] cps = value.codePoints().toArray();
        int[] out = Nfc.nfc(Nfc.casefold(Nfc.nfc(cps)));
        Arrays.fill(cps, 0);
        // Every code point here is assigned and none is a surrogate, so the encoding is exact.
        byte[] bytes = new String(out, 0, out.length).getBytes(StandardCharsets.UTF_8);
        Arrays.fill(out, 0);
        return new Result.Value(bytes);
    }

    private static String describe(int cp, int offset) {
        String name = String.format(Locale.ROOT, "U+%04X", cp);
        return isSurrogate(cp)
                ? "a lone surrogate, " + name + ", at code point offset " + offset
                        + ": it has no UTF-8 encoding (docs/09 §7.1 clause 1)"
                : name + " at code point offset " + offset + " is not assigned in Unicode "
                        + UNICODE_VERSION + " (docs/09 §7.1 clause 1)";
    }

    /** Text to UTF-8 for a normalizer defined on bytes: a lone surrogate cannot be encoded. */
    private static Result utf8(String value) {
        for (int i = 0, offset = 0; i < value.length(); offset++) {
            int cp = value.codePointAt(i);
            if (isSurrogate(cp)) {
                return new Result.Refused(describe(cp, offset));
            }
            i += Character.charCount(cp);
        }
        return new Result.Value(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * {@code digits-only-v1} on text: the ASCII digits. UTF-8 encodes no other character with a
     * byte in {@code 0x30..0x39}, so this equals the byte definition applied to the encoding, and
     * a lone surrogate, which has none, is simply not a digit.
     */
    private static Result digitsOnly(String value) {
        byte[] out = new byte[value.length()];
        int n = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= '0' && c <= '9') {
                out[n++] = (byte) c;
            }
        }
        byte[] result = Arrays.copyOf(out, n);
        Arrays.fill(out, (byte) 0);
        return new Result.Value(result);
    }

    /** docs/09 §7: strip ASCII non-digits, on bytes. */
    private static byte[] digits(byte[] value) {
        int n = 0;
        for (byte b : value) {
            if (b >= '0' && b <= '9') {
                n++;
            }
        }
        byte[] out = new byte[n];
        int j = 0;
        for (byte b : value) {
            if (b >= '0' && b <= '9') {
                out[j++] = b;
            }
        }
        return out;
    }

    /**
     * Strict UTF-8 (docs/09 §7.1 clause 5; docs/27 §4): a {@link String}, or a {@link
     * Result.Refused} naming the byte offset and the malformed sequence. Never replacement.
     */
    private static Object strictUtf8(byte[] value) {
        CharsetDecoder d = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer in = ByteBuffer.wrap(value);
        CharBuffer out = CharBuffer.allocate(value.length);
        CoderResult r = d.decode(in, out, true);
        if (!r.isError()) {
            r = d.flush(out);
        }
        if (r.isError()) {
            int at = in.position();
            int len = Math.min(Math.max(r.length(), 1), Math.min(4, value.length - at));
            char[] partial = out.array();
            Arrays.fill(partial, '\0');
            return new Result.Refused("malformed UTF-8 at byte offset " + at + ": "
                    + HEX.formatHex(value, at, at + len) + " (docs/09 §7.1 clause 5)");
        }
        out.flip();
        String s = out.toString();
        Arrays.fill(out.array(), '\0');
        return s;
    }
}
