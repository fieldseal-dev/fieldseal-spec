package dev.fieldseal.hibernate;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Spec §3.6: the plaintext bytes an attribute's value becomes, and back (docs/29 §2.2). One
 * instance per encrypted attribute; both the write path and the index path call {@link #render},
 * and the read path calls {@link #parse}. The {@code codec/} vector family runs through this class
 * (docs/08 §4.8).
 *
 * <p>Readers are exactly as strict as writers: {@link #parse} refuses anything but the canonical
 * rendering, and a value the attribute's Java type cannot hold exactly. Every refusal is a {@link
 * FieldsealNotSupportedException}, never a §9 error: nothing about the envelope is wrong.
 */
final class Codec {

    /** Spec §3.6's closed vocabulary. */
    enum LogicalType {
        STRING("string"), BYTES("bytes"), INT("int"), DECIMAL("decimal"), FLOAT("float"),
        BOOLEAN("boolean"), DATE("date"), DATETIME("datetime");

        final String id;

        LogicalType(String id) {
            this.id = id;
        }
    }

    private static final Pattern INT = Pattern.compile("0|-?[1-9][0-9]*");
    private static final Pattern DECIMAL = Pattern.compile("-?(0|[1-9][0-9]*)(\\.[0-9]*[1-9])?");
    private static final Pattern FLOAT =
            Pattern.compile("-?(0|[1-9][0-9]*)(\\.[0-9]+)?(e[+-][0-9]+)?");
    private static final Pattern DATE = Pattern.compile("([0-9]{4})-([0-9]{2})-([0-9]{2})");
    private static final Pattern DATETIME = Pattern.compile(
            "([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\\.([0-9]{6})Z");

    private static final BigInteger LONG_MIN = BigInteger.valueOf(Long.MIN_VALUE);
    private static final BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);

    final LogicalType type;
    /** The attribute's Java type, boxed. */
    final Class<?> javaType;
    /** {@code Entity.attribute}, for messages. */
    final String label;

    private Codec(LogicalType type, Class<?> javaType, String label) {
        this.type = type;
        this.javaType = javaType;
        this.label = label;
    }

    /**
     * The codec for an attribute of {@code javaType}, or null if spec §3.6 has no logical type
     * for it. The caller refuses the declaration (spec §3.6: at declaration time).
     */
    static Codec of(Class<?> javaType, String label) {
        Class<?> t = box(javaType);
        LogicalType lt;
        if (t == String.class) {
            lt = LogicalType.STRING;
        } else if (t == byte[].class) {
            lt = LogicalType.BYTES;
        } else if (t == Long.class || t == Integer.class || t == Short.class
                || t == BigInteger.class) {
            lt = LogicalType.INT;
        } else if (t == BigDecimal.class) {
            lt = LogicalType.DECIMAL;
        } else if (t == Double.class) {
            lt = LogicalType.FLOAT;
        } else if (t == Boolean.class) {
            lt = LogicalType.BOOLEAN;
        } else if (t == LocalDate.class) {
            lt = LogicalType.DATE;
        } else if (t == Instant.class || t == OffsetDateTime.class) {
            lt = LogicalType.DATETIME;
        } else {
            return null;
        }
        return new Codec(lt, t, label);
    }

    /** The Java types {@link #of} maps, for a refusal message. */
    static final String SUPPORTED = "String, byte[], long/Long, int/Integer, short/Short, "
            + "BigInteger, BigDecimal, double/Double, boolean/Boolean, LocalDate, Instant, "
            + "OffsetDateTime";

    // ---- write ----------------------------------------------------------------------------

    /** Spec §3.6's rendering of {@code value}, which must not be null. */
    byte[] render(Object value) {
        if (!javaType.isInstance(value)) {
            throw refuse("got a value of type " + value.getClass().getName());
        }
        return switch (type) {
            case STRING -> renderString((String) value);
            case BYTES -> ((byte[]) value).clone();
            case INT -> ascii(value instanceof BigInteger b ? b.toString()
                    : Long.toString(((Number) value).longValue()));
            case DECIMAL -> ascii(renderDecimal((BigDecimal) value));
            case FLOAT -> ascii(renderFloat((Double) value));
            case BOOLEAN -> ascii(((Boolean) value) ? "true" : "false");
            case DATE -> ascii(renderDate((LocalDate) value));
            case DATETIME -> ascii(renderDatetime(value instanceof OffsetDateTime o
                    ? o.toInstant() : (Instant) value));
        };
    }

    private byte[] renderString(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < s.length()
                    && Character.isLowSurrogate(s.charAt(i + 1))) {
                i++;
            } else if (Character.isSurrogate(c)) {
                throw refuse("an unpaired UTF-16 surrogate at index " + i
                        + " is not a Unicode scalar value");
            }
        }
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String renderDecimal(BigDecimal d) {
        return d.signum() == 0 ? "0" : d.stripTrailingZeros().toPlainString();
    }

    private String renderFloat(double x) {
        if (Double.isNaN(x) || Double.isInfinite(x)) {
            throw refuse(x + " is not a finite binary64");
        }
        return ecmaScriptToString(x);
    }

    /**
     * ECMA-262's {@code Number::toString(x)} in radix 10, except that negative zero is {@code -0}
     * (spec §3.6). Not {@link Double#toString}: since JDK 19 that picks the closest decimal of
     * length one <em>or two</em> when one digit suffices, so the smallest subnormal prints as
     * {@code 4.9E-324} where ECMAScript prints {@code 5e-324}. This finds ECMAScript's {@code k}
     * and {@code s} directly: the fewest digits that round-trip, and of those the closest.
     */
    static String ecmaScriptToString(double x) {
        if (x == 0) {
            return (Double.doubleToRawLongBits(x) < 0) ? "-0" : "0";
        }
        double ax = Math.abs(x);
        BigDecimal exact = new BigDecimal(ax);
        BigDecimal s = null;
        for (int k = 1; k <= 17 && s == null; k++) {
            BigDecimal lo = exact.round(new MathContext(k, RoundingMode.FLOOR));
            BigDecimal hi = exact.round(new MathContext(k, RoundingMode.CEILING));
            boolean loOk = Double.parseDouble(lo.toString()) == ax;
            boolean hiOk = Double.parseDouble(hi.toString()) == ax;
            if (loOk && hiOk && lo.compareTo(hi) != 0) {
                int cmp = exact.subtract(lo).compareTo(hi.subtract(exact));
                if (cmp != 0) {
                    s = cmp < 0 ? lo : hi;
                } else {
                    s = lo.unscaledValue().testBit(0) ? hi : lo;
                }
            } else if (loOk) {
                s = lo;
            } else if (hiOk) {
                s = hi;
            }
        }
        if (s == null) {
            throw new IllegalStateException("no round-tripping decimal for " + x);
        }
        s = s.stripTrailingZeros();
        String digits = s.unscaledValue().toString();
        int k = digits.length();
        int n = k - s.scale();
        StringBuilder out = new StringBuilder(x < 0 ? "-" : "");
        if (k <= n && n <= 21) {
            out.append(digits).append("0".repeat(n - k));
        } else if (0 < n && n <= 21) {
            out.append(digits, 0, n).append('.').append(digits, n, k);
        } else if (-6 < n && n <= 0) {
            out.append("0.").append("0".repeat(-n)).append(digits);
        } else {
            int e = n - 1;
            out.append(digits.charAt(0));
            if (k > 1) {
                out.append('.').append(digits, 1, k);
            }
            out.append('e').append(e < 0 ? '-' : '+').append(Math.abs(e));
        }
        return out.toString();
    }

    private String renderDate(LocalDate d) {
        if (d.getYear() < 1 || d.getYear() > 9999) {
            throw refuse("the year " + d.getYear() + " is outside 0001-9999");
        }
        return String.format(Locale.ROOT, "%04d-%02d-%02d", d.getYear(), d.getMonthValue(),
                d.getDayOfMonth());
    }

    private String renderDatetime(Instant i) {
        if (i.getNano() % 1000 != 0) {
            throw refuse(i + " has a nonzero digit below the microsecond, which spec §3.6 "
                    + "cannot hold; it is refused rather than truncated");
        }
        LocalDateTime t;
        try {
            t = LocalDateTime.ofInstant(i, ZoneOffset.UTC);
        } catch (DateTimeException e) {
            throw refuse(i + " is outside the years 0001-9999 in UTC");
        }
        if (t.getYear() < 1 || t.getYear() > 9999) {
            throw refuse(i + " is outside the years 0001-9999 in UTC");
        }
        return String.format(Locale.ROOT, "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ", t.getYear(),
                t.getMonthValue(), t.getDayOfMonth(), t.getHour(), t.getMinute(), t.getSecond(),
                t.getNano() / 1000);
    }

    // ---- read -----------------------------------------------------------------------------

    /** The value {@code plaintext} renders, or a refusal if it is not the canonical rendering. */
    Object parse(byte[] plaintext) {
        if (type == LogicalType.BYTES) {
            return plaintext.clone();
        }
        if (type == LogicalType.STRING) {
            try {
                return StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(plaintext)).toString();
            } catch (CharacterCodingException e) {
                throw refuse("the stored plaintext is not well-formed UTF-8");
            }
        }
        for (byte b : plaintext) {
            if (b < 0x21 || b > 0x7e) {
                throw notCanonical(plaintext);
            }
        }
        String s = new String(plaintext, StandardCharsets.US_ASCII);
        return switch (type) {
            case INT -> parseInt(s);
            case DECIMAL -> {
                if (!DECIMAL.matcher(s).matches() || s.equals("-0")) {
                    throw notCanonical(plaintext);
                }
                yield new BigDecimal(s);
            }
            case FLOAT -> {
                if (!FLOAT.matcher(s).matches()) {
                    throw notCanonical(plaintext);
                }
                double d = Double.parseDouble(s);
                if (Double.isInfinite(d) || !ecmaScriptToString(d).equals(s)) {
                    throw notCanonical(plaintext);
                }
                yield d;
            }
            case BOOLEAN -> switch (s) {
                case "true" -> Boolean.TRUE;
                case "false" -> Boolean.FALSE;
                default -> throw notCanonical(plaintext);
            };
            case DATE -> parseDate(s, plaintext);
            case DATETIME -> parseDatetime(s, plaintext);
            default -> throw new IllegalStateException(type.id);
        };
    }

    private Object parseInt(String s) {
        if (!INT.matcher(s).matches()) {
            throw notCanonical(s.getBytes(StandardCharsets.US_ASCII));
        }
        BigInteger v = new BigInteger(s);
        if (javaType == BigInteger.class) {
            return v;
        }
        long min = javaType == Long.class ? Long.MIN_VALUE
                : javaType == Integer.class ? Integer.MIN_VALUE : Short.MIN_VALUE;
        long max = javaType == Long.class ? Long.MAX_VALUE
                : javaType == Integer.class ? Integer.MAX_VALUE : Short.MAX_VALUE;
        if (v.compareTo(LONG_MIN) < 0 || v.compareTo(LONG_MAX) > 0
                || v.longValue() < min || v.longValue() > max) {
            throw refuse("the stored value " + s + " does not fit " + javaType.getSimpleName()
                    + "; it is refused rather than truncated");
        }
        long l = v.longValue();
        if (javaType == Long.class) {
            return l;
        }
        return javaType == Integer.class ? (Object) (int) l : (Object) (short) l;
    }

    private LocalDate parseDate(String s, byte[] raw) {
        var m = DATE.matcher(s);
        if (!m.matches()) {
            throw notCanonical(raw);
        }
        try {
            LocalDate d = LocalDate.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)),
                    Integer.parseInt(m.group(3)));
            if (d.getYear() < 1) {
                throw notCanonical(raw);
            }
            return d;
        } catch (DateTimeException e) {
            throw notCanonical(raw);
        }
    }

    private Object parseDatetime(String s, byte[] raw) {
        var m = DATETIME.matcher(s);
        if (!m.matches()) {
            throw notCanonical(raw);
        }
        Instant i;
        try {
            LocalDateTime t = LocalDateTime.of(Integer.parseInt(m.group(1)),
                    Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)),
                    Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)),
                    Integer.parseInt(m.group(6)), Integer.parseInt(m.group(7)) * 1000);
            if (t.getYear() < 1) {
                throw notCanonical(raw);
            }
            i = t.toInstant(ZoneOffset.UTC);
        } catch (DateTimeException e) {
            throw notCanonical(raw);
        }
        return javaType == OffsetDateTime.class ? i.atOffset(ZoneOffset.UTC) : i;
    }

    // ---- helpers --------------------------------------------------------------------------

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private FieldsealNotSupportedException refuse(String why) {
        return new FieldsealNotSupportedException(label + " is declared " + type.id
                + " (spec §3.6, from " + javaType.getSimpleName() + "): " + why);
    }

    private FieldsealNotSupportedException notCanonical(byte[] raw) {
        return refuse("the stored plaintext is not the canonical " + type.id + " rendering ("
                + raw.length + " bytes); readers are as strict as writers");
    }

    static Class<?> box(Class<?> t) {
        if (!t.isPrimitive()) {
            return t;
        }
        if (t == long.class) {
            return Long.class;
        } else if (t == int.class) {
            return Integer.class;
        } else if (t == short.class) {
            return Short.class;
        } else if (t == double.class) {
            return Double.class;
        } else if (t == boolean.class) {
            return Boolean.class;
        }
        return t;
    }
}
