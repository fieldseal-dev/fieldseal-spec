package dev.fieldseal.core.internal.envelope;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.fieldseal.core.errors.FieldsealError;
import dev.fieldseal.core.errors.LengthExceededError;
import dev.fieldseal.core.internal.registry.Registry;
import dev.fieldseal.core.internal.registry.Suite;
import java.util.Arrays;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.junit.jupiter.api.Test;

/**
 * The codec fuzzing pass docs/09 §4 mandates and docs/27 §7 lists: {@code parse ∘ serialize},
 * {@code isCiphertext} totality, recognition over the length edges in 64-bit arithmetic, and
 * guard totality.
 */
class CodecProperties {

    private static final long TWO_31 = 1L << 31;

    record Fields(Suite suite, byte[] keyId, byte[] msgSeed, byte[] nonce, byte[] ctAndTag,
            byte[] commitment) {}

    @Provide
    Arbitrary<Fields> fields() {
        return Arbitraries.of(Registry.all()).flatMap(s -> Combinators.combine(
                bytes(16), bytes(32), bytes(s.nonceLen()),
                Arbitraries.bytes().array(byte[].class).ofMinSize(s.tagLen())
                        .ofMaxSize(s.tagLen() + 300),
                bytes(s.commitLen()))
                .as((k, m, n, c, cm) -> new Fields(s, k, m, n, c, cm)));
    }

    private static Arbitrary<byte[]> bytes(int n) {
        return Arbitraries.bytes().array(byte[].class).ofSize(n);
    }

    @Property
    void parseOfSerializeRoundTrips(@ForAll("fields") Fields f) {
        byte[] env = EnvelopeCodec.serialize(f.suite(), f.keyId(), f.msgSeed(), f.nonce(),
                f.ctAndTag(), f.commitment());
        assertEquals(BufferLimits.fixedOverhead(f.suite()) + f.ctAndTag().length - f.suite().tagLen(),
                env.length);
        assertTrue(EnvelopeCodec.isCiphertext(env));

        ParsedEnvelope p = assertInstanceOf(DecryptFront.Ready.class,
                EnvelopeCodec.frontOfDecrypt(Operand.of(env))).envelope();
        assertEquals(f.suite(), p.suite());
        assertArrayEquals(f.keyId(), p.keyId());
        assertArrayEquals(f.msgSeed(), p.msgSeed());
        assertArrayEquals(f.nonce(), p.nonce());
        assertArrayEquals(f.commitment(), p.commitment());
        assertEquals(f.ctAndTag().length, p.ctAndTagLen());
        assertArrayEquals(f.ctAndTag(), Arrays.copyOfRange(env, (int) p.ctOffset(),
                (int) (p.ctOffset() + p.ctAndTagLen())));
        assertEquals(f.ctAndTag().length - f.suite().tagLen(), p.plaintextLen());
    }

    /** Arbitrary bytes, and bytes that start like an envelope, so every branch is reached. */
    @Provide
    Arbitrary<byte[]> anyInput() {
        Arbitrary<byte[]> prefix = Arbitraries.of(
                new byte[0], new byte[] {1}, new byte[] {2}, new byte[] {1, (byte) 0xFF, 1},
                new byte[] {1, (byte) 0xFF, 2}, new byte[] {1, 0, 1}, new byte[] {2, (byte) 0xFF, 1});
        Arbitrary<byte[]> tail = Arbitraries.bytes().array(byte[].class).ofMaxSize(200);
        // Each suite's minimum, one under and one over: random lengths almost never land on
        // it, and it is the one place a wrong minimum shows.
        Arbitrary<byte[]> atTheMinimum = Combinators.combine(
                Arbitraries.of(new byte[] {1, (byte) 0xFF, 1}, new byte[] {1, (byte) 0xFF, 2}),
                Arbitraries.of(110, 111, 112, 122, 123, 124))
                .as((p, len) -> Arrays.copyOf(p, len));
        return Arbitraries.oneOf(
                atTheMinimum,
                Arbitraries.bytes().array(byte[].class).ofMaxSize(300),
                Combinators.combine(prefix, tail).as((p, t) -> {
                    byte[] out = Arrays.copyOf(p, p.length + t.length);
                    System.arraycopy(t, 0, out, p.length, t.length);
                    return out;
                }));
    }

    /**
     * {@code isCiphertext} is total and agrees with spec §3.4's first row, restated here from
     * the spec rather than from the codec: the per-suite minimum is the spec's figure, not the
     * registry's, so a wrong registry row moves only one side.
     */
    @Property
    void isCiphertextIsTotalAndMatchesSpecRowOne(@ForAll("anyInput") byte[] input) {
        int min = input.length >= 3 && input[0] == 1
                ? specMinimum(((input[1] & 0xFF) << 8) | (input[2] & 0xFF))
                : -1;
        boolean expected = min > 0 && input.length >= min;
        assertEquals(expected, EnvelopeCodec.isCiphertext(input));
    }

    /**
     * spec §3.4 row one, per suite: the 51-byte header (§3.1) plus the suite's nonce, tag and
     * commitment (§4.2). -1 for an unregistered suite.
     */
    private static int specMinimum(int suiteId) {
        return switch (suiteId) {
            case 0xFF01 -> 111; // 51 + 12 + 16 + 32
            case 0xFF02 -> 123; // 51 + 24 + 16 + 32
            default -> -1;
        };
    }

    /**
     * Guard totality: over any real array, the decrypt front returns one of its three outcomes
     * and throws nothing (a real array cannot exceed the bound, so not even LENGTH_EXCEEDED).
     */
    @Property
    void theDecryptFrontIsTotalOverArrays(@ForAll("anyInput") byte[] input) {
        DecryptFront f = EnvelopeCodec.frontOfDecrypt(Operand.of(input));
        boolean reserved = input.length >= 111 && input[0] == 2;
        assertEquals(reserved, f instanceof DecryptFront.ReservedVersion);
        assertEquals(EnvelopeCodec.isCiphertext(input), f instanceof DecryptFront.Ready);
    }

    /**
     * spec §3.1, §3.4: 0x02 is reserved-version input from exactly 111 bytes, and non-envelope
     * below. No vector sits on this edge (the suite's are 120 bytes and under 111), so it is
     * pinned here.
     */
    @Test
    void theReservedVersionFloorIsExactly111() {
        for (long len : new long[] {1, 110, 111, 112, (1L << 31) + 111}) {
            SyntheticOperand op = SyntheticOperand.fabricating(len, new byte[] {2});
            Recognition want = len >= 111 ? Recognition.RESERVED_VERSION : Recognition.NON_ENVELOPE;
            assertEquals(want, EnvelopeCodec.recognize(op), "len " + len);
            assertTrue(op.highestOffsetRead() == 0, "read past fmt_ver");
        }
    }

    /**
     * Recognition and the guard at docs/27 §7's length edges, each computed as a {@code long}:
     * 0, 1, overhead−1, overhead, overhead+1, and implied lengths of 2^31−1, 2^31, 2^32 and
     * the largest a {@code long} allows. Only typed errors may escape.
     */
    @Test
    void lengthEdges() {
        for (Suite s : Registry.all()) {
            long overhead = BufferLimits.fixedOverhead(s);
            byte[] header = SyntheticOperand.header(s);
            long[] lengths = {0, 1, overhead - 1, overhead, overhead + 1, overhead + TWO_31 - 1,
                overhead + TWO_31, overhead + (1L << 32), Long.MAX_VALUE};
            for (long len : lengths) {
                SyntheticOperand op = SyntheticOperand.fabricating(len,
                        Arrays.copyOf(header, (int) Math.min(len, header.length)));
                boolean recognized = len >= overhead;
                assertEquals(recognized,
                        EnvelopeCodec.recognize(op) instanceof Recognition.Envelope, "len " + len);
                if (!recognized) {
                    assertInstanceOf(DecryptFront.NonEnvelope.class, EnvelopeCodec.frontOfDecrypt(op));
                } else if (len - overhead > BufferLimits.MAX_PLAINTEXT) {
                    FieldsealError e = assertThrows(LengthExceededError.class,
                            () -> EnvelopeCodec.frontOfDecrypt(op), "len " + len);
                    assertEquals("LENGTH_EXCEEDED", e.code());
                } else {
                    ParsedEnvelope p = assertInstanceOf(DecryptFront.Ready.class,
                            EnvelopeCodec.frontOfDecrypt(op)).envelope();
                    assertEquals(len - overhead, p.plaintextLen(), "len " + len);
                }
            }
        }
    }
}
