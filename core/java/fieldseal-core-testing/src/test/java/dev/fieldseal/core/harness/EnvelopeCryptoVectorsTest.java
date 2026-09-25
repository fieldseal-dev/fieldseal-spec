package dev.fieldseal.core.harness;

import static dev.fieldseal.core.capabilities.SuiteFiles.hex;
import static dev.fieldseal.core.harness.PrimitiveVectors.context;
import static dev.fieldseal.core.harness.PrimitiveVectors.suiteId;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import dev.fieldseal.core.internal.aead.Aead;
import dev.fieldseal.core.internal.commitment.Commitment;
import dev.fieldseal.core.internal.context.CanonicalContext;
import dev.fieldseal.core.internal.envelope.DecryptFront;
import dev.fieldseal.core.internal.envelope.EnvelopeCodec;
import dev.fieldseal.core.internal.envelope.Operand;
import dev.fieldseal.core.internal.envelope.ParsedEnvelope;
import dev.fieldseal.core.internal.kdf.Hkdf;
import dev.fieldseal.core.internal.kdf.KeyDerivation;
import dev.fieldseal.core.internal.registry.Registry;
import dev.fieldseal.core.internal.registry.Suite;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * {@code envelope/} in both directions through the S4 primitives, composed in docs/09 §3.1 and
 * §3.2's order. This is not yet the client: there is no provider, read mode or allow-list here,
 * and the vector's fixed {@code msg_seed} and nonce go straight into the primitives (docs/08 §6).
 * What it shows is that the modules the client will compose agree with the suite byte for byte:
 * the AAD, the record key, the AEAD writing in place at offset 63, and the commitment.
 */
class EnvelopeCryptoVectorsTest {

    private static final Map<String, int[]> PINNED = Map.of("envelope/ff01.json",
            new int[] {9, 0});

    private static final Commitment.Kdf KDF = Hkdf::derive;

    @TestFactory
    Stream<DynamicTest> envelopeBothDirections() {
        return PrimitiveVectors.run(PrimitiveVectors.family("envelope", PINNED),
                EnvelopeCryptoVectorsTest::value, v -> {
                    throw new AssertionError("envelope/ has no distinct vectors");
                });
    }

    private static void value(JsonNode v) {
        Suite suite = Registry.lookup(suiteId(v)).orElseThrow();
        Aead aead = Aead.forSuite(suite).orElseThrow();
        JsonNode e = v.path("expected");
        byte[] dek = hex(v.path("tenant_dek"));
        byte[] keyId = hex(v.path("key_id"));
        byte[] msgSeed = hex(v.path("msg_seed"));
        byte[] nonce = hex(v.path("nonce"));
        byte[] plaintext = hex(v.path("plaintext"));

        byte[] cc = CanonicalContext.encode(context(suite.id(), v.path("context")));
        assertEquals(e.path("canonical_context").asText(), hex(cc), "canonical_context");
        byte[] aad = CanonicalContext.aad(EnvelopeCodec.FMT_VER, keyId, msgSeed, cc);
        assertEquals(e.path("aad").asText(), hex(aad), "aad");
        byte[] recordKey = KeyDerivation.recordKey(suite, dek, keyId, msgSeed, cc);
        assertEquals(v.path("intermediates").path("record_key").asText(), hex(recordKey),
                "record_key");

        // Encrypt: docs/09 §3.1 steps 8-12, into the one allocation the codec makes.
        byte[] env = EnvelopeCodec.newEnvelope(suite, keyId, msgSeed, nonce, plaintext.length);
        int ctOffset = EnvelopeCodec.ciphertextOffset(suite);
        aead.sealInto(recordKey, nonce, aad, plaintext, env, ctOffset);
        byte[] commitment = Commitment.compute(suite, recordKey, KDF);
        System.arraycopy(commitment, 0, env,
                (int) EnvelopeCodec.commitmentOffset(suite, plaintext.length), commitment.length);
        assertEquals(e.path("envelope").asText(), hex(env), "envelope");

        // Decrypt: docs/09 §3.2 steps 2 and 6, from the pinned bytes, not from ours.
        byte[] pinned = hex(e.path("envelope"));
        ParsedEnvelope p = assertInstanceOf(DecryptFront.Ready.class,
                EnvelopeCodec.frontOfDecrypt(Operand.of(pinned))).envelope();
        byte[] rk = KeyDerivation.recordKey(p.suite(), dek, p.keyId(), p.msgSeed(), cc);
        assertTrue(Commitment.verify(p.suite(), rk, p.commitment(), KDF), "commitment verifies");
        Aead.Opened opened = aead.open(rk, p.nonce(),
                CanonicalContext.aad(EnvelopeCodec.FMT_VER, p.keyId(), p.msgSeed(), cc), pinned,
                (int) p.ctOffset(), (int) p.ctAndTagLen());
        assertEquals(hex(plaintext),
                hex(assertInstanceOf(Aead.Opened.Plaintext.class, opened).bytes()), "plaintext");
    }
}
