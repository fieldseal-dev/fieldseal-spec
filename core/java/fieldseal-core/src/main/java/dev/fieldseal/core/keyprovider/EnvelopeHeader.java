package dev.fieldseal.core.keyprovider;

import java.util.HexFormat;

/**
 * What a provider is told when asked for decryption candidates: the envelope's {@code suite_id}
 * and {@code key_id}, and the context of the decrypt call.
 *
 * <p><b>A binding decision, beyond spec §8's signature.</b> Spec §8 passes {@code decryption_keys}
 * the header alone. {@code key_id} is opaque to the core (spec §3.1), and a provider that derives
 * keys per tenant, such as the shipped derived provider, cannot find the tenant in 16 opaque
 * bytes. So this binding also passes the call's context, as a {@link KeyRequest} whose purpose is
 * {@code "encrypt"} (docs/07 §7, 2026-09-25). No plaintext and no envelope body reaches a
 * provider.
 *
 * @param suiteId the envelope's {@code suite_id}
 * @param keyId the envelope's 16-byte {@code key_id}
 * @param context the decrypt call's context
 */
public record EnvelopeHeader(int suiteId, byte[] keyId, KeyRequest context) {

    public EnvelopeHeader {
        keyId = keyId.clone();
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
    }

    @Override
    public byte[] keyId() {
        return keyId.clone();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof EnvelopeHeader h && suiteId == h.suiteId
                && java.util.Arrays.equals(keyId, h.keyId) && context.equals(h.context);
    }

    @Override
    public int hashCode() {
        return 31 * (31 * suiteId + java.util.Arrays.hashCode(keyId)) + context.hashCode();
    }

    @Override
    public String toString() {
        return String.format("EnvelopeHeader[suite=0x%04X, key_id=%s, %s]", suiteId,
                HexFormat.of().formatHex(keyId), context);
    }
}
