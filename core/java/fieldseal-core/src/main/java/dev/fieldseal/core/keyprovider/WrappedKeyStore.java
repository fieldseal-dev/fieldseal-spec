package dev.fieldseal.core.keyprovider;

import java.util.List;

/**
 * Where the envelope provider finds wrapped keys: the deployment's table of KMS-wrapped DEKs and
 * index keys, per tenant and version. The provider calls it only from {@code warm}, so it may do
 * I/O.
 */
public interface WrappedKeyStore {

    /**
     * Every currently valid version of the key {@code request} names, active-for-write first
     * (spec §5.6). The role follows the purpose: the tenant DEK for {@code "encrypt"}, the tenant
     * index key for {@code "index:<id>"} (spec §8). Empty when the tenant has none.
     */
    List<WrappedKey> keys(KeyRequest request);

    /**
     * One wrapped key version.
     *
     * @param keyId the 16-byte {@code key_id} envelopes written under it carry
     * @param blob what {@link Wrapper#wrap} produced
     */
    record WrappedKey(byte[] keyId, byte[] blob) {}
}
