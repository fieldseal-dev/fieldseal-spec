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
     *
     * <p><b>An empty list is an answer, not a failure.</b> The envelope provider treats it as
     * "this tenant has no valid keys": it evicts every cached version for the slot and stops
     * writing under it until a later warm lists one. A store that cannot reach its backend MUST
     * throw instead, which fails the warm and leaves the slot as it was.
     */
    List<WrappedKey> keys(KeyRequest request);

    /**
     * One wrapped key version. A handle, like {@link KeyMaterial}: {@code equals} compares the
     * arrays by identity, and the core never compares one.
     *
     * @param keyId the 16-byte {@code key_id} envelopes written under it carry
     * @param blob what {@link Wrapper#wrap} produced
     */
    record WrappedKey(byte[] keyId, byte[] blob) {}
}
