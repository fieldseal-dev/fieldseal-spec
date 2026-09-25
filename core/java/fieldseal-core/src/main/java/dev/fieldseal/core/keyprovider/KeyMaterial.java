package dev.fieldseal.core.keyprovider;

import java.util.HexFormat;

/**
 * A key and the 16-byte {@code key_id} that names it in an envelope (spec §8). Both arrays belong
 * to the provider that built this (docs/09 §8.1): the record holds them as given, and the core
 * reads them without writing to them or keeping them.
 *
 * @param key the key material; never printed
 * @param keyId 16 bytes, opaque to the core (spec §3.1)
 */
public record KeyMaterial(byte[] key, byte[] keyId) {

    /** The {@code key_id} length spec §3.1 fixes. */
    public static final int KEY_ID_LEN = 16;

    /** Never prints the key (spec §9: no key material in messages). */
    @Override
    public String toString() {
        return "KeyMaterial[key=<" + (key == null ? "null" : key.length + " bytes") + ">, key_id="
                + (keyId == null ? "null" : HexFormat.of().formatHex(keyId)) + "]";
    }
}
