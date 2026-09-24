package dev.fieldseal.core.internal.registry;

/**
 * One row of the frozen suite table (spec §4.2; docs/09 §6). A suite is complete: nothing about
 * it is chosen by a caller (spec §4.1).
 *
 * @param id the two-byte {@code suite_id}
 * @param name the spec §4.2 name
 * @param aead the AEAD, named for messages and documentation only
 * @param keyLen the record-key length the KDF derives (spec §5.3)
 * @param nonceLen the nonce length in the envelope
 * @param tagLen the tag length in the envelope
 * @param commitLen the commitment length in the envelope; 0 for a natively committing AEAD
 * @param implemented whether this core can perform the suite. A registered suite it cannot
 *     perform is still recognized (spec §3.4); what a client configured with one does is the
 *     {@code unimplemented-registered-suite} pinned decision (docs/14 §4), settled at S4.
 */
public record Suite(int id, String name, String aead, int keyLen, int nonceLen, int tagLen,
        int commitLen, boolean implemented) {

    /**
     * spec §4.8: the {@code 0xFF00}–{@code 0xFFFF} range is permanently provisional, and the
     * answer is one masked comparison on {@code suite_id}.
     */
    public static boolean isProvisional(int suiteId) {
        return (suiteId & 0xFF00) == 0xFF00;
    }

    public boolean provisional() {
        return isProvisional(id);
    }

    /** {@code 0x%04X}, the form every message uses. */
    public String hexId() {
        return String.format("0x%04X", id);
    }
}
