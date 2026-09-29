package dev.fieldseal.hibernate;

import dev.fieldseal.core.FieldContext;
import dev.fieldseal.core.Fieldseal;
import dev.fieldseal.core.Unassigned;
import dev.fieldseal.core.errors.InvalidArgumentError;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/** Index derivation, shared by the write path and the finder so that the two cannot differ. */
final class Indexing {
    private Indexing() {}

    /**
     * The index of {@code rendered}, the source attribute's spec §3.6 plaintext: the bytes the
     * listener encrypts, so the envelope and the index are derived from one rendering. Under
     * {@code BUCKET} the core returns the column's marker for a value its normalizer refuses;
     * under {@code REFUSE} this raises {@link FieldsealUnindexableException} (docs/29 §10).
     */
    static byte[] derive(Fieldseal client, IndexSpec ix, byte[] rendered, FieldContext ctx) {
        try {
            return client.blindIndex(rendered, ctx);
        } catch (InvalidArgumentError e) {
            throw unindexable(ix, rendered, e);
        }
    }

    private static FieldsealUnindexableException unindexable(IndexSpec ix, byte[] rendered,
            InvalidArgumentError cause) {
        String label = ix.source.label;
        Optional<Unassigned> where = Optional.empty();
        String text = null;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(rendered)).toString();
            where = Fieldseal.firstUnassigned(text);
        } catch (CharacterCodingException e) {
            // Not text: nothing to locate. The message says so.
        }
        if (where.isEmpty()) {
            return new FieldsealUnindexableException(label, -1, -1, label + " cannot be "
                    + "indexed by " + ix.label + " (" + ix.declaration.normalize().id() + " "
                    + "refused it: " + cause.getMessage() + "). The value is not wrong; the "
                    + "index cannot fingerprint it. Store it under onUnindexable = BUCKET, or "
                    + "write it through a path that does not derive this index (docs/29 §10)",
                    cause);
        }
        Unassigned u = where.get();
        String ch = new String(Character.toChars(u.codePoint()));
        return new FieldsealUnindexableException(label, u.codePoint(), u.offset(), label + ": "
                + "this value can't be saved yet. The character " + ch + " (U+"
                + String.format("%04X", u.codePoint()) + ", position " + (u.offset() + 1)
                + ") is one this system's Unicode tables (" + Fieldseal.UNICODE_VERSION
                + ") do not recognise yet. That is a gap on our side, not a problem with the "
                + "value. An operator can store it by moving " + ix.label + " to "
                + "onUnindexable = BUCKET (docs/29 §10; docs/12 §10.2)", cause);
    }
}
