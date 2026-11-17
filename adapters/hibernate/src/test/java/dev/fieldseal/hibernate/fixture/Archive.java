package dev.fieldseal.hibernate.fixture;

import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.hibernate.BlindIndex;
import dev.fieldseal.hibernate.Encrypted;
import dev.fieldseal.hibernate.FieldsealTable;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.util.UUID;

/**
 * An index declared under {@code 0xFF02} while the client's write suite and allow-list stay
 * {@code 0xFF01} (spec §7.2, #213): the index context's {@code suite_id} is the declared suite,
 * never the write suite.
 */
@Entity
@FieldsealTable("018f3c2e-7a1b-7c3d-8e4f-000000000061")
public class Archive {
    @Id
    public UUID id;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000062")
    public String ref;

    @BlindIndex(source = "ref", suiteId = 0xFF02, idf = Idf.HMAC_SHA512,
            normalize = Normalizer.NFC_CASEFOLD_V1, truncateBits = 15,
            projectedPopulation = 100_000)
    public byte[] refIndex;

    public Archive() {}

    public Archive(String ref) {
        this.id = UUID.randomUUID();
        this.ref = ref;
    }
}
