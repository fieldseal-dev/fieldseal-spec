package dev.fieldseal.hibernate.fixture;

import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.core.IndexDeclaration.OnUnindexable;
import dev.fieldseal.hibernate.BlindIndex;
import dev.fieldseal.hibernate.Encrypted;
import dev.fieldseal.hibernate.FieldsealTable;
import dev.fieldseal.hibernate.ReviewedOverride;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.util.UUID;

/** A legal name, indexed under onUnindexable = BUCKET (docs/29 §10; docs/12 §10.3). */
@Entity
@FieldsealTable("018f3c2e-7a1b-7c3d-8e4f-000000000011")
public class Person {
    @Id
    public UUID id;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000012")
    public String legalName;

    @BlindIndex(source = "legalName", idf = Idf.HMAC_SHA512,
            normalize = Normalizer.NFC_CASEFOLD_V1, truncateBits = 15,
            projectedPopulation = 100_000, onUnindexable = OnUnindexable.BUCKET,
            unindexableOverride = @ReviewedOverride(reason = "names must be storable",
                    approvedBy = "fixture", date = "2026-09-29"))
    public byte[] legalNameIndex;

    public Person() {}

    public Person(String legalName) {
        this.id = UUID.randomUUID();
        this.legalName = legalName;
    }
}
