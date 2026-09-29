package dev.fieldseal.hibernate.fixture;

import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.hibernate.BlindIndex;
import dev.fieldseal.hibernate.Encrypted;
import dev.fieldseal.hibernate.FieldsealTable;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.util.UUID;

/** The workhorse: an indexed email, an encrypted note and age, and a plain status. */
@Entity
@FieldsealTable("018f3c2e-7a1b-7c3d-8e4f-000000000001")
public class Patient {
    @Id
    public UUID id;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000002")
    public String email;

    @BlindIndex(source = "email", id = "exact", idf = Idf.HMAC_SHA512,
            normalize = Normalizer.NFC_CASEFOLD_V1, truncateBits = 15,
            projectedPopulation = 100_000)
    public byte[] emailIndex;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000003")
    public String note;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000004")
    public Integer age;

    public String status;

    public Patient() {}

    public Patient(String email, String note, Integer age) {
        this.id = UUID.randomUUID();
        this.email = email;
        this.note = note;
        this.age = age;
        this.status = "active";
    }
}
