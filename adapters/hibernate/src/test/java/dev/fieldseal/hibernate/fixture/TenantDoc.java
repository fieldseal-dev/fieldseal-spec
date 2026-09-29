package dev.fieldseal.hibernate.fixture;

import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.hibernate.BlindIndex;
import dev.fieldseal.hibernate.Encrypted;
import dev.fieldseal.hibernate.FieldsealTable;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.util.UUID;

/** Tenant-bound columns (L3, docs/29 §4): the tenant is the session's tenant identifier. */
@Entity
@FieldsealTable("018f3c2e-7a1b-7c3d-8e4f-000000000021")
public class TenantDoc {
    @Id
    public UUID id;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000022", tenantBound = true)
    public String body;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000023", tenantBound = true)
    public String handle;

    @BlindIndex(source = "handle", idf = Idf.HMAC_SHA512, normalize = Normalizer.NFC_CASEFOLD_V1,
            truncateBits = 15, projectedPopulation = 100_000)
    public byte[] handleIndex;

    public TenantDoc() {}

    public TenantDoc(String body, String handle) {
        this.id = UUID.randomUUID();
        this.body = body;
        this.handle = handle;
    }
}
