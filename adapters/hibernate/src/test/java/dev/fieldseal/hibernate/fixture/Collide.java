package dev.fieldseal.hibernate.fixture;

import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.hibernate.BlindIndex;
import dev.fieldseal.hibernate.Encrypted;
import dev.fieldseal.hibernate.FieldsealTable;
import dev.fieldseal.hibernate.ReviewedOverride;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.util.UUID;

/**
 * A 4-bit index, so that two different values collide often enough to find by brute force: the
 * re-verification fixture (spec §7.5). b = 4 needs 32 <= P < 256 (spec §7.4), which is under
 * spec §7.6's gate, hence the override.
 */
@Entity
@FieldsealTable("018f3c2e-7a1b-7c3d-8e4f-000000000031")
public class Collide {
    @Id
    public UUID id;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000032")
    public String code;

    @BlindIndex(source = "code", idf = Idf.HMAC_SHA512, normalize = Normalizer.NFC_CASEFOLD_V1,
            truncateBits = 4, projectedPopulation = 100,
            cardinalityOverride = @ReviewedOverride(reason = "collision fixture",
                    approvedBy = "fixture", date = "2026-09-29"))
    public byte[] codeIndex;

    public String kind;

    public Collide() {}

    public Collide(String code, String kind) {
        this.id = UUID.randomUUID();
        this.code = code;
        this.kind = kind;
    }
}
