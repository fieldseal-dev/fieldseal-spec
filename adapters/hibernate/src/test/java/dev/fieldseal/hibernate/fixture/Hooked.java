package dev.fieldseal.hibernate.fixture;

import dev.fieldseal.core.IndexDeclaration.Idf;
import dev.fieldseal.core.IndexDeclaration.Normalizer;
import dev.fieldseal.hibernate.BlindIndex;
import dev.fieldseal.hibernate.Encrypted;
import dev.fieldseal.hibernate.FieldsealTable;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import java.util.UUID;

/**
 * An entity whose {@code @PostLoad} runs whatever a test installs: application code that runs
 * on the finder's thread while the finder materializes its rows (the #238 review, finding 2).
 */
@Entity
@FieldsealTable("018f3c2e-7a1b-7c3d-8e4f-000000000051")
public class Hooked {
    /** Run on every load, on the loading thread; null means nothing. */
    public static volatile Runnable onLoad;

    @Id
    public UUID id;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000052")
    public String code;

    @BlindIndex(source = "code", idf = Idf.HMAC_SHA512, normalize = Normalizer.NFC_CASEFOLD_V1,
            truncateBits = 15, projectedPopulation = 100_000)
    public byte[] codeIndex;

    public Hooked() {}

    public Hooked(String code) {
        this.id = UUID.randomUUID();
        this.code = code;
    }

    @PostLoad
    void loaded() {
        Runnable r = onLoad;
        if (r != null) {
            r.run();
        }
    }
}
