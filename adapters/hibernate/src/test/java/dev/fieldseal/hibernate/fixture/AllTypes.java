package dev.fieldseal.hibernate.fixture;

import dev.fieldseal.hibernate.Encrypted;
import dev.fieldseal.hibernate.FieldsealTable;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;

/** One encrypted attribute per supported Java type (docs/29 §2.2), with an IDENTITY key. */
@Entity
@FieldsealTable("018f3c2e-7a1b-7c3d-8e4f-000000000041")
public class AllTypes {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000042") public String text;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000043") public byte[] blob;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000044") public Long bigCount;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000045") public int small;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000046") public Short tiny;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000047") public BigInteger huge;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000048") public BigDecimal amount;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-000000000049") public double ratio;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-00000000004a") public Boolean flag;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-00000000004b") public LocalDate born;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-00000000004c") public Instant seen;
    @Encrypted(column = "018f3c2e-7a1b-7c3d-8e4f-00000000004d") public OffsetDateTime at;
}
