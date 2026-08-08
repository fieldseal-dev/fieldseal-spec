# Verification Log

**Date:** 2026-08-08 · **Method:** independent re-verification of the 20 highest-risk factual claims against primary sources (eCFR, Federal Register, NIST CSRC, PCI SSC, IEEE/ACM proceedings, vendor advisories, project source code). Claims were selected on the basis of "most damaging if wrong."

## Corrections applied

| # | Claim as originally written | Correct statement | Applied to |
|---|---|---|---|
| 1 | "NIST SP 800-38G is **withdrawn**" | **Not withdrawn.** SP 800-38G Update 1 (March 2016) remains the current, active recommendation. The "Withdrawn on August 04, 2016" flag on CSRC applies only to the superseded original 29 March 2016 printing — routine editorial supersession by Update 1. Rev. 1 is at second public draft (3 Feb 2025), dropping FF3 and retaining only FF1. | Research memo §2.2; spec §4.7 |
| 2 | Grubbs et al. S&P 2017: "birthdates **91%**" and "98%/97% against CLWW" | Abstract verbatim: "99% of first names, 97% of last names, and **90%** of birthdates." The CLWW figures are **98% first names / 97% ZIP codes** — different attributes, not first/last names. BCLO managed only 12% on ZIP codes. | Research memo §4.4; spec §4.7; README |
| 3 | "16 CFR **314.4(j)**… information is **deemed** unencrypted if the encryption key was accessed" | The 500-consumer threshold and 30-day deadline are in §314.4(j)(1), but the encryption condition is in the definition at **16 CFR 314.2(m)**, and the verb is "**considered**," not "deemed." | Research memo §6; compliance mapping §4, §9 |
| 4 | AWS-2025-032: "No workarounds exist." | Verbatim: "**There are no known workarounds.**" Bulletin is "Key Commitment Issues in S3 Encryption Clients," CVE-2025-14759 through -14764. | Research memo §4.3; spec §4.6; README |
| 5 | "CIS Controls **v8.1** Safeguard 3.11" | Text is unchanged between v8 and v8.1, but the verbatim quote comes from the **CIS Controls Assessment Specification for Controls v8**, not a v8.1-labeled document. Attribute accordingly. | Research memo §7.1; compliance mapping §1, §6 |
| 6 | IBM 2026 US average $11.5M, healthcare $6.64M stated as primary | **Not in IBM's press release or public report page**; secondary aggregators only (Becker's, HIPAA Journal, eSecurityPlanet). The full report is registration-gated. Downgraded to flagged-secondary. | Research memo §7.4; compliance mapping §7, §8 |
| 7 | FIPS 140-2 → Historical List, 22 September 2026 | Date confirmed from the transition timeline table, **but NIST's own page is internally inconsistent by one day** — the prose says modules remain active "until September 21, 2026." Cite the table; expect a challenge. | Compliance mapping §6 |

## Verified without change

| Claim | Source |
|---|---|
| PCI DSS v4.0.1 Req. 3.5.1.2 — the "disk-level or partition-level (rather than file-, column-, or field-level database encryption)" language, the transparent-decryption Guidance sentence, the hot-swap/bulk-tape non-removable classification, and required-since-31-March-2025 | [PCI DSS v4.0.1 PDF](https://www.middlebury.edu/sites/default/files/2025-01/PCI-DSS-v4_0_1.pdf), pp. 93–94 |
| 16 CFR 314.4(c)(3) exact text | [eCFR](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314/section-314.4) |
| HHS safe harbor, "decryption tools should be stored on a device or at a location separate from the data" | [74 FR 42740](https://www.federalregister.gov/documents/2009/08/24/E9-20169/breach-notification-for-unsecured-protected-health-information), printed page **42742** |
| HIPAA NPRM: 6 Jan 2025, 90 FR 898, RIN 0945-AA22, comments closed 7 Mar 2025, **not finalized**, Unified Agenda Long-Term Actions with Final Action **07/00/2027** | [reginfo.gov](https://www.reginfo.gov/public/do/eAgendaViewRule?pubId=202510&RIN=0945-AA22) |
| 23 NYCRR 500.15 in the **one-year** bucket under §500.22(d)(2) → due **1 Nov 2024**; two-year bucket (d)(4) is 500.12 and 500.13(a) only | [NYDFS Second Amendment text](https://www.dfs.ny.gov/system/files/documents/2023/10/rf_fs_2amend23NYCRR500_text_20231101.pdf) |
| NIST SP 800-88 Rev. 2 final September 2025; Cryptographic Erase classified as a Purge technique | [SP 800-88r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf) |
| AWS Database Encryption SDK supports **DynamoDB only**; normative structured-encryption spec exists with RFC 2119 language, written against generic "Structured Data" | [AWS docs](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/what-is-database-encryption-sdk.html) · [spec](https://github.com/aws/aws-database-encryption-sdk-dynamodb/blob/main/specification/structured-encryption/header.md) |
| Rails: "Rotating keys is not supported for deterministic encryption"; `cipher.auth_data = ""` in `decrypt`, and `encrypt` never sets `auth_data` at all | [Rails guides](https://edgeguides.rubyonrails.org/active_record_encryption.html) · [aes256_gcm.rb](https://github.com/rails/rails/blob/main/activerecord/lib/active_record/encryption/cipher/aes256_gcm.rb) |
| RailsConf ended after 2025 (Philadelphia, 8–10 Jul); Strange Loop's final edition was 2023 | [railsconf.org](https://railsconf.org/) · [thestrangeloop.com](https://thestrangeloop.com/) |
| Naveed–Kamara–Wright: mortality risk and patient death for 100% of patients in ≥99% of the 200 largest hospitals; disease severity 100% in ≥51% | [CCS 2015 PDF](https://cs.brown.edu/people/seny/pubs/edb.pdf) |
| CIS Safeguard 3.11 "storage-layer encryption… meets the minimum requirement" | [CIS Assessment Specification](https://controls-assessment-specification.readthedocs.io/en/latest/control-3/control-3.11.html) |
| The "60% of small businesses close within six months" statistic is fabricated; NCSA's Executive Director disavowed it and recommended against its use; traced to a Sept 2011 Business Insider piece whose author could not identify his source five years later | [Nextgov](https://www.nextgov.com/cybersecurity/2017/05/how-fake-cyber-statistic-raced-through-washington/137542/) |
| SP 800-38D §8 (2⁻³² IV-collision probability) and §8.3 (2³² invocation limit) exact text | [SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) |
| IBM 2026: "Only 37% of breached organizations stated that they encrypt sensitive data both at rest and in transit"; 34% cryptographic-asset visibility; global average $4.99M | [IBM press release](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average) |
| Verizon DBIR 2025 SMB Snapshot: ransomware in 39% of large-org breaches vs **88%** of SMB breaches | [2025 SMB Snapshot](https://www.verizon.com/business/resources/infographics/2025-dbir-smb-snapshot.pdf) |

## Still unverified — carried forward

Tracked in `03-compliance-mapping.md` §8. Highest priority to close before anything is published:

1. Number of US states with an explicit encryption safe harbor (assert the pattern, not a number).
2. Texas Bus. & Com. Code § 521.053's encrypted-data-plus-key clause (secondary source only).
3. HITRUST encryption-at-rest control IDs (catalog paywalled).
4. IBM 2026 US and healthcare figures (registration-gated report).
5. US SaaS firm counts by employee band — download Census SUSB 2022 6-digit NAICS directly for 513210 and 541511 rather than citing an aggregator.

## Second pass — internal consistency review (2026-08-08)

A separate review of the documents *against each other and against their own normative claims* (distinct from the source-verification pass above) found six substantive defects. All are fixed; recorded here because several were security-relevant.

| # | Defect | Fix |
|---|---|---|
| 1 | **The "per-record derived keys make the 2³² ceiling unreachable" claim was false under the spec's own defaults.** With `row_id` off by default (§6.4), the KDF context collapsed to (tenant, table, column) — one derived key per tenant-column, so the SP 800-38D §8.3 invocation limit still bound, contradicting §4.4's own "counting will fail on backup restore" argument. | Added a random 32-byte per-write derivation seed (`msg_seed`) to the envelope, feeding the KDF salt — the AWS Encryption SDK v2 message-ID pattern. Every derived key is now single-use regardless of `row_id` configuration. Spec §3.1, §4.4, §5.3. |
| 2 | **Index keys were derived from the tenant DEK (§7.2 `ikm = tenant_dek`), silently reintroducing gap G3** — the rotation-invalidates-searchability trap the memo documents in Rails. Any data-key rotation would have broken every blind index. | Tenant index key is now a distinct sibling key under the KEK, never derived from the DEK. Data-key rotation leaves indexes valid; index-key rotation is an explicit rebuild; crypto-shredding must destroy both. Spec §5.1, §5.2, §5.8, §7.2, §8. |
| 3 | **Envelope arithmetic omitted the mandatory 32-byte commitment.** §3.3 computed a 9-byte SSN at 56 bytes while §4.2 makes the commitment REQUIRED for both registered suites. | Recomputed honestly with seed and commitment: 120 B binary / 160 B base64 (13.3×/17.8×); fixed per-field overhead 111 B; the 20-col × 100M-row example is ~220 GB, not ~110 GB. Spec §3.3, README. |
| 4 | **`canonical_context` was ill-defined.** It referenced envelope fields (`fmt_ver`, `key_id`) absent from `FieldContext` and nonexistent for index derivation, and carried no per-index identifier — two indexes on one column would have derived the *same* key, violating §7.2's own distinctness rule. | Split the encoding: `canonical_context` covers only `FieldContext` fields; AAD = envelope fields + context. `purpose` now carries an index identifier (`index:exact`, `index:prefix3`). Spec §6.1–§6.3, §7.2. |
| 5 | **Conformance level L2 path (a) presumed a deterministic suite the registry does not contain.** "The ORM converts WHERE parameters through the type layer" can never match randomized ciphertext — the path was incoherent as written, and the TypeORM guidance ("default to a deterministic configuration") recommended a configuration that does not exist in the spec. | L2 redefined as blind-index-based with two mechanisms: (a) explicit index-typed property, (b) transparent rewrite. Matrix corrected: TypeORM ❌→⚠️ (a) only, and ⚠️ tenant-via-CLS at L3; Hibernate (b) removed (no comparator hook); EF/Django gain (a). TypeORM carve-out now documents spurious re-encryption on every `save()` instead. New open question §13.6 (deterministic AES-SIV suite). Spec §10, §10.1, §10.2, §13.6; PRD AD-5; ORM notes §2, §4. |
| 6 | **`is_ciphertext` tied recognition to the decrypt allow-list.** A retired suite's ciphertext would be misclassified as unmigrated plaintext in `permissive` mode — returned as application data and double-encrypted on the next write. | Recognition (registered suites) decoupled from authorization (allow-list → `SUITE_NOT_ALLOWED`). Spec §3.4. |

Minor: Django lookup-path note softened (`get_prep_value` runs earlier via `Lookup.get_prep_lookup`; it is not skipped outright — ORM notes §1); memo's WHERE-parameter list now includes TypeORM find-options; NPRM comment count flagged as secondary; SQLAlchemy "deterministic filters with zero rewriting" claim annotated as inapplicable under a randomized-only registry.

## Standing rule

Re-run this verification before any public release of any document in this repository. Regulatory citations, NIST publication statuses, and vendor advisories all move; several of the items above changed within the last twelve months.
