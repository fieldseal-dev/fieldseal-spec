# Research Memo — Application-Layer Encryption at the Data-Access Layer

**Status:** Draft 1 · **Date:** 2026-08-08 · **Scope:** landscape, prior art, regulatory basis, gap analysis
**Purpose:** establish, with citations, whether a language-agnostic reference architecture for transparent encryption-at-rest at the ORM layer is (a) technically distinct from existing work, (b) supported by a real regulatory driver, and (c) worth building. This memo is deliberately written to *survive an adversarial reading*. Where the case is weak, it says so.

---

## 1. Executive summary

**The idea survives scrutiny, but not in the form it is usually pitched.**

Three findings reframe the project:

1. **The gap is a *format*, not a *feature*.** Every capability people assume is missing — key rotation, per-record keys, blind indexes, per-tenant isolation, even full-text search over ciphertext — exists somewhere in shipping software. What does not exist anywhere is a **published, vendor-neutral, cross-language specification for the ciphertext of a single database cell**, with conformance test vectors. Data encrypted by Rails Active Record Encryption cannot be read by a Python analytics job, ever, without reimplementing a proprietary layout. That is the defensible, novel contribution.

2. **The compliance driver is real but narrower than the usual pitch.** SOC 2 does *not* require application-layer encryption. CIS Controls v8.1 Safeguard 3.11 explicitly states storage-layer encryption "meets the minimum requirement." Cyber-insurance underwriting asks only for laptop disk encryption. **The genuine, citable drivers are three:** PCI DSS v4.0.1 Req. 3.5.1.2 (enforceable since 31 Mar 2025, and it names disk-level encryption as *insufficient* on servers); 16 CFR 314.4(c)(3) (an unconditional GLBA mandate to encrypt customer information at rest); and 23 NYCRR 500.15 (in force since 1 Nov 2024). Plus the commercial driver: enterprise buyers demanding BYOK/CMK and per-tenant key separation, which TDE structurally cannot deliver.

3. **The commercial field is actively vacating this segment.** Skyflow, Basis Theory, and Evervault have all repositioned toward payments/agentic AI in the last ~12 months. Piiano's domain now redirects to an unrelated AI-security company. The leading open-source option, Cossack Labs' Acra, has not shipped a release since September 2024. IronCore Labs is the only vendor with transparent mid-market pricing, at ~$23k/yr entry plus per-tenant fees. There is a hole, and it is getting larger, not smaller.

**The honest counter-case,** stated up front so it is not a surprise later: application-layer encryption is genuinely expensive (Basecamp spent roughly two years of a senior engineer's time building the Rails implementation, and shipped a deterministic-encryption flaw caught by audit days before launch); it breaks a long list of database functionality; it makes the KMS a hard dependency in the read path of every query; and it provides **no protection at all** against a compromised application process. A specification that does not state these in normative language will not be taken seriously by cryptographers.

---

## 2. Prior art

### 2.1 What already exists, and what it can't do

| Option | Ecosystem | Searchable | Rotation | Per-tenant keys | The disqualifying limitation |
|---|---|---|---|---|---|
| Rails Active Record Encryption | Ruby (core) | Equality (deterministic) | Key list — **not for deterministic columns** | None | Cannot rotate the exact columns you can query |
| lockbox + blind_index | Ruby | Equality, **Argon2id** index | `Lockbox.rotate` + column dance | Manual | Ruby only; single maintainer |
| Django ecosystem | Python | pgcrypto only (in-DB) | Effectively none | None | Fragmented, stale; `django-pgcrypto` sends the key to the DB server |
| SQLAlchemy `StringEncryptedType` | Python | No | None | Callable key only | No envelope, no key ID in ciphertext |
| JPA `AttributeConverter` | Java | No | DIY | DIY | **There is no library** — it is a pattern |
| Quarkus + Vault Transit | Java | Convergent equality | Vault `rewrap` | Namespaces | No ORM integration; network round-trip per op |
| EFCore.DataEncryption | .NET | No | None | None | Raw key+IV in app; author disclaims production use |
| GORM serializers | Go | No | DIY | DIY | No built-in encryption serializer exists |
| prisma-field-encryption | TS | Equality via **salted SHA-2** | Good (multi-key + migration generator) | None | Hash is not memory-hard; silent empty results on `in:`/`contains:` |
| CipherSweet | PHP (+ lagging JS) | Blind index + Bloom truncation + compound | Documented | Manual | **Java/.NET/Rust/Python ports "coming soon" for years** |
| AWS Database Encryption SDK | Java/.NET/Rust | **Beacons** (equality, compound) | Branch-key versions | **Best-in-class** | **DynamoDB only** — despite the generic name |
| Google Tink | Java/Go/Py/C++ | AES-SIV primitive | First-class keysets | DIY | Primitives only — no field, row, column, or tenant concept |
| Vault Transit | any (HTTP) | Convergent equality | **rotate + rewrap (best design)** | Namespaces | No search, no format, network in the hot path |
| MongoDB Queryable Encryption | drivers | Eq + range GA; prefix/suffix preview | Manual DEK rotation | Per-DEK | Mongo only; new collections only; observability blackout |
| SQL Server Always Encrypted + enclaves | .NET/JDBC/ODBC | **Richest** (`=`,`<`,`BETWEEN`,`LIKE`,`JOIN`,`ORDER BY`) | In-place re-encrypt | None | SQL Server/Azure only; attestation ops burden |
| PostgreSQL | — | pgcrypto (key in SQL) | — | — | **pgsodium deprecated on Supabase; core TCE patch never landed** |
| Acra | Go proxy + SDKs | Blind index equality | **Enterprise-only** | Per-client keys | ~2 years without a release |
| IronCore Alloy / Cloaked Search | Kotlin/Java/Py/Rust | Deterministic + **full-text (phrase, fuzzy, prefix)** | Rekey tooling | **Best-in-class** | $1,954/mo + $25–35/tenant; no ORM integration |

### 2.2 Specifications that exist (and why none of them close the gap)

- **AWS Database Encryption SDK structured-encryption spec** — [aws/aws-database-encryption-sdk-dynamodb/specification/structured-encryption/](https://github.com/aws/aws-database-encryption-sdk-dynamodb/blob/main/specification/structured-encryption/header.md). This is a genuinely normative public specification using RFC 2119 language, written against generic "Structured Data," not DynamoDB types. **It is the closest prior art and should be treated as the baseline to profile or extend, not as an absence.** But: it lives in a DynamoDB-named repo, has no non-AWS implementations, assumes AWS KMS in its key-provider model, and has no change-control process open to outsiders.
- **Tink wire format** — [developers.google.com/tink/wire-format](https://developers.google.com/tink/wire-format). Implementation documentation whose stated audience is "cryptographers who want to add additional languages to Tink." No RFC 2119 conformance language, no standards body, no independent implementations. Google explicitly warns the 5-byte prefix "is not authenticated and must not be relied on for security."
- **JOSE / COSE / HPKE** — RFC 7516 (JWE) compact serialization would plausibly work as a column envelope. **No published proposal, draft, or standards work applies JWE or COSE to database field encryption.** JWE is rejected in practice on size grounds (Base64url + JSON header per cell) and has no deterministic mode. COSE's CBOR compactness would suit far better and nobody has tried.
- **NIST** — SP 800-38G Update 1 (format-preserving encryption) remains current; **Rev. 1 is at second public draft** (published 3 Feb 2025), which drops FF3 and retains only FF1. *(Note: a "Withdrawn" flag appears on the CSRC page for the original March 2016 printing — that is routine editorial supersession by Update 1, not withdrawal of the recommendation. Do not claim SP 800-38G is withdrawn.)* No NIST publication specifies a searchable-encryption or blind-index construction, or a leakage bound for one.
- **ANSI X9.119-2** — real, but payment-card-scoped and paywalled; a system-requirements standard, not an interoperable ciphertext format.
- **OWASP, OpenSSF, OASIS, CSA** — nothing in this space.

**Conclusion:** there is no published, vendor-neutral, standards-body specification for an interoperable encrypted-database-field format. That is the hole.

---

## 3. Gap analysis

Ranked by strength. Weak claims are marked as such.

### Strong

**G1. No portable ciphertext envelope for a database cell.**
Every implementation invents its own layout: Rails' `{p:, h:}` message, Tink's 5-byte prefix, AWS's `aws_dbe_head`/`aws_dbe_foot`, Fernet's version byte, CipherSweet's backend-specific framing. Cross-language reads are impossible. This blocks polyglot architectures, analytics pipelines, data migrations between stacks, and any second implementation of a first vendor's format. **This is the primary contribution.**

**G2. No independently specified blind-index construction.**
`blind_index` has the best KDF (Argon2id) but a bespoke, Ruby-only derivation. CipherSweet has the best design (per-index keys, Bloom-filter truncation, compound indexes) but is PHP-plus-a-lagging-JS-port. AWS beacons are the best-documented (with an actual tuning formula: `2 ≤ Population × 2^(−b) < √Population`) but are DynamoDB-only. **The construction itself has never been specified independently of an implementation, and no spec anywhere carries a machine-readable leakage budget.**

**G3. Rotation and searchability are mutually exclusive in the most widely deployed option.**
Rails Active Record Encryption — the most-used ORM-native encryption in the world — [cannot rotate keys on deterministic columns](https://edgeguides.rubyonrails.org/active_record_encryption.html). Every other library has rotation-without-search or search-with-a-manual-migration-dance. Acra has rotation-without-re-encryption and **paywalls it**.

**G4. Per-tenant key isolation is absent from every ORM-native library.**
Zero of eight ORM-native options (Rails, Django, SQLAlchemy, Hibernate, EF Core, GORM, Prisma, TypeORM) have any tenancy concept in their encryption layer, and their ciphertext carries no tenant or key identifier at all. Only two paid products do it credibly: AWS DB ESDK (branch key + beacon key per tenant) and IronCore SaaS Shield. **This is also the one requirement TDE structurally cannot satisfy**, and therefore the strongest commercial wedge.

**G5. PostgreSQL — plausibly the most common target database — has no viable answer.**
`pgcrypto` leaks keys into SQL text, `pg_stat_activity`, and query logs. Supabase [deprecated pgsodium and its Transparent Column Encryption](https://supabase.com/docs/guides/database/extensions/pgsodium). The PostgreSQL core client-side TCE patch reached [v20 in April 2024 targeting PG18](https://www.postgresql.org/message-id/f63fe170-cef2-4914-be00-ef9222456505@eisentraut.org) and never landed.

**G6. No published migration cost model or benchmarks.**
The pain is well-evidenced *qualitatively* (see §5) but nobody has published person-months, measured latency deltas, or a migration cost model. A rigorous benchmark suite would be a genuinely novel contribution and is cheap to produce relative to its citation value.

### Weak or already filled — do not claim these

- **Key rotation as a general concept is solved.** Vault Transit's `vault:v<n>:` prefix plus `rewrap` is clean and proven; Tink keysets solve key-ID-in-ciphertext properly. Adopt these; do not claim to invent them.
- **Rich queries over encrypted data are solved, twice, in production.** SQL Server Always Encrypted with enclaves does `LIKE`, `BETWEEN`, `JOIN`, `GROUP BY`, `ORDER BY` on *randomized* encryption. MongoDB Queryable Encryption does equality and range at GA. Both are non-portable, but "nobody can do range queries on encrypted data" is false. What is missing is a *portable, database-agnostic* version — which without a TEE is a hard cryptographic problem, not an engineering gap.
- **Full-text search over encrypted data exists.** IronCore Cloaked Search does phrase, fuzzy, prefix, and boosting. Paid and Elasticsearch-specific, but it exists.
- **A normative structured-encryption spec exists.** AWS's is well written. Profile it; do not pretend it isn't there.

---

## 4. Cryptographic design constraints

The literature imposes hard constraints. These are not preferences.

### 4.1 The threat model is narrower than the marketing

Grubbs, Ristenpart and Shmatikov ([HotOS '17](https://eprint.iacr.org/2017/468)) demolished the "snapshot attacker" model: "Logs, caches, and data structures kept by DBMS's leak information that is not accounted for in the threat models used by the designers of encrypted databases." This was confirmed empirically against a shipping product — the ETH Zurich analysis of MongoDB Queryable Encryption ([USENIX Security '23](https://www.usenix.org/system/files/usenixsecurity23-gui_1.pdf)) recovered **40–100% of field values purely from MongoDB's `queryLog` and `opLog`**, with the `opLog` attack requiring **zero client queries**.

The only defensible threat model:

| Adversary | Protection |
|---|---|
| Stolen backup / disk / replica | **Strong.** This is the real win, and it maps directly onto every breach-notification safe harbor. |
| Compromised DBA or DB operator with table read access | **Good** for randomized fields, **degraded** for indexed fields. |
| Compromised application process | **None.** The keys are in that process. |
| Persistent adversary observing queries + logs over time | **Weak.** This is where the leakage-abuse literature bites. |

A spec must disclaim rows 3 and 4 in normative language and must require query/slow-query/audit logs be treated as in-scope sensitive artifacts.

### 4.2 The nonce problem forces the key hierarchy

NIST SP 800-38D §8 requires that IV+key reuse probability be ≤2⁻³², and §8.3 caps random-nonce AES-GCM at **2³² invocations per key**. A database breaks every construction NIST allows: UPDATEs re-encrypt different plaintext at the same row identity; restored backups rewind persisted counters; autoscaled app tiers cannot guarantee unique device fixed-fields.

The resolution is structural, not procedural: **per-record derived keys** mean the 2³² ceiling never binds, because no key encrypts more than a handful of values. A spec that asks operators to *count* encryptions will fail the first time someone restores a backup.

### 4.3 Key commitment is not optional

None of AES-GCM, AES-GCM-SIV, or ChaCha20-Poly1305 is key-committing. In a multi-key field-encryption system where the ciphertext header names a key ID, this enables partitioning-oracle attacks (Len–Grubbs–Ristenpart, [USENIX Security '21](https://www.usenix.org/system/files/sec21-len.pdf)). This is not theoretical: **AWS shipped [security bulletin AWS-2025-032](https://aws.amazon.com/security/security-bulletins/AWS-2025-032/) on 17 Dec 2025** — "Key Commitment Issues in S3 Encryption Clients," CVE-2025-14759 through -14764, across six languages — remediating by "introducing the concept of 'key commitment' to S3EC where the EDK is cryptographically bound to the ciphertext." Their note: **"There are no known workarounds."**

### 4.4 Searchable encryption: what is defensible and what is broken

**Broken, with reproduced results — the spec must forbid these:**

- Deterministic encryption on low-entropy fields. Naveed–Kamara–Wright ([CCS 2015](https://cs.brown.edu/people/seny/pubs/edb.pdf)) on real hospital data: mortality risk and patient death recovered for **100% of patients in ≥99% of the 200 largest US hospitals**; disease severity 100% in ≥51%.
- Order-preserving / order-revealing encryption. Grubbs et al. ([S&P 2017](https://www.ieee-security.org/TC/SP2017/papers/433.pdf)), abstract verbatim: "attacks that recover **99% of first names, 97% of last names, and 90% of birthdates**." Against the "more secure" CLWW successor: **98% of first names and 97% of ZIP codes** (BCLO managed only 12% on ZIP codes). Their conclusion: "the security benefits of deployed schemes is quite marginal."
- Range queries. Reconstruction attacks cascade from O(N⁴ log N) (Kellaris et al. CCS '16) to O(N log N) (Lacharité–Minaud–Paterson S&P '18) to volume-leakage-only (Grubbs et al. CCS '18) to sample complexity **independent of N** (S&P '19 — "with only 50 queries, predict salaries to 2% error").

**Contested — state honestly, do not overclaim:** Kamara et al.'s [LEAKER SoK (EuroS&P '22)](https://encrypto.de/papers/KKMSTY22.pdf) re-evaluated attacks on real data and query logs and found several headline attacks far weaker than reported (IKK <15%) while SUBGRAPH was *stronger*. This does not rehabilitate OPE/ORE — whose attacks need no query observations at all — but the range-reconstruction severity under realistic workloads is actively re-litigated.

**Defensible:** equality-only, via truncated keyed indexes with (a) a distinct key per (tenant, table, column, index), (b) truncation inside the AWS collision band, (c) mandatory application-side re-verification of decrypted candidates, and (d) a per-column gate refusing to index low-cardinality domains by default.

### 4.5 Crypto-shredding: a supportable claim, but not the one vendors make

NIST SP 800-88r2 (Final, Sept 2025) classifies Cryptographic Erase as a **Purge** technique — but conditions it on: no prior plaintext on the media; all copies of the key sanitizable; all hierarchically-lower keys eliminated; and it "should not be trusted on ISM that have been backed up or escrowed."

On GDPR Art. 17, EDPB Guidelines 02/2025 (v2, July 2026) ¶51 is explicit that "encrypted personal data is still personal data" and treats key destruction as a mitigating measure conditioned on algorithm strength and key non-leakage. **No regulator has endorsed key destruction as standalone erasure.** The CJEU's *EDPS v SRB* (C-413/23 P, Sept 2025) cuts the other way on the relativity of personal data, but says nothing about a controller who still holds key backups. The honest position: *a documented technical measure that renders data unintelligible, supporting an erasure or anonymisation argument.*

**Critical corollary for the spec:** shredding a subject must destroy **both** the data key **and** every blind-index key derived for that subject — an HMAC of the value survives destruction of the encryption key.

---

## 5. What the ORMs will actually let us do

Full per-ORM detail is in the technical spec. The synthesis matters here.

**The universal capability set — everything all seven ORMs provide, and no more:**

- per-column scalar transform on write (single-row and ORM-managed multi-row insert)
- per-column scalar transform on read (entity hydration)
- a stable declaration point for "column X is encrypted"
- the ability to add an ordinary extra column that the migration tool picks up
- the ability to run **synchronous, pure** code in the value path
- errors raised in the transform abort the operation

**Not universal:** transform firing on all write paths (GORM's map-based `Updates` writes plaintext silently; Sequelize's static methods bypass setters; EF Core's `ExecuteUpdate` is partial); transform firing on WHERE parameters (SQLAlchemy/Django/EF/Hibernate/TypeORM-find-options yes, GORM/Prisma no); sibling-field access; async; query rewriting.

**Therefore the spec can mandate only:** a self-describing ciphertext envelope, a key-identification scheme carried in it, **synchronous** `encrypt`/`decrypt`/`blind_index` entry points, permissive-read and strict-read modes, and a blind-index derivation function. It **must not** mandate AAD binding to the primary key, transparent query rewriting, or async.

Two findings deserve emphasis:

- **Rails does not bind AAD.** `cipher/aes256_gcm.rb` literally sets `cipher.auth_data = ""`. The most mature implementation in existence punted on row binding because `ActiveModel::Type` has no access to the record. This is decisive evidence that AAD-to-row binding cannot be a mandatory conformance requirement for a type-decorator-shaped spec — it belongs at an optional conformance level.
- **Primary-key binding is nearly universally blocked at INSERT.** With DB-generated identity keys, the PK is `NULL` at the moment the value transform runs in Django, SQLAlchemy, EF Core, GORM, and Prisma. Only Hibernate with sequence/UUID generators has it available. **Client-generated UUIDv7 primary keys are the general solution** and should be a documented prerequisite for the row-binding conformance level.
- **TypeORM is the hard case.** `to(value: any): any` receives a bare scalar — no entity, no column metadata, no context, no async. Worse, its dirty-check runs the transform, so non-deterministic encryption makes **every `save()` mark every encrypted column dirty**. Blind indexes are not transparently implementable there; deterministic (SIV) encryption is the only sane configuration.

---

## 6. Regulatory basis

Detailed clause-level mapping is in `04-compliance-mapping.md`. The three strongest citations:

1. **PCI DSS v4.0.1 Req. 3.5.1.2** — "If **disk-level or partition-level encryption (rather than file-, column-, or field-level database encryption)** is used to render PAN unreadable, it is implemented only as follows: on removable electronic media, **OR** if used for non-removable electronic media, PAN is **also** rendered unreadable via another mechanism." The Guidance column adds: "disk-level encryption is not appropriate to protect stored PAN on computers, laptops, servers, storage arrays, or any other system that provides transparent decryption upon user authentication." Applicability Notes classify data-center media (hot-swap drives, bulk tape) as **non-removable**. This became **fully enforceable 31 March 2025**. Via **NRS 603A.215(1)**, PCI DSS is incorporated into Nevada state law for card-accepting businesses.

2. **16 CFR 314.4(c)(3) (GLBA Safeguards Rule)** — "Protect by encryption all customer information held or transmitted by you both in transit over external networks and **at rest**." A flat, non-risk-conditioned mandate; the infeasibility escape hatch requires a named Qualified Individual's written sign-off. Paired with **314.4(j)** (effective 13 May 2024, 500-consumer threshold, 30-day deadline): a "notification event" turns on acquisition of *unencrypted* information — and the definition at **16 CFR 314.2(m)** provides that customer information "is **considered** unencrypted for this purpose **if the encryption key was accessed by an unauthorized person**." FTC reports are published publicly. *(Note the citation: the encryption condition lives in the §314.2(m) definition, not in §314.4(j) itself.)*

3. **74 FR 42742–43 (HHS breach safe-harbor guidance)** — "To avoid a breach of the confidential process or key, these **decryption tools should be stored on a device or at a location separate from the data** they are used to encrypt or decrypt." This is regulatory endorsement of the exact key/data separation that full-disk and TDE approaches structurally cannot provide, and it is the gateway to the HIPAA breach-notification safe harbor at 45 CFR 164.402.

**Corrections to common assumptions — these matter:**

- **The HHS Security Rule NPRM was published 6 January 2025 (90 FR 898), not 2026, and it is NOT final.** The Unified Agenda pushed projected final action to **July 2027**; 100+ provider groups asked HHS to withdraw it. The accurate claim is "HHS has formally proposed to make encryption required, and that proposal is pending." Do not claim HIPAA requires encryption today — it is "addressable" at 45 CFR 164.312(a)(2)(iv).
- **Massachusetts 201 CMR 17.04 does NOT require encryption at rest on servers or databases.** The at-rest mandate is limited to laptops and portable devices (17.04(5)). Use MA as evidence of *affirmative* encryption regulation, and be precise.
- **NYDFS 500.15 compliance was due 1 November 2024**, not 2025. The widely-cited November 2025 date is the two-year tranche (MFA, asset inventory).
- **The HHS safe harbor still points at NIST SP 800-111**, a 2007 document titled *Guide to Storage Encryption Technologies for End User Devices*, and still says "FIPS 140-2 validated" — and **all FIPS 140-2 certificates move to the Historical List on 22 September 2026**. Flag this as a live regulatory-hygiene gap rather than leaning on it.

---

## 7. Market and demand

### 7.1 The honest demand thesis

Frameworks that do **not** force this:

- **SOC 2** is a controls report, not a prescriptive encryption standard. TDE, column-level, and application-level are all acceptable. CC6.1's points of focus are explicitly *illustrative* and conditioned on "the entity's risk mitigation strategy."
- **CIS Safeguard 3.11**, verbatim: "Storage-layer encryption, also known as server-side encryption, **meets the minimum requirement** of this Safeguard." Application-layer encryption is described as an *additional* method. *(Attribute this to the CIS **Controls Assessment Specification for Controls v8** — the text is unchanged between v8 and v8.1, but the verbatim quote comes from the Assessment Specification, not a v8.1-labeled document.)*
- **Cyber insurance.** 2026 underwriter control lists are MFA, EDR/MDR, immutable backups, email auth, segmentation, patch SLAs. The only encryption requirement found is disk encryption for laptops and portable devices.

What **does** drive it:

- The three regulatory citations in §6, which are unconditional where SOC 2 is not.
- **Enterprise security questionnaires**, where encryption appears as a deal-stalling item — specifically "are encryption keys managed by your organization, or can customers bring their own keys (BYOK)?" — but is not a consistent hard blocker like SSO or SOC 2.
- **CSA CCM v4's CEK domain** (21 controls: CEK-03 Data Encryption, CEK-08 CSC Key Management Capability, CEK-10/12/13/14 lifecycle, CEK-21 key inventory), which explicitly places burden on the cloud customer. This is the strongest framework hook, and the key-management controls are where teams actually fail.

**Reframe the pitch:** *"how to answer the BYOK/per-tenant-key question without buying a vault"* — not *"how to pass SOC 2."*

### 7.2 Evidence of the pain

The strongest primary source is Jorge Manrubia's account of building Rails Active Record Encryption at 37signals ([part 1](https://world.hey.com/jorge/a-story-of-rails-encryption-ce104b67), [part 2](https://world.hey.com/jorge/a-system-to-encrypt-data-in-bulk-for-rails-e339e213)):

- Vision Oct 2019 → first prototype Feb 2020 (**abandoned**) → rewrite May 2020 → shipped into HEY two weeks before launch → **security audit on 10 June 2020 found a deterministic-encryption flaw requiring emergency fix and data re-encryption days before launch** → upstreamed to Rails Mar 2021.
- A separate near-miss: using `Marshal` to serialize encrypted payloads created an **RCE vulnerability**, caught only while writing it up for Rails.
- Migrating **2 billion records** at Basecamp required inventing a "track encryption mode" and extending `upsert_all`.
- Roughly **two years of elapsed time with a dedicated senior engineer**, at a company with unusual engineering depth, for one framework in one language.
- Telling detail on motivation: "no customer was demanding this... no legal or operational need."

Eugene Pilyankevich (CTO, Cossack Labs) in [InfoQ](https://www.infoq.com/articles/ale-software-architects) gives the best practitioner cost analysis: "encryption is easy, key management is hard"; ALE "isn't an easy win"; hundreds-to-thousands of key requests per minute becoming a bottleneck; rotation requiring re-encryption that either disrupts availability or demands continuous background housekeeping.

### 7.3 Market size — flagged as rough

There are roughly **275,000 US firms in the 50–499 employee band across all industries** ([naics.com](https://www.naics.com/business-lists/counts-by-company-size/), a commercial aggregator, Dec 2024). Software/SaaS is plausibly low single-digit thousands of that, of which a minority (health, fintech, HR, edtech, insurtech) handle regulated consumer data. **A serviceable audience in the low thousands, not tens of thousands.**

The authoritative source — Census SUSB 2022, US & states 6-digit NAICS by enterprise employment size, for NAICS 513210 and 541511 — should be downloaded and parsed before any number goes in a public document. Do not put a fraction on "handle regulated consumer data"; no credible source exists for it. Derive it bottom-up from HIPAA-BA / PCI-merchant / state-privacy-law applicability if it is needed.

### 7.4 Statistics: what to use and what to avoid

**Use:**

- **The single best statistic for this thesis, and it is primary-sourced:** IBM 2026 found **"Only 37% of breached organizations stated that they encrypt sensitive data both at rest and in transit,"** and just **34% have visibility into cryptographic assets** ([IBM press release](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average), 29 July 2026).
- Global average breach cost **$4.99M** (+12% YoY, record high) — primary-sourced from the same release. Financial services **$6.3M**.
- ⚠️ **Secondary only — mark as such if used:** US average **$11.5M** and healthcare **$6.64M** appear in aggregator coverage (Becker's, HIPAA Journal, eSecurityPlanet) but **not** in IBM's press release or public report page; the full report is registration-gated. Retrieve the report itself before putting these figures in anything public.
- Verizon DBIR 2025 SMB Snapshot, verbatim: "In larger organizations, Ransomware is a component of **39%** of breaches, while SMBs experienced Ransomware-related breaches to the tune of **88%** overall." The strongest published SMB-vs-enterprise asymmetry available.
- HHS OCR breach portal: 2025 saw **789 breaches** of 500+ records affecting **~138.5 million individuals** — 2.1 large breaches per day; hacking/IT incidents were >80%.

**Do not use:**

- IBM 2026 publishes **no** discrete "cost saving attributable to encryption" figure. Do not invent one.
- **"60% of small businesses close within six months of a cyberattack" is false** and was traced by [Nextgov](https://www.nextgov.com/cybersecurity/2017/05/how-fake-cyber-statistic-raced-through-washington/137542/) to a 2011 Business Insider piece citing an unnamed expert the author could not later recall. The National Cyber Security Alliance disavowed it. Citing it is an easy credibility kill.
- DBIR does not report a "proportion of breaches involving stolen data at rest" cut. Do not fabricate one.

---

## 8. Recommendation

**Build it, scoped as a specification-first project with reference implementations, not as a library that happens to have docs.**

The differentiated, defensible core is:

1. A **versioned, self-describing, cross-language ciphertext envelope** for a single database cell, with a frozen cipher-suite registry (no negotiable `alg` field), authenticated header fields, key commitment, and published test vectors that any implementation can run.
2. A **specified blind-index construction** with a mandatory declared leakage budget, a memory-hard KDF for enumerable domains, per-(tenant, table, column, index) key separation, and a default-deny gate on low-cardinality columns.
3. A **conformance-level model** (L0 envelope → L4 async) that is honest about which ORMs can reach which level, because the least-common-denominator analysis proves a single uniform mandate is unimplementable.
4. **Reference implementations** in Python, TypeScript, Java, .NET, and Go that all pass the same vectors — which is the only way to prove the format claim.
5. A **published migration cost model and benchmark suite**, because that is the one thing the literature demonstrably lacks and it is cheap to produce.

**Sequence the dissemination for credibility before ambition:** an OWASP Cryptographic Storage Cheat Sheet PR (the current sheet has verified holes exactly where this work sits — no ORM guidance, no field-level specifics, no searchable-encryption coverage, no schema design guidance) costs days and reaches an enormous practitioner audience. Then IACR ePrint and arXiv for citability. Then OpenSSF Sandbox, which needs 3 maintainers across 2 organizations plus a TAC sponsor before applying. Then the USENIX Security Enigma track (~March deadline, explicitly non-academic) and OWASP Global AppSec (April–June CFP) — the only two conferences where a defensive reference architecture is a natural fit.

Full dissemination detail, including confirmed-dead venues (Strange Loop, RailsConf, standalone Enigma, LocoMocoSec) and the fact that QCon has no open CFP, is in `05-dissemination.md`.

---

## Sources

Consolidated in the individual documents. Primary research artifacts backing this memo:

**Prior art:** [Rails AR Encryption](https://edgeguides.rubyonrails.org/active_record_encryption.html) · [lockbox](https://github.com/ankane/lockbox) · [blind_index](https://github.com/ankane/blind_index) · [CipherSweet](https://ciphersweet.paragonie.com/) · [AWS DB ESDK spec](https://github.com/aws/aws-database-encryption-sdk-dynamodb/blob/main/specification/structured-encryption/header.md) · [AWS beacons](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/beacons.html) · [Tink wire format](https://developers.google.com/tink/wire-format) · [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit) · [MongoDB QE limitations](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/limitations/) · [Always Encrypted](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-database-engine) · [Acra](https://github.com/cossacklabs/acra) · [IronCore Alloy](https://github.com/IronCoreLabs/ironcore-alloy) · [prisma-field-encryption](https://github.com/47ng/prisma-field-encryption) · [Supabase pgsodium deprecation](https://supabase.com/docs/guides/database/extensions/pgsodium)

**Cryptography:** [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) · [SP 800-57 Pt.1 Rev.5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) · [SP 800-88r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf) · [NIST CSWP 39 Crypto Agility](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.39.pdf) · [NIST IR 8547 ipd](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf) · [CNSA 2.0](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF) · [Naveed–Kamara–Wright CCS'15](https://cs.brown.edu/people/seny/pubs/edb.pdf) · [Grubbs et al. S&P'17](https://www.ieee-security.org/TC/SP2017/papers/433.pdf) · [Why Your Encrypted Database Is Not Secure](https://eprint.iacr.org/2017/468) · [MongoDB QE analysis USENIX'23](https://www.usenix.org/system/files/usenixsecurity23-gui_1.pdf) · [LEAKER SoK EuroS&P'22](https://encrypto.de/papers/KKMSTY22.pdf) · [Partitioning Oracle Attacks](https://www.usenix.org/system/files/sec21-len.pdf) · [AWS-2025-032](https://aws.amazon.com/security/security-bulletins/AWS-2025-032/)

**Regulatory:** [PCI DSS v4.0.1](https://www.middlebury.edu/sites/default/files/2025-01/PCI-DSS-v4_0_1.pdf) · [16 CFR Part 314](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314) · [45 CFR 164.312](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) · [74 FR 42740](https://www.federalregister.gov/documents/2009/08/24/E9-20169/breach-notification-for-unsecured-protected-health-information) · [90 FR 898 NPRM](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information) · [23 NYCRR 500.15](https://www.law.cornell.edu/regulations/new-york/23-NYCRR-500.15) · [NRS 603A](https://www.leg.state.nv.us/NRS/NRS-603A.html) · [EDPB Guidelines 02/2025 v2](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf)

**Market:** [IBM Cost of a Data Breach](https://www.ibm.com/reports/data-breach) · [Verizon DBIR](https://www.verizon.com/business/resources/reports/dbir/) · [2025 DBIR SMB Snapshot](https://www.verizon.com/business/resources/infographics/2025-dbir-smb-snapshot.pdf) · [CIS Safeguard 3.11](https://controls-assessment-specification.readthedocs.io/en/latest/control-3/control-3.11.html) · [Rails encryption story](https://world.hey.com/jorge/a-story-of-rails-encryption-ce104b67) · [InfoQ ALE for architects](https://www.infoq.com/articles/ale-software-architects) · [Nextgov on the fake 60% statistic](https://www.nextgov.com/cybersecurity/2017/05/how-fake-cyber-statistic-raced-through-washington/137542/)
