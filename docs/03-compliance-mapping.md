# Compliance Mapping

**Date:** 2026-08-08 · **Status:** Draft 1 · **Verification:** clause numbers below were read from primary sources (eCFR, Federal Register full text, the PCI DSS v4.0.1 PDF, NIST CSRC, AICPA TSC) except where explicitly flagged as secondary.

> **How to read this document.** §1 states what these frameworks do **not** require, because overclaiming here is the fastest way to lose a sophisticated reader. §2–§6 are the clause-level mapping. §7 is the supporting evidence base. §8 lists what could not be verified.

---

## 1. What these frameworks do NOT require

Read this first.

| Framework | The honest position |
|---|---|
| **SOC 2** | A controls report, not a prescriptive encryption standard. CC6.1's encryption points of focus are **illustrative, not mandatory**, and are conditioned on "the entity's risk mitigation strategy." TDE, column-level, and application-level encryption are all acceptable. **SOC 2 cannot be cited as requiring encryption at rest.** Its real value here is commercial — customer questionnaires — not regulatory. |
| **CIS Safeguard 3.11** | Verbatim: "Encrypt sensitive data at rest… **Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this Safeguard.**" Application-layer encryption is described as an *additional* method. CIS explicitly says the cheap option is sufficient. ⚠️ Attribute to the **CIS Controls Assessment Specification for Controls v8** — the text is unchanged between v8 and v8.1, but the verbatim quote is from the Assessment Specification, not a v8.1-labeled document. |
| **Cyber insurance** | 2026 underwriter control lists are dominated by MFA, EDR/MDR, immutable backups, email authentication, segmentation, and patch SLAs. The only encryption requirement found is **disk encryption for laptops and portable devices**. No application-layer or field-level requirement appears in any underwriting list reviewed. **Do not cite insurance as a driver.** |
| **HIPAA (current)** | Encryption is **addressable**, not required — 45 CFR 164.312(a)(2)(iv). The proposed rule that would change this is *not final*; see §2. |
| **Massachusetts 201 CMR 17** | Requires encryption in transit and on **laptops and portable devices**. It does **not** require encryption at rest on servers or databases. Anyone claiming otherwise is overstating it. |
| **NY SHIELD Act § 899-bb** | A "reasonable safeguards" duty. It does **not** expressly mandate encryption. Cite it as a duty into which encryption fits, not as a mandate. |
| **Enterprise questionnaires** | Encryption appears as a deal-stalling item, phrased as "What encryption standards do you use for data at rest and in transit? Are encryption keys managed by your organization, or can customers bring their own keys (BYOK)?" — but it is **not** a consistent hard blocker in the way SSO and SOC 2 are. |

**What this means for positioning.** The genuine forcing functions are the three unconditional mandates in §3–§5, and the commercial demand for **BYOK/CMK and per-tenant key separation** — the one requirement TDE structurally cannot satisfy, because TDE keys are per-database, not per-tenant.

---

## 2. HIPAA / HITECH

| Citation | Requirement (short quote) | What the architecture must do | Caveat |
|---|---|---|---|
| **45 CFR 164.312(a)(2)(iv)** | "Encryption and decryption **(Addressable)**. Implement a mechanism to encrypt and decrypt electronic protected health information." | Per-field encrypt/decrypt bound to the access-control standard at 164.312(a)(1) — decryption gated by the authorization decision, not by disk mount. | "Addressable" ≠ optional but ≠ mandatory. |
| **45 CFR 164.306(d)(1)–(3)** | (d)(3)(ii): "Implement the implementation specification if reasonable and appropriate; or… Document why it would not be reasonable and appropriate… and implement an equivalent alternative measure." | The architecture is the "reasonable and appropriate" answer, discharging (d)(3)(ii)(A) and eliminating the documentation burden of (B). | OCR's own NPRM preamble says regulated entities **misread "addressable" as "optional."** |
| **45 CFR 164.402** ("unsecured PHI") | "…protected health information that is **not rendered unusable, unreadable, or indecipherable** to unauthorized persons through a technology or methodology specified by the Secretary…" | Ciphertext at rest meeting HHS guidance ⇒ PHI is "secured" ⇒ **no breach notification duty at all**, bypassing the four-factor risk assessment. | **The safe harbor is lost if the key is compromised.** Key custody is the whole ballgame. |
| **74 FR 42740, at 42742–43** (HHS safe-harbor guidance) | Encryption = "an algorithmic process to transform data into a form in which there is a low probability of assigning meaning **without use of a confidential process or key**"… "Valid encryption processes for data **at rest** are consistent with **NIST Special Publication 800-111**"… "or others which are **FIPS 140-2 validated**." | Use a validated module; document mapping to SP 800-111. | **Two live weaknesses in the authority itself.** (a) SP 800-111 (2007) is titled *Guide to Storage Encryption Technologies for End User Devices* — a poor fit for server-side encryption, and HHS has never updated the pointer. (b) It says **FIPS 140-2**, and **all FIPS 140-2 certificates move to the CMVP Historical List on 22 September 2026**. Flag this; do not lean on it. |
| **74 FR at 42742–43** | "To avoid a breach of the confidential process or key, these **decryption tools should be stored on a device or at a location separate from the data** they are used to encrypt or decrypt." | **The single most architecturally load-bearing sentence in the HIPAA corpus for this design.** Explicit regulatory endorsement of key/data separation — which full-disk and TDE structurally cannot deliver. | Phrased "should," not "shall." Guidance, not regulation. |

### 2.1 The proposed Security Rule overhaul — status, corrected

**The NPRM was published 6 January 2025 (90 FR 898, RIN 0945-AA22). It is NOT final.**

- Comment period closed 7 March 2025; roughly 4,000–5,000 comments received *(figure via secondary sources — Clark Hill, HIPAA Journal)*.
- The Unified Agenda (edition 202510) pushed projected final action from May 2026 to **July 2027**.
- 100+ provider groups have asked HHS to withdraw it.

Proposed **45 CFR 164.312(b)(2)**, verbatim from the Federal Register: "**Encrypt all electronic protected health information at rest and in transit**, except to the extent that an exception at paragraph (b)(3) of this section applies." Proposed (b)(1): "Deploy technical controls to encrypt and decrypt [ePHI] using encryption that **meets prevailing cryptographic standards**." Exceptions at proposed (b)(3)(i)–(iv) cover technology assets that cannot support it (with a written migration plan), individual requests under §164.524, emergency/contingency operations, and certain FDA-authorized devices.

**Accurate claim:** *HHS has formally proposed to make encryption required, and that proposal is pending.* Design to it — it is where the puck is going — but do not state that HIPAA requires encryption today.

---

## 3. PCI DSS v4.0.1 — the strongest citation

**Version status:** v4.0.1 published 11 June 2024; **v4.0 retired 31 December 2024**; v4.0.1 is the only active version. Of 64 new requirements in v4.x, **51 were future-dated and became effective 31 March 2025**.

| Citation | Requirement (short quote) | What the architecture must do | Caveat |
|---|---|---|---|
| **Req. 3.5.1** | "PAN is rendered unreadable anywhere it is stored by using any of the following: one-way hashes… truncation… index tokens… **strong cryptography with associated key-management processes and procedures.**" | Field-level encryption satisfies bullet 4. Applicability Notes extend this to "**non-primary storage (backup, audit logs, exception, or troubleshooting logs)**" — paths a DB-level control misses. | Also satisfiable by tokenization. Here the competitor is tokenization vendors, not disk encryption. |
| **Req. 3.5.1.2** *(future-dated; required since **31 March 2025**)* | "If **disk-level or partition-level encryption (rather than file-, column-, or field-level database encryption)** is used to render PAN unreadable, it is implemented only as follows: on removable electronic media, **OR** if used for non-removable electronic media, PAN is **also rendered unreadable via another mechanism** that meets Requirement 3.5.1." | **The single strongest citation in the entire corpus.** PCI names file-/column-/field-level encryption as the contrasting acceptable category and disqualifies disk encryption as a sole control on servers. | Verified: the Applicability Notes contain "best practice until 31 March 2025, after which it will be required." **That date has passed.** |
| **Req. 3.5.1.2, Guidance** | "Disk-level and partition-level encryption typically encrypts the entire disk or partition **using the same key**, with all data automatically decrypted when the system runs… For this reason, **disk-level encryption is not appropriate to protect stored PAN on computers, laptops, servers, storage arrays, or any other system that provides transparent decryption upon user authentication**." | Quote verbatim. This is PCI explicitly rejecting the "we use encrypted EBS / we have TDE" posture. | The Guidance column is non-normative — but the Applicability Notes (normative) say the same thing. |
| **Req. 3.5.1.2, Applicability Notes** | "This requirement applies to **any encryption method that provides clear-text PAN automatically when a system runs**, even though an authorized user has not specifically requested that data… **Media that is part of a data center architecture (for example, hot-swappable drives, bulk tape-backups) is considered non-removable electronic media**…" | Cloud block storage and managed-database volumes fall on the non-removable side. TDE is squarely the target of "transparent decryption upon user authentication." | Issuer carve-out: does not apply to PANs accessed for real-time transaction processing, but does apply to PANs stored for other purposes. |
| **Req. 3.5.1.1** *(required since 31 March 2025)* | "Hashes used to render PAN unreadable… are **keyed cryptographic hashes of the entire PAN**, with associated key-management processes and procedures in accordance with Requirements 3.6 and 3.7." | If blind indexes are offered, they **must be keyed**, and the index key must be managed under 3.6/3.7. | **Unkeyed SHA-256 of a PAN is no longer compliant.** This directly invalidates naive "hash for lookup" designs — including `prisma-field-encryption`'s salted-SHA-2 approach for card data. |
| **Req. 3.6.1** | "Access to keys is restricted to the **fewest number of custodians**… **Key-encrypting keys are at least as strong as the data-encrypting keys** they protect… **Key-encrypting keys are stored separately from data-encrypting keys**… Keys are stored securely in the **fewest possible locations and forms**." | Mandates a two-tier KEK/DEK hierarchy with separation — exactly the envelope pattern in spec §5. | — |
| **Req. 3.6.1.2** | "Secret and private keys… are stored in one (or more) of the following forms at all times: **encrypted with a key-encrypting key** that is at least as strong… and **stored separately**; **within a secure cryptographic device (SCD)** such as an HSM; or as at least **two full-length key components**." | DEKs must never be at rest in plaintext. Wrap with a KMS/HSM-held KEK in a different trust domain. | — |
| **Req. 3.6.1.3 / 3.6.1.4** | Access to cleartext key components restricted to fewest custodians; keys stored in the fewest possible locations. | Argues against distributing key material to every application node; favors central unwrap plus a bounded local cache. | Direct tension with the availability argument in spec §8.1. Document the trade-off. |
| **Req. 3.7.1 / 3.7.2 / 3.7.3** | Generation of strong keys; secure distribution; secure storage. | Full lifecycle documented and implemented, not just the encrypt call. | — |
| **Req. 3.7.4** | "…key changes for keys that have **reached the end of their cryptoperiod**… including: **a defined cryptoperiod for each key type in use**; a process for key changes at the end of the defined cryptoperiod." | Key versioning and re-encryption without downtime — a schema/ORM concern, not an infrastructure one. Cite SP 800-57 Pt.1 Rev.5 as the "industry best practices" source. | **PCI deliberately does not name a fixed rotation interval.** The "annual rotation" folklore is not in v4.x. Do not claim it is. |
| **Req. 3.7.5** | "…**retirement, replacement, or destruction of keys**… when: the key has reached the end of its cryptoperiod; the **integrity of the key has been weakened**, including when personnel with knowledge of a cleartext key component **leaves the company**…" | Crypto-shredding / key destruction at record or tenant granularity. | — |
| **Req. 3.7.6** | "Where **manual cleartext cryptographic key-management operations are performed by personnel**… managing these operations using **split knowledge and dual control**." | **Important nuance:** the Applicability Notes state this "is applicable for **manual** key-management operations." An architecture where keys are generated inside and never leave an HSM/KMS makes 3.7.6 **not applicable**. | That is a *stronger* position than "we help you comply with 3.7.6." Do not overclaim that the architecture *satisfies* it — it avoids triggering it. |

---

## 4. GLBA Safeguards Rule (16 CFR Part 314)

| Citation | Requirement (short quote) | What the architecture must do | Caveat |
|---|---|---|---|
| **16 CFR 314.4(c)(3)** | "**Protect by encryption all customer information held or transmitted by you both in transit over external networks and at rest.** To the extent you determine that encryption… is infeasible, you may instead secure such customer information using **effective alternative compensating controls reviewed and approved by your Qualified Individual**." | **A flat, non-risk-conditioned mandate** — arguably the most unambiguous encryption-at-rest requirement in US federal law applicable to private companies. No "addressable," no "reasonable and appropriate" qualifier on the duty. | The infeasibility escape hatch exists but requires a named individual to put their name on it — a recurring governance cost, which is itself part of the argument. |
| **16 CFR 314.2(h)** | "financial institution" = "any institution the business of which is engaging in an activity that is **financial in nature or incidental to such financial activities**…" | The 2021 amendments swept in "finders" and many non-bank entities. Mid-size SaaS doing lending, payments facilitation, financial data aggregation, mortgage/auto/tax services — or serving such firms — is commonly in scope. | **Do not assert blanket SaaS coverage.** Whether a given SaaS is a "financial institution" or a "service provider" under 314.4(f) is fact-specific. Assert that many mid-market SaaS firms are covered directly, and nearly all serving this vertical are bound contractually. |
| **16 CFR 314.4(a), (b)** | Designate a **Qualified Individual**; base the program on a **written risk assessment**. | Supply artifacts — threat model, key-custody model, data-classification gate — that drop directly into the written risk assessment. | — |
| **16 CFR 314.4(f)** | Select providers capable of maintaining safeguards; require safeguards **by contract**; periodically assess. | **The flow-down mechanism.** A covered client will contractually demand 314.4(c)(3)-grade encryption from its SaaS vendors. This is how the requirement reaches companies not directly covered. | — |
| **16 CFR 314.4(j)(1)** *(effective 13 May 2024)* | "Upon discovery of a **notification event**… if the notification event involves the information of **at least 500 consumers**, you must notify the Federal Trade Commission **as soon as possible, and no later than 30 days after discovery**." | A "notification event" is acquisition of **unencrypted** customer information. | **FTC reports are published on a public database.** Reputational as well as legal exposure. The rule presumes unauthorized acquisition occurred absent "reliable evidence" to the contrary. |
| **16 CFR 314.2(m)** | "Customer information is **considered** unencrypted for this purpose **if the encryption key was accessed by an unauthorized person**." | **The encryption hook.** Encryption with keys held in a separate trust boundary ⇒ no FTC filing. | ⚠️ **Cite this clause, not §314.4(j), for the encryption condition** — it lives in the definition, and the verb is "considered," not "deemed." Getting this wrong in front of counsel is avoidable. |

---

## 5. State law

**Coverage.** All 50 states plus DC have breach-notification statutes. The near-universal pattern is that the statutory definition of "personal information" or "breach" is limited to **unencrypted** data, which functions as a safe harbor — **but no authoritative published count of how many statutes contain an explicit encryption safe harbor was obtained.** Assert the pattern; do not assert a number.

| Citation | Requirement (short quote) | Relevance | Caveat |
|---|---|---|---|
| **Cal. Civ. Code § 1798.82(a), (g), (h)** | Breach = "**unauthorized acquisition of computerized data that compromises the security, confidentiality, or integrity of personal information**." Safe harbor operates through (h): encrypted PI triggers notice only where "**the encryption key or security credential was, or is reasonably believed to have been, acquired by an unauthorized person**." | Keys must live in a separate trust boundary so a database or host compromise is not key acquisition. | **California has no blanket exemption for encrypted data.** It is conditioned on key/credential integrity. Companion: § 1798.81.5 (reasonable security procedures); § 1798.29 mirrors for agencies. |
| **N.Y. Gen. Bus. Law § 899-aa(1)(b), (1)(c)** | "private information" = personal information plus a listed element "**when either the data element or the combination… is not encrypted, or is encrypted with an encryption key that has also been accessed or acquired**." | Same key-separation conclusion. NY also reaches unauthorized **access**, not just acquisition — a lower trigger than California. | — |
| **NRS 603A.215(1)** (Nevada) | "If a data collector doing business in this State **accepts a payment card**… the data collector shall **comply with the current version of the Payment Card Industry (PCI) Data Security Standard**." | **Nevada statutorily incorporates PCI DSS — meaning PCI Req. 3.5.1.2 is state law in Nevada for any card-accepting business.** A genuinely strong and underused hook. | "Current version" ⇒ v4.0.1 as of August 2026. |
| **NRS 603A.215(5)(b)** | Encryption requires (1) "an encryption technology that has been adopted by an established standards setting body, including… **FIPS**… which renders such data indecipherable in the absence of associated cryptographic keys"; **(2) "appropriate management and safeguards of cryptographic keys**… using guidelines promulgated by an established standards setting body, including… NIST." | **The clearest statutory statement anywhere that key management is part of the definition of encryption.** A ciphertext without disciplined key management is legally *not encrypted* in Nevada. Pair with NIST SP 800-57. | — |
| **NRS 603A.215(2)(a), (2)(b)** | Shall not transfer PI "through an electronic, nonvoice transmission… outside of the secure system of the data collector **unless the data collector uses encryption**"; shall not move a storage device containing PI "**beyond the logical or physical controls** of the data collector… unless… encryption." | "Beyond the **logical**… controls" arguably reaches cloud storage handoffs, not merely physical media transport. | Applies to data collectors to whom subsection 1 does not apply. |
| **201 CMR 17.04(3), (5)** (Massachusetts) | (3) "Encryption of all transmitted records… that will travel across public networks," and wirelessly. (5) "Encryption of all personal information stored on **laptops or other portable devices**." | Use MA as evidence of *affirmative* (not merely safe-harbor) encryption regulation. | **201 CMR 17.04 does NOT require encryption at rest on servers or databases.** Be precise. |
| **201 CMR 17.02** ("Encrypted") | "the **transformation of data into a form in which meaning cannot be assigned without the use of a confidential process or key**." | Algorithm-neutral and key-centric; the 2010 amendment deliberately removed a bit-length floor. | Because it is key-centric, key compromise defeats "Encrypted" status. |
| **201 CMR 17.03(1)** | Duty to maintain a comprehensive **written** information security program; applies to anyone who "**receives, stores, maintains, processes, or otherwise has access to**" PI of a MA resident. | "Otherwise has access to" pulls in processors and SaaS directly, not just controllers. | — |
| **Tex. Bus. & Com. Code § 521.053(a), (b), (i)** | Disclose "without unreasonable delay and… **not later than the 60th day**"; notify the Texas AG if **≥250 Texas residents** affected, within 30 days. | Encrypted data still constitutes a breach if the unauthorized person obtained the decryption keys. | ⚠️ **Secondary source (FindLaw).** The (a)/(b)/(i) figures are reliable; the verbatim "encrypted… if the person accessing the data has the key" clause was **not** obtained from a primary source. Verify before quoting it exactly. |
| **23 NYCRR § 500.15(a)** (NYDFS) | "Each covered entity shall implement a **written policy requiring encryption that meets industry standards, to protect nonpublic information held or transmitted** by the covered entity **both in transit over external networks and at rest**." | Like GLBA 314.4(c)(3), an unconditional at-rest mandate. | Applies to NYDFS-licensed entities; reaches SaaS mainly via third-party service provider obligations (§ 500.11). |
| **23 NYCRR § 500.15(b)** | Where encryption at rest is infeasible, compensating controls may be used, **reviewed and approved in writing by the CISO**, with feasibility and effectiveness **reviewed at least annually**. | A recurring annual cost of *not* encrypting — a concrete TCO argument. | The Second Amendment removed the ability to use compensating controls for data in transit. |
| **23 NYCRR § 500.22** | Transitional periods: § 500.15 fell in the **one-year** bucket. | **Compliance was due 1 November 2024. It is fully in force today.** | **The widely-cited "1 November 2025" date is the two-year tranche (§ 500.12 MFA, § 500.13(a) asset inventory) — not encryption. Do not conflate them.** |

---

## 6. Standards referenced by regulators

| Standard | Relevance | Caveat |
|---|---|---|
| **NIST SP 800-57 Pt.1 Rev.5** (May 2020) | The normative reference behind PCI 3.7.4's "industry best practices," NYDFS "industry standards," and Nevada's "guidelines promulgated by an established standards setting body." | Current; supersedes Rev. 4. No Rev. 6 announced as of Aug 2026. |
| **NIST SP 800-38D** (Nov 2007) | §8 IV uniqueness and §8.3 invocation limits are the hard engineering constraint most hand-rolled designs get wrong. **This constraint is itself an argument for a designed framework over ad-hoc `encrypt()` calls.** | Under active revision; second pre-draft comment period closed 31 July 2026. |
| **NIST SP 800-111** (Nov 2007) | Cited because HHS cites it. | **The weakest link in the chain.** Nineteen years old and scoped to *end-user devices*, not servers or databases. Flag this honestly. |
| **NIST SP 800-175B Rev.1** (Mar 2020) | Algorithm and mechanism selection justification. | Federal-scoped; persuasive, not binding for the private sector. |
| **FIPS 140-3 / CMVP** | "FIPS-validated module" means a specific *module* — a named software/firmware/hardware boundary at a specific version — holds a CMVP certificate. Using it in a non-approved configuration, or patching it, voids the validation. **It is a property of the build, not the algorithm.** Architecturally this argues for delegating primitives to a validated module rather than embedding your own. | **Time-sensitive: all FIPS 140-2 certificates move to the Historical List on 22 September 2026**, leaving HHS's 2009 "FIPS 140-2 validated" safe-harbor language dangling. ⚠️ NIST's own transition page is internally inconsistent by one day — the timeline table says 22 September 2026 while the prose says modules remain active "until September 21, 2026." Cite the table date and expect the discrepancy to be raised. |
| **AICPA SOC 2 TSC, CC6.1** | Two relevant points of focus: "**Uses Encryption to Protect Data**… (at rest, during processing, or in transmission), **when such protections are deemed appropriate** based on the entity's risk mitigation strategy"; and "**Protects Cryptographic Keys** — during generation, storage, use, and destruction. **Cryptographic modules, algorithms, key lengths, and architectures are appropriate**…" Both map cleanly onto a DEK/KEK architecture, and auditors ask for both. | Points of focus are illustrative, not mandatory, and both are risk-conditioned. See §1. |
| **CSA CCM v4, CEK domain** | 21 controls: CEK-03 Data Encryption, CEK-04 Encryption Algorithm, CEK-08 CSC Key Management Capability, CEK-10/12/13/14 generation/rotation/revocation/destruction, CEK-21 key inventory. The framework explicitly places burden on the cloud customer: "CSCs take responsibility for encrypting their own sensitive data before uploading it to the cloud." | **The strongest framework hook available**, and the key-management controls (8, 10, 12, 21) are where teams actually fail. Reaches enterprise procurement via CAIQ. |
| **HITRUST CSF v11.8.0** (May 2026) | The practical certification path for healthcare SaaS; prescriptive where HIPAA is not. Maps to PCI DSS v4.0.1 and SOC 2 TSC. | ⚠️ Version and date verified; the control catalog is behind MyCSF. **Encryption-at-rest control IDs were not independently verified — do not cite specific HITRUST control numbers without pulling the catalog.** |
| **FedRAMP** (Crypto Module Policy v1.1, Jan 2025; SC-13, SC-8(1), SC-28(1)) | Relevant only when selling to federal customers. Notably, FedRAMP "generally prefers the elimination of known vulnerabilities through patches or updates over continuing to use known-vulnerable software that is FIPS-validated." | Likely out of scope for mid-market consumer-data SaaS. Appendix, not a pillar. FedRAMP 20x changes not investigated. |

---

## 7. Evidence base

### IBM Cost of a Data Breach 2026
Published 29 July 2026 (Ponemon Institute). Sample: 602 organizations breached March 2025 – February 2026; 3,558 leaders interviewed.

- **⭐ The single best statistic for this thesis, primary-sourced and verbatim: "Only 37% of breached organizations stated that they encrypt sensitive data both at rest and in transit,"** and just **34% have visibility into cryptographic assets** ([IBM press release](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average)).
- **Global average: $4.99M** — up 12% YoY, a record high. Primary-sourced. Financial services **$6.3M**.
- ⚠️ **Secondary only:** **US average $11.5M** and **healthcare $6.64M** (costliest industry for the 13th consecutive year) appear in aggregator coverage — Becker's, HIPAA Journal, eSecurityPlanet — but **not** in IBM's press release or public report page. The full report is registration-gated. **Retrieve the report before using these figures publicly**, and mark them as secondary until then.
- **Customer PII compromised in 52% of breaches.**
- Breaches lasting 200+ days cost $5.65M vs $4.32M for faster resolution.
- Security AI and automation reduced costs by $1.93M and shortened lifecycles by 65 days — the top cost mitigator.

**⚠️ Do not invent an encryption-savings figure.** IBM 2026 publishes no discrete "cost saving attributable to encryption." The 37% statistic is the encryption-relevant finding.

**⚠️ Discrepancy flagged:** eSecurityPlanet reports "53% of breached organizations lacked encryption." 37% + 53% = 90%, so these are probably different questions. Use the IBM press-release 37% as primary.

### Verizon DBIR
**2026 edition** (published 19 May 2026; 31,000+ incidents, 22,000+ confirmed breaches, 145 countries): exploitation of software vulnerabilities is now the **#1 breach vector at 31%**, displacing stolen credentials (13%); ransomware present in 48% of breaches; third parties involved in 48%; human element in 62%.

**2025 SMB Snapshot** — the SMB-specific asymmetry, verbatim: "In larger organizations, Ransomware is a component of **39%** of breaches, while SMBs experienced Ransomware-related breaches to the tune of **88%** overall." System Intrusion rose to 53% of SMB breaches from 36%.

**⚠️** Cite the SMB figures with the year attached (2025 edition). DBIR does **not** report a "proportion of breaches involving stolen data at rest" cut — do not fabricate one.

### HHS OCR Breach Portal (healthcare)
2025: **789 breaches** of 500+ records affecting **~138.5 million individuals** — 2.1 large breaches per day. 2024: 779 breaches affecting ~289 million, inflated by Change Healthcare alone at 192.7 million. Hacking/IT incidents accounted for **more than 80%** of large healthcare breaches in 2025. *(Secondary: HIPAA Journal's aggregation of the OCR portal.)*

### Security workforce (ISC2 2025 Workforce Study, published 4 Dec 2025)
36% of organizations cut cybersecurity budgets in the prior 12 months; 39% imposed hiring freezes; only 34% believe they have appropriate staffing; **59% face critical or significant skills shortages, up from 44% in 2024**. Smaller organizations (1–99 employees) had lower layoff rates but report less capacity to absorb cuts.

**⚠️** The widely-quoted "4.8 million unfilled cybersecurity jobs" figure was **not** confirmed against the ISC2 study page. Verify before use.

### ❌ Statistic to avoid — actively debunked

**"60% of small businesses close within six months of a cyberattack" is false.** [Nextgov's 2017 investigation](https://www.nextgov.com/cybersecurity/2017/05/how-fake-cyber-statistic-raced-through-washington/137542/) found it has "no basis in fact." The National Cyber Security Alliance, routinely credited as the source, stated the underlying "third-party data has not actively been used for multiple years" and "its original source cannot be confirmed." The earliest traceable instance is a September 2011 *Business Insider* piece citing an unnamed expert the author could not later recall. It propagated through congressional bills, FTC testimony, and Senate hearings by circular citation. **No rigorous study has measured SMB closure rates after breaches.** Citing it is an easy credibility kill.

---

## 8. Not verified — check before publishing

1. **Number of states with an explicit encryption safe harbor.** No authoritative count obtained. Assert the pattern, not a number.
2. **Texas § 521.053's encrypted-data-plus-key clause** — from FindLaw (secondary); the Texas legislature's site is a JS app and Justia returned 403.
3. **HITRUST encryption-at-rest control IDs** — catalog paywalled.
4. **IBM 37% vs 53% figures** — not reconcilable from public summaries.
5. **IBM mean-time-to-identify-and-contain of 247 days** — secondary (HIPAA Journal), not confirmed against IBM directly.
6. **ISC2 "4.8M workforce gap"** — secondary aggregators only.
7. **2026 DBIR SMB Infographic** — exists per Verizon's site but no working URL found.
8. **Federal Register page number** for the FTC Safeguards breach-notification final rule (88 FR, 13 Nov 2023) — cite the document, not a page.
9. **FedRAMP 20x** crypto requirements — not investigated.
10. **SIG (Shared Assessments) 2026 question text** — licensed/paywalled; not obtained at question level.
11. **IBM 2026 US average ($11.5M) and healthcare ($6.64M)** — secondary aggregators only; not in IBM's press release or public report page. The full report is registration-gated.

### Corrections applied after independent verification (2026-08-08)

- **16 CFR 314.2(m), not 314.4(j)**, carries the "considered unencrypted if the encryption key was accessed" condition. The verb is "considered," not "deemed."
- **NIST SP 800-38G is NOT withdrawn.** Update 1 (March 2016) remains the current recommendation; the "Withdrawn" flag on CSRC applies only to the superseded original printing. Rev. 1 is at second public draft (3 Feb 2025).
- **Grubbs et al. S&P 2017 recovered 90% of birthdates, not 91%**; and the CLWW figures are 98% first names / 97% ZIP codes, not first/last names.
- **AWS-2025-032 says "There are no known workarounds,"** not "No workarounds exist."
- **CIS Safeguard 3.11** verbatim text is from the CIS Controls Assessment Specification for Controls v8, not a v8.1-labeled document.

---

## 9. The three strongest citations, ranked

1. **PCI DSS v4.0.1 Req. 3.5.1.2** — explicitly names "file-, column-, or field-level database encryption" as the acceptable alternative and disqualifies disk-level encryption on non-removable media; fully enforceable since 31 March 2025; and via **NRS 603A.215(1)** it is incorporated into Nevada state law for any card-accepting business.
2. **16 CFR 314.4(c)(3)** — unconditional "encrypt all customer information… at rest," with an escape hatch requiring a named Qualified Individual's sign-off; paired with **314.4(j)(1)** and the **§314.2(m)** definition, where the encryption-key condition determines whether you file a publicly-published FTC breach report.
3. **74 FR 42742–43** — "decryption tools should be stored on a device or at a location **separate from the data**" — regulatory endorsement of the exact key/data separation that FDE and TDE cannot structurally provide, and the gateway to the HIPAA breach-notification safe harbor at 45 CFR 164.402.

---

**Sources:** [eCFR 45 CFR 164.312](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) · [45 CFR 164.306](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.306) · [45 CFR 164.402](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.402) · [HHS Breach Safe Harbor Guidance](https://www.hhs.gov/hipaa/for-professionals/breach-notification/guidance/index.html) · [74 FR 42740](https://www.federalregister.gov/documents/2009/08/24/E9-20169/breach-notification-for-unsecured-protected-health-information) · [90 FR 898 NPRM](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information) · [PCI DSS v4.0.1](https://www.middlebury.edu/sites/default/files/2025-01/PCI-DSS-v4_0_1.pdf) · [PCI SSC future-dated requirements](https://blog.pcisecuritystandards.org/now-is-the-time-for-organizations-to-adopt-the-future-dated-requirements-of-pci-dss-v4-x) · [16 CFR Part 314](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314) · [FTC Safeguards notification](https://www.ftc.gov/business-guidance/blog/2024/05/safeguards-rule-notification-requirement-now-effect) · [201 CMR 17.04](https://www.law.cornell.edu/regulations/massachusetts/201-CMR-17-04) · [Cal. Civ. Code 1798.82](https://california.public.law/codes/ca_civ_code_section_1798.82) · [NY GBL 899-aa](https://www.nysenate.gov/legislation/laws/GBS/899-AA) · [NRS 603A](https://www.leg.state.nv.us/NRS/NRS-603A.html) · [23 NYCRR 500.15](https://www.law.cornell.edu/regulations/new-york/23-NYCRR-500.15) · [NYDFS Second Amendment text](https://www.dfs.ny.gov/system/files/documents/2023/10/rf_fs_2amend23NYCRR500_text_20231101.pdf) · [NIST SP 800-57 Pt1 Rev5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) · [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) · [NIST SP 800-111](https://csrc.nist.gov/pubs/sp/800/111/final) · [FIPS 140-3 Transition](https://csrc.nist.gov/projects/fips-140-3-transition-effort) · [AICPA Trust Services Criteria](https://assets.ctfassets.net/rb9cdnjh59cm/5jT1narHNQNzt4JGlkd1gr/248661d08e42531329d147782a6f8854/Trust-services-criteria.pdf) · [CSA CCM CEK domain](https://cloudsecurityalliance.org/blog/2025/03/10/implementing-ccm-cryptography-encryption-and-key-management) · [CIS Safeguard 3.11](https://controls-assessment-specification.readthedocs.io/en/latest/control-3/control-3.11.html) · [HITRUST CSF v11.8.0](https://hitrustalliance.net/advisories/haa-2026-002-csf-version-11.8.0-release) · [IBM Cost of a Data Breach](https://www.ibm.com/reports/data-breach) · [Verizon DBIR](https://www.verizon.com/business/resources/reports/dbir/) · [2025 DBIR SMB Snapshot](https://www.verizon.com/business/resources/infographics/2025-dbir-smb-snapshot.pdf) · [ISC2 2025 Workforce Study](https://www.isc2.org/Insights/2025/12/2025-ISC2-Cybersecurity-Workforce-Study) · [HHS OCR Breach Portal](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf)
