# Fieldseal Core Specification

**Version:** 0.1-draft · **Date:** 2026-08-08 (rev. 2026-08-22) · **Status:** Working draft. Not for production use. **Not independently reviewed** — the Phase 0 cryptographic review has not taken place, and every suite in the registry is provisional (§4.2, §4.8) for that reason.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

> **Reviewer note.** Every normative statement below carries its justification inline. Where the underlying literature is contested, or where a design choice was made against a plausible alternative, this is stated rather than hidden. Two markers appear in the text and mean different things. **[OPEN]** marks a question this specification has not answered; all of them are listed in §13. **[PROVISIONAL]** marks a question it has answered *provisionally under Gate 0a* (PRD §8) so that implementation could begin — the answer is written normatively, is what the vectors and cores are built against, and is expected to be the thing your review changes. Each provisional marker names its tracker issue and the question in [`16-reviewer-brief.md`](16-reviewer-brief.md) that would close it. Nothing marked provisional is settled, and §4.8 keeps data written under one identifiable after the fact.

---

## 1. Scope

This specification defines:

1. A self-describing **ciphertext envelope** for a single field (cell) of a database record.
2. A registry of **cipher suites**, each frozen as a complete unit.
3. A **key hierarchy** and derivation scheme.
4. A **blind-index** construction for equality search, with a declared leakage budget.
5. A **key-provider interface**.
6. **Conformance levels** L0 through L4.

It does not define a wire protocol, a key-management service, a query language, or an ORM API. Adapter behavior is described normatively only where interoperability or safety depends on it (§10).

---

## 2. Threat model (normative)

An implementation MUST document its threat model in terms of this section. Claims beyond it are out of scope for conformance.

### 2.1 In scope

| # | Adversary | Protection |
|---|---|---|
| T1 | Obtains a database backup, a stolen disk, an exfiltrated dump, or a detached replica volume | **Strong.** Ciphertext without keys. This is the primary protection and maps directly onto breach-notification safe harbors. |
| T2 | Obtains read access to database tables (compromised read replica credential, DBA, misconfigured BI connection) | **Strong** for fields encrypted under a randomized suite. **Degraded** for fields carrying a blind index — see §7.4. |
| T3 | Moves ciphertext between rows, columns, or tenants within the database | **Strong** at conformance level L3 (§6.4). **None** below L3. |
| T4 | Obtains a single tenant's key material | Blast radius is bounded to that tenant, provided per-tenant DEKs are used (§5.2). |

### 2.2 Explicitly out of scope

An implementation MUST state the following, in substance, in its user-facing documentation.

| # | Adversary | Status |
|---|---|---|
| N1 | Compromises the application process | **No protection.** The keys are in that process. Anything the application can read, the adversary can read. |
| N2 | Observes queries, query logs, slow-query logs, the DBMS buffer cache, or replication logs over time | **Weak.** See §2.3. |
| N3 | Observes result-set sizes and access patterns across many queries | **Weak.** This is the leakage-abuse setting; see §7.4. |
| N4 | Has the ability to submit chosen plaintexts and observe blind-index values | **Degraded.** Registration and search endpoints are chosen-plaintext oracles; see §7.5. |

### 2.3 Logs are in scope as sensitive artifacts (normative)

An implementation MUST document, and a deployment SHOULD enforce, that database query logs, slow-query logs, audit logs, and replication logs are treated as sensitive artifacts subject to the same access controls as the ciphertext.

*Justification.* Grubbs, Ristenpart and Shmatikov ([HotOS '17](https://eprint.iacr.org/2017/468)) showed that "logs, caches, and data structures kept by DBMS's leak information that is not accounted for in the threat models used by the designers of encrypted databases," with query text surviving in MySQL memory across thousands of subsequent operations. This was confirmed against a shipping product: the ETH Zurich analysis of MongoDB Queryable Encryption ([USENIX Security '23](https://www.usenix.org/system/files/usenixsecurity23-gui_1.pdf)) recovered **40–100% of field values purely from MongoDB's `queryLog` and `opLog`** — the `opLog` attack required **zero client queries**, only one inevitable compaction. A field-encryption design that ignores logs is not reviewable.

### 2.4 Relationship to storage-layer encryption

This specification does not replace full-disk, volume, or transparent database encryption. Deployments SHOULD retain those controls. They defend a different adversary (physical media loss) and cost almost nothing.

---

## 3. Envelope format

### 3.1 Layout

A conformant ciphertext is the concatenation:

```
+---------+----------+---------+----------+--------+------------+-------+--------------+
| fmt_ver | suite_id | key_id  | msg_seed | nonce  | ciphertext |  tag  | [commitment] |
|   1 B   |   2 B    |  16 B   |   32 B   | 12 B*  |    var     | 16 B* |    32 B*     |
+---------+----------+---------+----------+--------+------------+-------+--------------+
 \________________ header (51 B) ________________/
```

Fields marked `*` have sizes determined by `suite_id`; the values shown are for suite `0xFF01`.

| Field | Size | Description |
|---|---|---|
| `fmt_ver` | 1 B | Envelope format version. `0x01` for this specification. |
| `suite_id` | 2 B | Big-endian identifier of a complete cipher suite from the registry in §4. |
| `key_id` | 16 B | Opaque identifier of the key material required to decrypt. Structure is defined by the `KeyProvider`; implementations MUST treat it as opaque bytes. |
| `msg_seed` | 32 B | Random per-write key-derivation seed, freshly generated from a CSPRNG on **every** encryption operation, including UPDATEs. Feeds record-key derivation (§5.3), making every derived key single-use. Precedent: the AWS Encryption SDK v2 32-byte Message ID. |
| `nonce` | suite-defined | Freshly generated per encryption operation. |
| `ciphertext` | variable | AEAD output. |
| `tag` | suite-defined, ≥16 B | AEAD authentication tag. |
| `commitment` | suite-defined, 0 or 32 B | Key-commitment value, present only for suites whose AEAD is not itself committing. The requirement is settled; the construction is adopted provisionally in §4.6 (gap G1), as is whether the mandatory suite needs one at all (§13.2). |
### 3.2 Header authentication (normative)

`fmt_ver`, `suite_id`, `key_id`, and `msg_seed` MUST be included in the AEAD's additional authenticated data (§6.2–§6.3). They MUST NOT be an unauthenticated prefix. (`msg_seed` is additionally self-authenticating: tampering with it changes the derived key and fails the tag check — §5.3.)

*Justification.* These fields drive key selection. Google's own Tink documentation states that its 5-byte prefix "is not authenticated and cannot be relied on for security purposes" — it is a hint. An implementation that selects a decryption key from an unauthenticated field is inviting key-substitution steering. The AWS Encryption SDK authenticates its header; this specification follows that model.

### 3.3 Column storage type (normative)

Implementations MUST support storing the envelope in a binary column type (`BYTEA`, `VARBINARY`, `BLOB`). Implementations MAY support base64 text storage, and if they do, MUST document the resulting overhead.

*Justification and honest cost.* A 9-byte US Social Security Number under suite `0xFF01` becomes 51 (header, including the 32-byte derivation seed) + 12 (nonce) + 9 (ciphertext) + 16 (tag) + 32 (commitment) = **120 bytes binary**, or **160 bytes base64** — a 13.3× or 17.8× expansion. The fixed overhead is 111 bytes per encrypted field; across a 20-encrypted-column, 100-million-row table that is roughly 220 GB of envelope overhead alone, before index bloat and before WAL/replication amplification of the same. Base64 is a 33% tax paid on every row, forever.

This envelope is deliberately heavier than Tink's 5-byte prefix. The extra bytes purchase authenticated key identification, key commitment, per-write derived keys, and context binding. A deployment that does not need those properties should not pay for them — and should not use this specification.

### 3.4 Detection

`is_ciphertext(bytes)` MUST return true only if the input is at least the minimum envelope length for a registered suite, `fmt_ver` is a recognized version, and `suite_id` is a **registered** suite. Recognition MUST be independent of the decrypt allow-list (§4.3): the allow-list governs *authorization to decrypt* (`SUITE_NOT_ALLOWED`), not *recognition*. If recognition consulted the allow-list, ciphertext under a retired suite would be misclassified as unmigrated plaintext in `permissive` read mode — returning ciphertext bytes as application data and, worse, *re-encrypting them* on the next write (double encryption, unrecoverable without forensics). `is_ciphertext` MUST NOT attempt to decrypt, and implementations MUST NOT infer the suite by trial decryption.

### 3.5 Plaintext length bound (normative)

`encrypt()` MUST reject a plaintext longer than **2³¹−1 bytes** with `LENGTH_EXCEEDED` (§9), raised at the API boundary before any key acquisition or cryptographic processing. `decrypt()` MUST reject an envelope whose implied plaintext length exceeds the same bound, and MUST do so *before* allocating a buffer for the result. `rotate()` is subject to both bounds, being a decrypt followed by an encrypt (§11.1).

The decrypt-side check depends only on the received byte count and the suite's fixed overhead, so it is computable immediately after the header is parsed and requires neither key material nor context. Its position relative to the other decrypt-path checks is therefore immaterial, and this clause deliberately does not constrain that ordering.

*Justification.* The specification would otherwise place no bound at all, leaving each implementation to inherit its platform's accidental limits — a value one implementation encrypts is then one another cannot buffer, which is an interoperability failure this specification never sanctioned. Agreement on *rejection* is the same portability property as agreement on acceptance, and a bound chosen here is testable in the way a bound inherited from a runtime is not. AES-GCM's own plaintext ceiling (~2³⁹−256 bits, SP 800-38D §5.2.1.1) is far above anything a database cell should hold and is not the binding constraint. 2³¹−1 is the largest value representable in a signed 32-bit length, which is the lowest common denominator across the target languages; the bound is deliberately generous, because a field-level encryption specification whose length limit binds in legitimate use has the wrong limit.

**The bound is a ceiling, not a guarantee of support.** A given runtime MAY fail below it — the JVM cannot reliably allocate a `byte[]` of exactly `Integer.MAX_VALUE`, and 32-bit builds fail far earlier. Failing below the bound with a platform allocation error is not a conformance failure; the testable conformance requirement is narrower and exact: a plaintext of 2³¹ bytes MUST be refused with `LENGTH_EXCEEDED` rather than with whatever the platform would have raised. Multi-gigabyte values in a database cell indicate a design error upstream, and implementations SHOULD document that.

---

## 4. Cipher suite registry

### 4.1 Design principle (normative)

A `suite_id` names a **complete, frozen suite**: AEAD, nonce policy, KDF, and blind-index construction, as one indivisible unit. There MUST NOT be per-algorithm header fields. There MUST NOT be a caller-settable algorithm parameter.

*Justification.* This is deliberately the PASETO model rather than the JOSE model. The JWT `alg` header produced `alg=none` stripping, RSA→HMAC confusion, and `kid` abuse — all reducible to attackers controlling which validation rules the target follows. Adam Langley's position ("have **one** option. Maybe two. Fight to keep it that small.") and NIST CSWP 39 §3.2.3 ("if the integrity of algorithm selection during negotiation is not protected, the protocol will be subject to a downgrade attack") point the same direction.

Data at rest has no peer and therefore **no negotiation**. The header is a declaration, not a negotiation. This dissolves the usual agility-versus-simplicity tension: there is nothing to downgrade *to* unless an implementation chooses to support it.

### 4.2 Registry

**No suite identifier is assigned yet.** Until Gate 0b closes (PRD §8) the registry defines *provisional* suites only, in the reserved `0xFF00`–`0xFFFF` range governed by §4.8. The `0x0001` and `0x0002` identifiers are **reserved but unassigned**, and MUST NOT appear in any envelope until the constructions they will name are frozen.

| `suite_id` | Name | AEAD | Nonce | KDF | Committing | FIPS-approvable | Status |
|---|---|---|---|---|---|---|---|
| `0xFF01` | `FLE-AES256GCM-HKDF-SHA512-PROVISIONAL` | AES-256-GCM | 96-bit RBG | HKDF-SHA-512 (SP 800-56C) | No — explicit 32 B commitment REQUIRED | **Yes** (CAVP-testable) | **[PROVISIONAL]** — AEAD choice deferred (§13.2, ADR-0002); commitment construction adopted provisionally (§4.6, G1) |
| `0xFF02` | `FLE-XCHACHA20POLY1305-HKDF-SHA512-PROVISIONAL` | XChaCha20-Poly1305 | 192-bit RBG | HKDF-SHA-512 | No — explicit 32 B commitment REQUIRED | **No** | **[PROVISIONAL]** — no normative definition of the AEAD yet exists (§4.2 note, G7) |
| `0x0001` | *(reserved, unassigned)* | — | — | — | — | — | Assigned when `0xFF01`'s constructions freeze at Gate 0b |
| `0x0002` | *(reserved, unassigned)* | — | — | — | — | — | Assigned when `0xFF02`'s constructions freeze at Gate 0b, if it survives |

Implementations MUST support `0xFF01`. Implementations MAY support `0xFF02`. No more than two suites will be defined in v1.0.

> **[PROVISIONAL — G7]** XChaCha20-Poly1305 has no IETF RFC; `draft-irtf-cfrg-xchacha` expired, and libsodium's `crypto_aead_xchacha20poly1305_ietf_*` is the de-facto standard. A specification that requires a citation for every normative claim cannot name a suite it cannot cite. The open question is whether to name libsodium's construction normatively (the PASETO precedent) or drop the suite and ship a one-suite registry — see [issue #7](https://github.com/fieldseal-dev/fieldseal-spec/issues/7) and reviewer question [Q6](16-reviewer-brief.md#q6). `0xFF02` exists under Gate 0a so the two-suite mechanics (allow-listing, mixed-suite reads, rotation across suites) are exercised by the vectors and the cross-implementation matrix; the mechanics are what Phase 1 is proving, and they are unaffected by which AEAD ultimately fills the slot.

A provisional suite is a complete, frozen suite in every sense §4.1 requires — it offers the caller no algorithm agility whatsoever. "Provisional" constrains the *project*, not the caller: it says this project may still change these constructions, and §4.8 governs what an implementation may do with one in the meantime.

### 4.3 Suite allow-listing (normative)

Decrypt-side suite policy MUST be a configured allow-list. An implementation MUST refuse to decrypt an envelope whose `suite_id` is not on the allow-list, even if it has code capable of doing so.

*Justification.* This is how a suite is retired without a downgrade window.

### 4.4 Nonce policy (normative)

For every encryption operation, including UPDATEs of an existing value, the nonce MUST be freshly generated from a CSPRNG. The nonce MUST NOT be derived from row identity. It MUST NOT be a counter. It MUST NOT be persisted.

*Justification.* NIST SP 800-38D §8 requires that the probability of IV+key reuse be no greater than 2⁻³², and states that "if even one IV is ever repeated, then the implementation may be vulnerable to the forgery attacks... In practice, this requirement is almost as important as the secrecy of the key."

A database breaks every construction SP 800-38D permits:

| Database reality | Effect |
|---|---|
| Row rewritten (UPDATE) | A nonce derived from `table‖column‖pk` re-encrypts *different* plaintext under the *same* key+nonce. In CTR-based modes this leaks the XOR of both plaintexts **and** enables recovery of the GHASH authentication key → universal forgery. |
| Restored backup / PITR | A persisted counter rewinds. Every write after the restore replays used nonces. There is no operational control that reliably prevents this. |
| Replicated / autoscaled app tier | SP 800-38D §8.2.1 requires a globally unique fixed field per device. Ephemeral containers make provably-unique device IDs an operational fiction. |
| Volume | SP 800-38D §8.3 caps random-nonce use at 2³² invocations per key — ~4.3×10⁹ field writes. A per-table DEK reaches this quickly. |

The volume constraint is not solved by counting. It is solved structurally by per-write key derivation from the envelope's random 32-byte `msg_seed` (§3.1, §5.3): no derived key ever encrypts more than one value, so the §8.3 ceiling is unreachable regardless of tenant size or `row_id` configuration. The random nonce is retained as defense in depth on top of key uniqueness.

### 4.5 Tag length (normative)

Authentication tags MUST be at least 128 bits. Tag truncation MUST NOT be supported.

*Justification.* NIST opened a second pre-draft comment period on revising SP 800-38D on 1 June 2026, proposing to "remove support for authentication tags whose lengths are less than 96 bits." A specification fixing 128 bits is future-proof.

### 4.6 Key commitment (normative)

> **[PROVISIONAL — G1]** The *requirement* below is settled: every suite provides key commitment. The **construction** that satisfies it is adopted provisionally under Gate 0a — the derivation, its inputs and its verification point are written below so that vectors and cores have one thing to agree on, and all three are what the review is asked to judge. See [issue #1](https://github.com/fieldseal-dev/fieldseal-spec/issues/1) and reviewer question [Q2](16-reviewer-brief.md#q2). Whether the mandatory suite needs an explicit commitment at all is downstream of [ADR-0002](adr/0002-suite-0x0001-aead.md), itself provisional (§13.2): a natively committing AEAD would set `commit_len = 0`.

Every suite MUST provide key commitment, either by using a committing AEAD or by emitting an explicit 32-byte commitment value derived from the key. AAD binding alone MUST NOT be relied upon for this purpose.

**Provisional construction (Gate 0a, 2026-08-23).** For every registered suite whose AEAD is not itself committing — both provisional suites — the 32-byte `commitment` field of §3.1 is:

```
commitment = KDF(
    ikm     = record_key,                    // §5.3, the key the AEAD is opened with
    salt    = "",                            // zero-length; RFC 5869 §2.2 then uses HashLen zero bytes
    info    = "fieldseal-commit-v1",         // 19 ASCII bytes, fixed
    length  = 32
)
```

where `KDF` is the suite's KDF — HKDF-SHA-512 for `0xFF01` and `0xFF02`. The label is the domain separator: record-key derivation (§5.3) and index-key derivation (§7.2) use the same KDF with `canonical_context` as `info`, and `canonical_context` begins with a presence byte and a length-prefixed `suite_id`, so no `info` of theirs can equal this one.

On decrypt, an implementation MUST derive `record_key` from each candidate key (§8), recompute `commitment`, and compare it with the envelope's field in constant time **before** opening the AEAD with that key. A candidate whose recomputed value does not match MUST NOT be used to open the ciphertext; if no candidate matches, the result is `COMMITMENT_INVALID` (§9). Where this check sits among the other §9 outcomes is G5's subject; that it precedes the AEAD is this section's.

*What the construction commits to.* `record_key` is a function of `tenant_dek`, `key_id`, `msg_seed` and `canonical_context` (§5.3), so the commitment binds all four jointly, through one derivation, without any of them being re-encoded here. Two consequences follow and are stated rather than left to be discovered. First, a ciphertext cannot verify under two different tenant keys unless HKDF-SHA-512 collides on distinct inputs, which is the collision-binding property wanted. Second, a *context* mismatch at decrypt time changes `record_key` and therefore fails here, indistinguishably from a wrong key — which is why §9 cannot promise `AAD_MISMATCH` on these suites and why G5 exists.

*What is open.* The choice of deriving from `record_key` rather than from the tenant key and `msg_seed` directly (the AWS Database Encryption SDK derives its commitment key from the data key and message ID, then MACs the header — `docs/adr/0001-appendix-a-expressibility-mapping.md`, F7); whether a KDF output is the right commitment primitive or a MAC over the header would be stronger; and whether 32 bytes is the right length. Test vectors: `vectors/commitment/ff01.json`.

*Justification.* None of AES-GCM, AES-GCM-SIV, or (X)ChaCha20-Poly1305 is key-committing. In a multi-key system where the header names a key ID and an adversary may influence which key is used, a single ciphertext can be crafted to decrypt validly under two keys ("invisible salamanders"), enabling partitioning-oracle attacks (Len–Grubbs–Ristenpart, [USENIX Security '21](https://www.usenix.org/system/files/sec21-len.pdf); Bellare–Hoang, EUROCRYPT '22).

This is not theoretical for databases. **AWS shipped [security bulletin AWS-2025-032](https://aws.amazon.com/security/security-bulletins/AWS-2025-032/) on 17 December 2025** — "Key Commitment Issues in S3 Encryption Clients," CVE-2025-14759 through -14764, across six language SDKs — remediating by "introducing the concept of 'key commitment' to S3EC where the EDK is cryptographically bound to the ciphertext." Their advisory states: **"There are no known workarounds."** AAD binds *context*; it does not bind *key identity*.

### 4.7 Prohibited constructions (normative)

An implementation MUST NOT support, and this specification will not register:

- Order-preserving encryption (OPE)
- Order-revealing encryption (ORE)
- Any range-queryable index over ciphertext
- Any `LIKE`, substring, or regex index over ciphertext
- Format-preserving encryption for the field cipher
- Tag lengths below 128 bits
- Runtime algorithm selection derived from stored data
- Any "auto-detect the algorithm" decoder

*Justification for OPE/ORE.* Grubbs, Sekniqi, Kolesnikov, Boneh and Ristenpart ([S&P 2017](https://www.ieee-security.org/TC/SP2017/papers/433.pdf)), abstract verbatim: "attacks that recover **99% of first names, 97% of last names, and 90% of birthdates**." Against the successor CLWW scheme: **98%** of first names and **97%** of ZIP codes (BCLO managed only 12% on ZIP codes). Against Kerschbaum's frequency-hiding scheme: top-10 first names **86%**. Their conclusion: "the security benefits of deployed schemes is quite marginal." Naveed–Kamara–Wright ([CCS 2015](https://cs.brown.edu/people/seny/pubs/edb.pdf)) recovered, on real US hospital data under OPE: admission month, disease severity and mortality risk at **100% for 100% of the 200 largest hospitals**; length of stay ≥99.77% of patients for 100% of hospitals.

*Justification for FPE.* Format-preserving encryption is excluded because it preserves the plaintext's format and therefore its domain structure, which is precisely what the frequency-analysis results above exploit. Note that SP 800-38G Update 1 **remains a current NIST recommendation** — this specification's exclusion is a design choice, not a claim that NIST has withdrawn FPE. SP 800-38G Rev. 1 is at second public draft (3 Feb 2025) and proposes dropping FF3, retaining only FF1.

### 4.8 Provisional suites (normative)

The `0xFF00`–`0xFFFF` identifier range is permanently reserved for provisional and experimental suites, and no suite in that range will ever be promoted in place. A provisional suite that survives review is re-registered under a fresh low-range identifier and the provisional identifier is retired unused. An envelope is therefore never ambiguous about whether the construction that produced it had been reviewed, and the answer is one masked comparison on `suite_id` — available from bytes 1–2 of any stored envelope, without a key.

**On encrypt.** An implementation MUST refuse to produce an envelope naming a provisional `suite_id` unless the deployment has explicitly armed provisional use. The arming mechanism MUST NOT default to armed, MUST be an affirmative out-of-band act (an environment variable or an explicit constructor argument), and MUST NOT be satisfiable by the ordinary configuration that carries `allowed_suites` and `write_suite` — an operator who arms a provisional suite is to have done so deliberately, not inherited it from a copied config. Refusal raises `SUITE_PROVISIONAL` (§9) at the API boundary, before key acquisition and before any cryptographic processing.

**On decrypt.** Provisional suites are subject only to the ordinary allow-list of §4.3 and require no arming. Reading data one has already written is not what the gate exists to prevent, and making recovery harder than writing would be exactly the wrong incentive.

**On rotate.** `rotate()` produces ciphertext and is an encrypt for this purpose: it requires arming.

**On conformance.** A conformance claim (§10) made against a provisional suite MUST name the provisional identifier and MUST NOT be restated as a claim against the reserved identifier it instantiates. The conformance report of `docs/14` carries the provisional identifier verbatim.

*Justification.* The Phase 0 exit gate is split (PRD §8): Gate 0a permits implementation work, Gate 0b — independent cryptographic review — permits freezing. Between the two there is working code whose constructions may still change, which is a state this project had no vocabulary for. The failure this section prevents is an operator migrating production data behind a construction later found wrong, on the strength of a README paragraph nobody read; a normative, code-enforced refusal puts the warning where the operator will actually meet it. The reserved-range rule adds the recovery property: if a construction is overturned at Gate 0b, every row written under it is identifiable in bulk from the stored bytes alone, with no key and no application involvement.

The arming mechanism deliberately mirrors the `FIELDSEAL_TEST_MODE` gate that arms determinism injection (`docs/08-test-vector-spec.md` §6) — same shape, same reasoning, one concept for an implementer to learn rather than two.

*What this is not.* Arming a provisional suite does not make it reviewed, and nothing here licenses describing it as such. It records that the operator was told.

---

## 5. Key hierarchy

### 5.1 Structure (normative)

```
  ROOT KEK                        (KMS / HSM — never leaves the boundary)
      │  wraps
      ├──────────────────────────────────┐
      ▼                                  ▼
  TENANT DEK                       TENANT INDEX KEY
  (wrapped at rest; cached         (sibling key, wrapped at rest;
   in memory, TTL + max-uses)       NOT derived from the DEK — §7.2)
      │  KDF(key_id ‖ msg_seed,          │  KDF(context), one key per
      │      context)                    │  (table, column, index)
      ▼                                  ▼
  RECORD KEY                       BLIND-INDEX KEY
  (per write; never stored)
```

An implementation MUST implement all three data-path tiers. A single global DEK MUST NOT be the default configuration. The tenant index key exists only where blind indexes are used.

*Justification for separation of roles.* NIST SP 800-57 Pt.1 Rev.5 §5.2: "In general, a single key **shall** be used for only one purpose."

### 5.2 Tenant DEK granularity (normative)

The tenant DEK MUST be the crypto-shredding and blast-radius boundary. Deployments without a tenancy concept MUST still define a DEK scope (for example, per data-subject or per data-classification domain) and document it.

*Justification.* Granularity trade-offs:

| Granularity | Blast radius | Rotation cost | KMS calls | Crypto-shred unit | 2³² nonce budget |
|---|---|---|---|---|---|
| Per-field-value | Minimal | None | Prohibitive without derivation | Per value | Never binds |
| **Per-write (seed-derived)** | 1 value | None | 1 per cached tenant key | Via tenant key | Never binds |
| **Per-tenant** | 1 tenant | Re-wrap only | 1 per tenant per TTL | **Per tenant** | Binds at ~4.3×10⁹ writes |
| Per-table | Whole table | Full re-encrypt | Very low | Useless | Binds quickly |
| Single global | Everything | Catastrophic | Lowest | None | Binds fast |

Per-record *KMS-generated* keys are an anti-pattern at scale: AWS KMS shared cryptographic-operation quota is 100,000 req/s in the largest regions and **1,800 req/s, non-adjustable, for custom key stores**. A per-row KMS call is architecturally impossible. Per-write *derived* keys give per-value isolation at zero KMS cost.

**Index keys are siblings, not derivatives (normative).** The tenant index key (§7.2) MUST be a distinct key wrapped by the KEK and MUST NOT be derived from the tenant DEK. Consequences: (a) rotating or re-encrypting data under a new DEK version never invalidates blind indexes — the failure mode that makes rotation and searchability mutually exclusive in Rails Active Record Encryption; (b) rotating an index key is a separate, explicitly costed operation requiring an index-column rebuild (§7.8); (c) crypto-shredding a tenant MUST destroy both keys, because an index value — a keyed hash of the plaintext — survives destruction of the encryption key alone.

### 5.3 Record key derivation (normative)

```
record_key = KDF(
    ikm     = tenant_dek,
    salt    = key_id ‖ msg_seed,
    info    = canonical_context(ctx),        // purpose = "encrypt"
    length  = suite.key_length
)
```

where `KDF` is the suite's KDF, `canonical_context` is the length-prefixed encoding defined in §6.2, and `msg_seed` is the envelope's random per-write derivation seed (§3.1). Because `msg_seed` is fresh on every encryption, **every derived key is single-use** — this, not `row_id`, is what makes key uniqueness structural.

The KDF MUST be one-way, and it MUST NOT be possible to determine one derived key from another (SP 800-57 §8.2.4).

### 5.4 Key update chaining is forbidden (normative)

An implementation MUST NOT derive a new key version from the value of a previous key version.

*Justification, verbatim from SP 800-57 Pt.1 Rev.5 §8.2.3.2:* "If the 'value' of the new key is dependent on the value of the old key, the process is known as key update... Key update could result in a security exposure if an adversary obtains a key in the chain... **Federal applications shall not use key update.**"

### 5.5 DEK caching (normative)

An implementation MUST provide an in-memory tenant-DEK cache with **both**:

- a **max-age** threshold, and
- a **max-uses** threshold that MUST NOT exceed 2³².

The cache MUST zeroize evicted key material. Where the platform supports it, the implementation SHOULD prevent the cache from being paged to swap (`mlock` or equivalent). Documentation MUST describe cache TTL as a security parameter, not a performance tuning knob.

*Justification.* AWS's normative caching thresholds require a max-age > 0 and a max-messages value in `1..2³²`; their guidance is "use the minimum amount of caching that is required to meet your cost and performance goals," and their published per-tenant case study frames the trade-off exactly: "shorter TTLs reduce the window of exposure in the event of a memory dump, while longer TTLs reduce KMS call volume." The 2³² max-uses bound is the same number as the SP 800-38D ceiling — the cache threshold **is** the nonce-safety control in any implementation that skips per-write derivation (which this specification does not permit — the bound is retained as defense in depth).

**Honest limitation, which MUST be documented:** an in-memory plaintext DEK cache is exposed to memory dumps, core files, and swap. This is a real, acknowledged residual risk.

### 5.6 Key versions (normative)

An implementation MUST support multiple simultaneously-decryptable key versions with exactly **one** version marked active-for-write. Rotation without this is a hard cutover and will cause an outage.

### 5.7 Cryptoperiods

Deployments SHOULD target the guidance in SP 800-57 Pt.1 Rev.5 Table 1: symmetric data-encryption keys, originator-usage period **< 2 years**, recipient-usage period **< OUP + 3 years**; symmetric master / key-derivation keys, **about 1 year**.

*This specification does not claim NIST requires annual rotation. It does not.* SP 800-57's Table 1 preamble is explicitly non-binding, and §5.3.3.1 and §5.3.3.2 directly anticipate the re-encryption cost problem: "Cryptoperiods are generally made longer for stored data because the overhead of generating new keys and re-encrypting all data that was encrypted using the old keys may be burdensome," and "In some cases, the costs associated with changing keys are painfully high. Examples include the decryption and subsequent re-encryption of very large databases."

### 5.8 Rotation strategies

| Strategy | What moves | Cost | What it achieves | Conformance |
|---|---|---|---|---|
| **KEK rotation / DEK re-wrap** | Wrapped-DEK blobs only | O(#DEKs), seconds–minutes | Rotates the KMS-held root. **Does not** limit data encrypted under a given DEK. | REQUIRED — this is the default posture |
| **Full background re-encryption** | Every ciphertext | O(#rows), hours–weeks | True cryptoperiod enforcement; **the only mechanism that permits destroying an old key** | REQUIRED to be available; MUST be resumable, rate-limited, and idempotent |
| **Lazy on-read re-encryption** | Records touched by reads | Amortized | Converges asymptotically; cold rows never rotate | MAY be offered. If offered, documentation MUST state that it never completes for cold data and therefore never permits old-key destruction on its own. |

None of these strategies affects blind indexes: index keys are siblings of data keys (§5.2, §7.2), so data-key rotation at any tier leaves every index valid. Rotating an *index* key is a distinct operation requiring an index-column rebuild (§7.8).

An implementation SHOULD prefer on-*write* re-encryption plus a background sweep over on-read.

*Justification.* On-read re-encryption turns SELECTs into writes, breaking read-replica routing, read-only transactions, and query-planner expectations.

### 5.9 Re-encryption is the crypto-agility mechanism (normative)

The full re-encryption sweep of §5.8 is the mechanism by which a suite is retired. NIST CSWP 39 §5.1: "For the encrypted storage of data at rest, a mechanism must be established to handle encrypted user data when the encryption algorithm is to be replaced by a stronger one." **Agility without a re-encryption sweep is a claim, not a capability.**

---

## 6. Context binding

### 6.1 What context is

`FieldContext` is the tuple supplied to every core operation:

```
FieldContext {
    suite_id     : uint16
    table_uuid   : bytes(16)      // stable surrogate, NOT the SQL table name
    column_uuid  : bytes(16)      // stable surrogate, NOT the SQL column name
    tenant_id    : bytes | null
    row_id       : bytes | null   // OPTIONAL — see §6.4
    purpose      : "encrypt" | "index:<index-id>"
}
```

`table_uuid` and `column_uuid` MUST be immutable surrogate identifiers, not SQL identifiers.

*Justification.* Binding to SQL names means a table or column rename renders every ciphertext undecryptable.

`purpose` is constrained to the following grammar (ABNF, RFC 5234):

```
purpose   = "encrypt" / ("index:" index-id)
index-id  = 1*32( %x61-7A / %x30-39 / "-" )   ; [a-z0-9-], 1–32 bytes, ASCII
```

An identifier outside this grammar MUST be refused as a configuration error when the index is declared (§7.8), not at call time — index declarations are construction-time input, and a derivation string that fails validation must never reach a key derivation. Because uppercase is unrepresentable rather than merely discouraged, case drift cannot occur: there is no `index:Exact` to disagree with `index:exact` about.

*Justification.* `purpose` is a component of `canonical_context` (§6.2), which is both KDF `info` and part of the AAD, so every byte an identifier may contain is a byte the encoding's injectivity argument must cover. Restricting identifiers embedded in derivation strings to a minimal ASCII alphabet is ordinary practice and matches the fixed ASCII labels this specification already uses (`"fieldseal-index-v1"`, §7.2). The constraint narrows, and can never widen, what that argument has to consider. Two identifiers differing only in case or in Unicode representation would otherwise derive different keys for what an operator believes is one index — a failure that surfaces as an index silently matching nothing. 32 bytes of `[a-z0-9-]` is comfortably expressive for index naming (`exact`, `prefix3`, `email-domain`).

**This does not settle the encoding's injectivity.** Whether `canonical_context` is injective over its whole field set — in particular the still-unspecified encoding of an absent `tenant_id` — is open, and is tracked separately as a specification issue against §6.2.

**The optional fields carry no length bound.** `tenant_id` and `row_id` are unbounded here, which makes the KDF `info` of §5.3 and §7.2 unbounded; several platform HKDF implementations cap `info` (Node.js at 1024 bytes, OpenSSL 3.0–3.5 at 32 KiB), so an implementation built on one cannot derive keys for every context another can write. Whether this section should bound those fields — or instead require implementations to accept any `info` the encoding can produce — is open and tracked as [issue #43](https://github.com/fieldseal-dev/fieldseal-spec/issues/43) (G14). This paragraph is a pointer, not a rule; nothing here is settled by it.

### 6.2 Canonical encoding (normative)

> **[PROVISIONAL — G4]** The presence-bitmap encoding below is adopted provisionally under Gate 0a — it is what makes this encoding injective across the absent-versus-zero-length cases, which the previous positional form was not. See [issue #4](https://github.com/fieldseal-dev/fieldseal-spec/issues/4) and reviewer question [Q4](16-reviewer-brief.md#q4). What stays open is whether the encoding is injective over the current *and* plausibly-extended field set; the bit assignment may change at Gate 0b.

```
canonical_context(ctx) =
    u8(presence)
  ‖ u64be(len(suite_id))    ‖ suite_id
  ‖ u64be(len(table_uuid))  ‖ table_uuid
  ‖ u64be(len(column_uuid)) ‖ column_uuid
  ‖ [ u64be(len(tenant_id)) ‖ tenant_id ]      // present iff presence & 0x01
  ‖ [ u64be(len(row_id))    ‖ row_id    ]      // present iff presence & 0x02
  ‖ u64be(len(purpose))     ‖ purpose

presence : bit 0 (0x01) — tenant_id present
           bit 1 (0x02) — row_id present
           bits 2–7     — reserved, MUST be zero

AAD(header, ctx) =
    u64be(len(fmt_ver))    ‖ fmt_ver
  ‖ u64be(len(key_id))     ‖ key_id
  ‖ u64be(len(msg_seed))   ‖ msg_seed
  ‖ canonical_context(ctx)
```

An absent optional field contributes **nothing** to the encoding — not a length, not a value — and its presence bit is zero. A present field contributes its length prefix and its bytes even when that length is zero. `tenant_id = null` and `tenant_id = b""` therefore differ in the first byte, which is the case the positional form could not distinguish. Reserved bits MUST be written as zero; `canonical_context` is only ever produced and recomputed, never parsed, so this is a producer obligation with no decoder counterpart.

`canonical_context` covers only `FieldContext` fields, and is therefore well-defined both for encryption (§5.3) and for index derivation (§7.2), which has no envelope. The envelope-bound fields — `fmt_ver`, `key_id`, `msg_seed` — enter only the AAD. Naive concatenation MUST NOT be used.

*Justification.* Unlength-prefixed concatenation is forgeable across field boundaries. RFC 7518 §5.2 and Tink's AES-CTR-HMAC both use explicit bit-length encoding for exactly this reason. The bitmap is added on top because length prefixes alone do not distinguish *absent* from *present-and-empty* when the field is optional: the previous form omitted `row_id` entirely if null while giving `tenant_id` no null rule at all, so two different contexts could encode identically — and since `canonical_context` is both the KDF `info` and part of the AAD (§6.3), such a collision would be a key-reuse bug and an authentication bug at once. Declaring presence before the fields also makes extension cheap: a new optional field takes the next free bit, and adding one cannot silently alias against any existing encoding.

*Injectivity argument, stated so it can be attacked.* Fix the field set. The first byte determines exactly which optional fields appear and in what order; every field that appears is `u64be` length-prefixed with a fixed-width length; the mandatory fields are always present in a fixed order. Parsing is therefore unambiguous left to right, so distinct `FieldContext` values produce distinct byte strings. This is the claim Q4 asks a reviewer to confirm or break — including under future extension, where the argument holds only while new fields consume new bits rather than being appended positionally.

### 6.3 Dual-layer binding (normative)

`canonical_context(ctx)` MUST be used as the KDF `info` parameter (§5.3), and `AAD(header, ctx)` MUST be the AEAD's additional authenticated data.

*Justification.* Binding at two layers means a context mismatch produces a *wrong key* (KDF layer) **and** a failed authentication (AAD layer) — a stronger failure and a clearer diagnostic than either alone.

### 6.4 `row_id` is OPTIONAL and defaults to absent (normative)

Implementations MUST support `row_id = null`. Implementations MAY support `row_id` binding; if they do, it MUST be off by default and enabled per-column by explicit configuration.

*Justification — this is a significant and deliberate concession.* Row binding is the correct defense against intra-database ciphertext swapping (copying row A's encrypted salary into row B, or a value from the `ssn` column into the `notes` column where a different code path may expose it). But:

1. **Rails, the most mature implementation in existence, omits AAD entirely.** `activerecord/lib/active_record/encryption/cipher/aes256_gcm.rb` literally sets `cipher.auth_data = ""`, because `ActiveModel::Type` has no access to the record. Mandating row binding would place the reference implementation of the pattern out of conformance.
2. **The primary key is not available at INSERT time in most ORMs.** With database-generated identity keys, the PK is `NULL` when the value transform runs in Django (`pre_save` during INSERT compilation), SQLAlchemy (`before_insert`), EF Core (`SavingChanges`, where it is a temporary value), GORM (populated from `RETURNING` afterwards), and Prisma (the extension runs before the query). Only Hibernate with a `SEQUENCE`, `TABLE`, or assigned/UUID generator has it. **Client-generated UUIDv7 primary keys are the general solution**, and deployments enabling row binding SHOULD adopt them.
3. **It converts data-migration bugs into decryption failures.** Any legitimate PK change, tenant migration, table rename, or shard resplit breaks every affected ciphertext.

Implementations supporting row binding MUST document a re-binding procedure for legitimate migrations, and MUST distinguish `AAD_MISMATCH` from `TAG_INVALID` in errors (§9).

### 6.5 AAD contains nothing secret (normative)

No component of `FieldContext` may be a secret or a sensitive value.

*Justification.* AAD is reconstructible from schema plus row identity and, in KMS-mediated designs, is logged. AWS states plainly of encryption context: "The encryption context is not secret and not encrypted. It appears in plaintext in AWS CloudTrail Logs... **Because the encryption context is logged, it must not contain sensitive information.**"

### 6.6 Record-level MAC (RECOMMENDED)

Implementations SHOULD offer an optional MAC computed over all protected fields of a record together.

*Justification.* Per-field AAD detects substitution of one field's ciphertext for another's. It does **not** detect a *deleted* field. The AWS Database Encryption SDK signs the canonicalization of the material description, encryption context, and every encrypted-or-signed field, specifically so it can "detect unauthorized changes to the item as a whole, including adding or deleting attributes, or substituting one encrypted value for another." This is the strongest published model.

---

## 7. Blind indexes

### 7.1 Purpose and hard limits (normative)

A blind index supports **equality** and **membership (`IN`)** lookups only. It MUST NOT be used for ordering, ranges, prefix matching (except via the explicit derived-field mechanism of §7.9), substring matching, or full-text search.

### 7.2 Construction (normative)

```
index_key  = KDF(ikm   = tenant_index_key,        // sibling of the tenant DEK — §5.2
                 salt  = "fieldseal-index-v1",
                 info  = canonical_context(ctx with purpose="index:<index-id>",
                                           row_id = null),
                 length= 32)

raw        = IDF(index_key, normalize(plaintext))

blind_index = truncate(raw, b bits)
```

where:

- `normalize` is a declared, deterministic transformation (for example Unicode NFC + case folding for email addresses). It MUST be declared per column and MUST NOT change after writes begin.
- `IDF` is the index derivation function, selected per §7.3.
- `b` is the truncation length in bits, selected per §7.4.

`truncate(raw, b)` is defined bit-exactly: keep the first `⌈b/8⌉` bytes of `raw`, then set the trailing `8·⌈b/8⌉ − b` bits of the final byte to zero. Bits are numbered MSB-first within each byte (the most significant bit is bit 0, mask `0x80`); equivalently, interpret `raw` as a bit string in network order, keep the first `b` bits, and zero-pad to the byte boundary. The output length is exactly `⌈b/8⌉` bytes. Example: `truncate(0xABCD…, 12 bits)` = `0xABC0`. The representation in which that value is written to the database is defined in §7.11.

*Justification.* Either bit-order convention is cryptographically equivalent: the IDF output is uniform, so which `b` bits survive does not change the §7.4 leakage analysis. The convention is pinned solely so that independent implementations write byte-identical index values into a shared database — an interoperability decision of exactly the kind the vector suite exists to verify (§12). Leading-bits/MSB-first is chosen because the truncated value is then a byte-prefix of the untruncated output, which simplifies debugging, and because it matches the network-byte-order conventions used elsewhere in this specification (§3.1 big-endian `suite_id`, §6.2 `u64be`).

The index key MUST be distinct per `(tenant, table, column, index)`. It MUST NOT be the field encryption key. Two indexes MUST NOT share a key. Distinctness per index is achieved by the index identifier carried in `purpose` (`index:exact` for the default equality index; a §7.9 prefix index declares its own identifier). The identifier MUST satisfy the `index-id` grammar of §6.1 (`[a-z0-9-]`, 1–32 bytes), validated when the index is declared.

The tenant index key is a sibling of the tenant DEK under the KEK, and MUST NOT be the tenant DEK or be derived from it (§5.2). Deriving index keys from data keys would make every data-key rotation silently invalidate every blind index — precisely the rotation-versus-searchability trap this design exists to escape.

*Justification.* SP 800-57 §5.2 ("a single key shall be used for only one purpose"). Both CipherSweet and `blind_index` implement per-index key separation; CipherSweet's design note is explicit: "Each blind index on each column uses a distinct key from your encryption key and each other blind index key." Cross-column shared keys additionally merge frequency-analysis populations, which is the opposite of what §7.6 requires.

### 7.3 Index derivation function selection (normative)

> **[PROVISIONAL — G2]** The selection rule and the invocation below are adopted provisionally under Gate 0a. **Narrowed 2026-08-22:** routing the index key through Argon2's secret parameter `K` — the original proposal — is **ruled out on portability grounds**, which is an engineering finding the project could settle itself, not a cryptographic judgment (see the Argon2id invocation below and [gap G2](issues/G02-argon2id-parameters.md)). What remains open is cryptographic and stays with the reviewers: whether salt-only keying through a domain-separated HKDF step is sound for this deterministic, keyed use. See [issue #2](https://github.com/fieldseal-dev/fieldseal-spec/issues/2) and reviewer question [Q3](16-reviewer-brief.md#q3).

| Domain class | Required IDF | Examples |
|---|---|---|
| **Enumerable** — attacker can feasibly enumerate the domain offline | **Argon2id**, minimum 3 iterations / 32 MiB | SSN, national ID, email, phone number, account number, date of birth |
| **High-entropy, non-enumerable** | HMAC-SHA-512 permitted | Opaque random tokens, high-entropy identifiers |

*Justification.* If the index key leaks, an HMAC index over an enumerable domain is invertible by brute force in seconds. Paragonie's analysis of the chosen-plaintext case is direct: an attacker "can iterate every possible value as a user and then correlate with the resultant blind index value." `blind_index` defaults to Argon2id for this reason.

**Honest cost, which MUST be documented:** Argon2id at 4 iterations / 32 MiB costs roughly 10–100 ms **per query term**. That is a hard ceiling on query rate and it is a product constraint, not a tuning detail.

**Argon2id invocation (normative).** Where §7.3 selects Argon2id, `IDF(index_key, normalize(plaintext))` is exactly:

```
salt = HKDF-SHA-512(ikm    = index_key,
                    salt   = "",
                    info   = "fieldseal-argon2-salt-v1",
                    length = 16)

raw  = Argon2id(password    = normalize(plaintext),
                salt        = salt,
                version     = 0x13,
                t           = 3,          // iterations
                m           = 32768,      // KiB, i.e. 32 MiB
                p           = 1,          // parallelism
                output_len  = 64)
```

The index key enters **only** through the salt. Argon2's optional secret parameter `K` (RFC 9106 §3.1) MUST NOT be used, and its associated-data parameter `X` MUST NOT be used. Deployments MAY raise `t` and `m`; raising either produces a different index and is therefore a new index under §7.8, not a reconfiguration of an existing one. `version`, `p`, `output_len`, and the salt derivation MUST NOT vary.

*Justification, and an honest cost.* The obvious construction routes `index_key` through `K`, which is what this specification proposed until 2026-08-22. It is not implementable portably: libsodium's `crypto_pwhash` exposes no secret parameter at all, and Python's `argon2-cffi` exposes one only through an ultra-low-level call its own documentation warns against, while Node's `node-argon2` does expose it. A construction that one reference core can express and another cannot is this project's central claim failing, so `K` is excluded on portability grounds rather than on cryptographic ones. The evidence table is in [gap G2](issues/G02-argon2id-parameters.md).

Two costs follow and are stated rather than hidden. First, keying now rests entirely on the salt, so the defense-in-depth argument for `K` — that the index stays keyed even if the salt derivation is misused — is gone. Second, the salt is fixed at 16 bytes because libsodium requires exactly that, so the keyed material at this step is 128 bits rather than the index key's 256. An adversary without `index_key` still faces a 128-bit barrier before the memory-hard function, which is not the binding constraint on this design, but it is a reduction and it is forced by portability.

`p = 1` is likewise forced: libsodium exposes no parallelism parameter, so any other value is unreachable there. **[VERIFY]** libsodium's fixed internal value during Phase 1; if it is not 1, this line changes and every Argon2id vector regenerates.

The construction that remains — a memory-hard function over the plaintext, keyed through a domain-separated salt derived from a per-index key — is the shape CipherSweet ships, which documents Argon2id "where the blind index key is the Argon2 salt." This specification adds the HKDF step so that the raw index key is never handed to Argon2 directly and so that the salt is domain-separated from every other use of that key.
### 7.4 Truncation length (normative)

Let `P` be the projected number of **distinct** values in the column (not the number of rows). `P` MUST be ≥ 16.

`b` MUST be chosen such that:

```
2 ≤ P × 2^(−b) < √P
```

`b` MUST be rounded **down**. Both `b` and the projected `P` MUST be recorded in schema metadata. The bit-level semantics of `truncate(raw, b)` are defined in §7.2.

*Justification and honest caveat.* This is the AWS beacon-length band. Worked example from AWS's documentation for `P` = 100,000: recommended range 8–15 bits. At 16 bits, 1.5 collisions per value, "66% likely same plaintext," retrieve ~15 records per 10 wanted. At 14 bits, 6.1 collisions, "33% likely same plaintext," retrieve ~30 per 10. "For every bit below 15, the performance cost and the security double."

**These are AWS engineering heuristics, not peer-reviewed leakage bounds, and AWS hedges on them:** "Beacon length only estimates the average number of false positives produced. The more unevenly distributed your dataset, the less effective beacon length is." Implementations SHOULD ship a tool that measures actual distribution skew rather than trusting the formula.

### 7.5 Application-side re-verification (normative)

A blind index MUST be treated as a **filter**, never as an answer. After retrieving candidate rows by index, the implementation MUST decrypt and compare the actual values before returning results to the caller.

Documentation MUST state that pagination built directly on an indexed encrypted column is incorrect: the correct pattern is over-fetch → decrypt → filter → paginate.

### 7.6 Default-deny cardinality gate (normative)

An implementation MUST refuse, by default, to create a blind index on a column whose declared domain has fewer than 2¹⁰ distinct values, or which is declared as heavily skewed. Override MUST require an explicit, logged, reviewed declaration in configuration.

Categories that MUST be gated: booleans, enumerations, sex/gender, region, US state, diagnosis and test-result codes, risk tiers.

*Justification.* Naveed–Kamara–Wright ([CCS 2015](https://cs.brown.edu/people/seny/pubs/edb.pdf)) on real US hospital data under deterministic encryption recovered mortality risk and patient death for **100% of patients in ≥99% of the 200 largest hospitals**, and disease severity for 100% of patients in ≥51%. Microsoft's own Always Encrypted documentation warns: "unauthorized users might guess information about encrypted values by examining patterns in the encrypted column, **especially if there's a small set of possible encrypted values, such as True/False, or North/South/East/West region.**" AWS is blunter: attributes "with very small populations or highly imbalanced binary outcomes — such as medical test results where NEGATIVE values dominate — **cannot be protected using truncation alone**."

### 7.7 Correlated columns (normative)

Two blind indexes MUST NOT be created over correlated fields.

*Justification, verbatim from AWS:* "We strongly recommend that you avoid constructing distinct beacons from fields with correlated values" — the canonical example being `City` and `ZIPCode`, because "an unauthorized user can easily identify which results are false positives," stripping out exactly the protection truncation was providing.

### 7.8 Immutability after first write (normative)

Once any row has been written with a given blind index, its `IDF`, `normalize` function, truncation length `b`, key-derivation context, and stored representation (§7.11) MUST NOT change. Changing any of them requires creating a new index column and performing a full backfill.

### 7.9 Prefix indexes (OPTIONAL, gated)

Prefix matching MAY be supported only via an explicitly declared derived field (for example, "first 3 characters, NFC-normalized, case-folded"), treated as its own independent index subject to every rule in this section.

Documentation MUST state that every prefix length is an additional leakage channel and that prefixes are lower-entropy than full values. Enabling a prefix index MUST require an explicit written risk acceptance recorded in configuration.

### 7.10 Honest statement of what is not supported (normative)

Documentation MUST reproduce this table.

| Operation | Supported | Honest fallback |
|---|---|---|
| Equality | **Yes** | — |
| Membership (`IN`) | **Yes** — N indexes OR'd | — |
| Prefix | Gated, §7.9 | — |
| `GROUP BY` / `DISTINCT` on an indexed column | Yes, with the caveat that it groups by index, including collisions | — |
| Equi-join across encrypted columns | **No** | Requires a shared index key, which destroys key separation and merges frequency populations. Keep the join key in plaintext. |
| Range, `<`, `>`, `ORDER BY` | **No** | A deliberately coarse plaintext bucket column (age decade, income band) with its own documented risk assessment, plus exact filtering after decryption. This is honest; OPE is not. |
| `LIKE '%x%'`, regex | **No** | Decrypt-and-search over a bounded candidate set. |
| Full-text search | **No** | A separate search system with its own access controls, holding plaintext, explicitly risk-assessed. |
| Aggregates (`SUM`, `AVG`) | **No** | Requires homomorphic encryption; out of scope. |
| Unique constraints | **No** — not on randomized ciphertext, and not on a blind index either (§7.4 mandates collisions) | Enforce uniqueness in application logic: index-filtered candidate fetch → decrypt → compare, inside a transaction. See the note below on the race. |
| Foreign keys | **No** | Keep the join key plaintext, or the relational model degrades. |

**On unique constraints.** A `UNIQUE` constraint over a blind index is not merely unhelpful, it is incorrect: §7.4 requires `2 ≤ P × 2^(−b)`, so every index value is expected to correspond to at least two distinct plaintexts *by construction* — that ambiguity is the privacy mechanism. A database-enforced uniqueness guarantee cannot sit on a value whose construction forbids injectivity; as the table fills toward `P`, such a constraint rejects legitimate, distinct values with probability approaching certainty.

The application-level fallback MUST be documented with its race, not presented as equivalent. Between the candidate fetch and the insert, a concurrent transaction may commit the same value: under `READ COMMITTED` both transactions observe no match and both insert. Correctness requires either `SERIALIZABLE` isolation or an advisory lock taken on the index value for the duration — the latter is the cheaper option and leaks nothing further, since the index value is already stored in the clear. Without one of the two, uniqueness is best-effort and the deployment MUST say so.

Database-enforced uniqueness over an encrypted column would require an index that is injective per key, which means a deterministic suite — that is the §13.6 discussion, and it should be settled there rather than smuggled in through this table.

### 7.11 Index column storage type (normative)

The stored form of a blind index MUST be the raw truncated bytes produced by §7.2 — length exactly `⌈b/8⌉`, no length prefix, no padding, no encoding — written to a binary column type (`BYTEA`, `VARBINARY(⌈b/8⌉)`, `BLOB`).

Implementations MAY support a lowercase hexadecimal alternative for text-only storage paths: exactly `2·⌈b/8⌉` characters, digits `0`–`9` and `a`–`f`, no `0x` prefix and no separators. Where it is supported, the representation MUST be declared per index column and is immutable after first write (§7.8).

Index comparison MUST be exact byte equality, or for the hexadecimal alternative exact string equality. Implementations MUST create the index column with a binary or otherwise case- and accent-sensitive collation, and MUST NOT rely on the database's default collation.

*Justification.* This is the §3.3 rule applied to the index column, and it exists for the same reason: two implementations sharing one database must write byte-identical values or equality matching silently fails. That failure mode is worse than an envelope divergence, because it produces no error — a Python-written index simply never matches a Node-issued `WHERE`, and the query returns zero rows as though the value were absent. No envelope vector detects it, which is why §12 requires the stored form to be asserted directly. The collation requirement is ordinary SQL behavior rather than a cryptographic claim: under a case-insensitive collation a hexadecimal column equates `AB` and `ab`, so the database would match two values the core treats as distinct, widening the §7.4 collision band by an amount the leakage analysis never accounted for. Raw bytes are the MUST rather than hex because hex doubles a column that sits in every index page and every `WHERE` clause on the table.

---

## 8. Key provider interface

```
interface KeyProvider {
    // Returns the tenant DEK and its key_id for a write.
    encryption_key(ctx: FieldContext) -> (key: bytes, key_id: bytes[16])

    // Returns candidate keys for a read, in preference order.
    decryption_keys(header: EnvelopeHeader) -> [bytes]

    // Optional: async prefetch. MUST NOT be required for correctness.
    warm(contexts: Iterable<FieldContext>) -> void
}
```

Implementations MUST provide at minimum:

- **`StaticKeyProvider`** — a single key. Test and development use only; MUST emit a warning outside test configuration.
- **`DerivedKeyProvider`** — keys derived from a root secret via an approved KDF.
- **`EnvelopeKeyProvider`** — KMS-wrapped DEKs with the cache of §5.5. This is the production path.

`decryption_keys` MUST return keys for all currently-valid versions, enabling §5.6.

When `ctx.purpose` names an index derivation (§7.2), `encryption_key` MUST return the tenant **index key**, never the tenant DEK. Blind-index values carry no envelope; the key and parameters that produced them are identified by schema metadata (§7.8) — which is why §7.8's immutability rule exists.

### 8.1 KMS availability is a hard dependency (normative)

Documentation MUST state that the key service becomes a hard dependency in the read path of every query touching an encrypted field, and MUST document the deployment's degradation mode: **fail-closed** (return an error) or **serve-cached** (serve only what the cache can decrypt).

*Justification.* AWS states this more bluntly about external key stores than most vendors state about their own products: "**The greater risk to availability and latency will, for most customers, exceed the perceived security benefits of external key stores**"; "If you temporarily revoke access to your external key manager... ciphertext encrypted under your KMS keys can't be decrypted. If you permanently revoke access... all ciphertext encrypted under a KMS key in your external key store becomes unrecoverable." NIST names the same risk from the other side (SP 800-57 §5.3.2): "short cryptoperiods may be counter-productive, particularly where denial-of-service is the paramount concern."

### 8.2 Key destruction is unrecoverable data loss

Implementations MUST NOT provide a key-destruction API without a configurable delay window and an explicit confirmation step. Google Cloud KMS's 30-day "scheduled for destruction" window exists precisely because operators do this.

---

## 9. Errors

> **[PROVISIONAL — G5]** The error *set* below is settled. The **precedence** among these codes on the decrypt path is not — under dual-layer binding (§6.3) a context mismatch and a key confusion are indistinguishable at decrypt time. See [issue #5](https://github.com/fieldseal-dev/fieldseal-spec/issues/5) and reviewer question [Q5](16-reviewer-brief.md#q5). An implementation built under Gate 0a MUST pin an order and declare it in its conformance report (`docs/14`); the pinned order may change at Gate 0b.

An implementation MUST distinguish at least these error types, and MUST NOT collapse them into a single "decryption failed":

| Error | Meaning | Likely cause |
|---|---|---|
| `UNKNOWN_FORMAT_VERSION` | `fmt_ver` unrecognized | Data written by a newer implementation |
| `SUITE_NOT_ALLOWED` | `suite_id` not on the decrypt allow-list | A retired suite, or a downgrade attempt |
| `KEY_UNAVAILABLE` | `key_id` not resolvable | Key destroyed, KMS unreachable, wrong tenant context |
| `AAD_MISMATCH` | Context does not match | **Usually a data-migration bug**, occasionally tampering |
| `TAG_INVALID` | Authentication failed with correct context | Corruption or tampering |
| `COMMITMENT_INVALID` | Key commitment check failed | Key confusion or a partitioning-oracle attempt |
| `NOT_CIPHERTEXT` | Input is not a recognizable envelope | Unmigrated plaintext; see §10.3 |
| `MODE_VIOLATION` | The operation is not permitted in the configured read mode | `encrypt()` or `rotate()` on a `readonly` client (§10.3) |
| `LENGTH_EXCEEDED` | Plaintext exceeds the §3.5 bound, on encrypt or as implied by an envelope on decrypt | A blob stored in a field-level column; a corrupted or hostile length |
| `SUITE_PROVISIONAL` | The write suite is provisional (§4.8) and provisional use has not been armed | An attempt to write real data before Gate 0b closes |

`MODE_VIOLATION` is raised at the API boundary, before any cryptographic processing or key acquisition begins, and therefore sits outside the decrypt-path error ordering. Its message MUST name both the rejected operation and the active mode: a mode violation is a deployment-configuration error, and an implementation that reports only "operation not permitted" sends the operator looking in the wrong place. One code covers all present and future modes rather than one code per mode, so that adding a mode is not a breaking change to the error taxonomy.

`LENGTH_EXCEEDED` is a distinct code rather than a reuse of `MODE_VIOLATION`, which is specifically about a configured mode forbidding an operation — a length rejection is neither mode-dependent nor configuration-dependent. On encrypt it is raised at the API boundary on the same terms as `MODE_VIOLATION`; on decrypt it is a function of the received byte count alone (§3.5).

`SUITE_PROVISIONAL` is likewise raised at the API boundary before key acquisition, and is a property of the suite rather than of the configured mode, so it does not participate in the decrypt-path ordering either. Its message MUST name the provisional `suite_id` and the arming mechanism the deployment failed to set (§4.8) — an operator who meets this error needs to be told both that the construction is unreviewed and exactly what acknowledging that entails.

Error messages MUST NOT include plaintext, key material, or derived key values.

---

## 10. Conformance levels

Each level is independently claimable. An implementation MUST state which levels it claims, per ORM adapter.

### L0 — Envelope conformance (REQUIRED for any conformance claim)

Envelope format, suite registry, key IDs, `previous_schemes` decryption chain, strict/permissive/readonly read modes, and the full test-vector suite. Achievable in **any** environment, including a bare `encrypt(value)` helper with no ORM integration at all.

### L1 — Transparent value mapping

Read and write transforms installed at the ORM's type layer, covering single-row writes, ORM-managed bulk insert, and ORM-managed bulk update.

**Achievable in:** Django, SQLAlchemy, Prisma, TypeORM, Hibernate, EF Core, GORM — with documented carve-outs (§10.2).

### L2 — Indexed equality

Every registered suite is randomized (§4.2), so ciphertext equality never reflects plaintext equality. L2 therefore always requires the blind-index column of §7. What varies per ORM is how a query reaches that column:

- **(a) Index-typed property.** The index column is declared as its own property whose type-layer transform derives the blind index from a plaintext parameter. `WHERE email_bidx = :plaintext` then works through the ORM's ordinary parameter conversion — no query rewriting, but the query surface is explicit (callers name the index property).
- **(b) Transparent rewrite.** Predicates on the *encrypted* property are rewritten onto the index column at query-compile time.

**(a) available in:** Django, SQLAlchemy, Hibernate (HQL/criteria parameter conversion), EF Core, TypeORM (find-options and `FindOperator` values only — string-condition `where()` bypasses transformers).
**(b) achievable with real work in:** Django (`Lookup` compiling a sibling `Col`), SQLAlchemy (`hybrid_property` + `Comparator`), EF Core (`IQueryExpressionInterceptor`), GORM (`clause.Where` tree rewrite), Prisma (args-tree path rewriting, with the §10.2 mandatory throws).
**(b) not available in:** TypeORM (no predicate-rewrite extension point) and Hibernate (no supported comparator hook; `StatementInspector` sees SQL text but not parameter values — `CompositeUserType` gives a type-safe *explicit* surface, which is (a), not (b)).

### L3 — Context binding

Requires sibling-field access in the value path.

**Cleanly available in:** GORM (`Value(ctx, field, dst reflect.Value, …)` receives the whole struct), Hibernate (`Interceptor.onPersist` receives a mutable state array plus the entity).
**Available with a documented side channel** (contextvar / AsyncLocal / CLS set by an earlier hook of the same operation): SQLAlchemy, Django, EF Core, Prisma.
**Tenant-only, via ambient request-scoped CLS** (no per-operation hook covers all write paths): TypeORM.
**Not achievable:** Rails (`ActiveModel::Type` has no record access), Sequelize getters.

**L3-row** (binding to `row_id`) is a separate sub-level, achievable only in Hibernate with sequence/assigned generators, or anywhere with client-generated primary keys.

### L4 — Async key acquisition in the value path

**Available in:** Prisma (`$allOperations` is async), EF Core (`SavingChangesAsync`, `*ExecutingAsync` — write path only, not materialization), GORM (context-aware blocking).
**Not available in:** Django, SQLAlchemy (attempting to await inside a type processor raises `MissingGreenlet`), TypeORM, Hibernate, Rails, Sequelize.

**This is why the core API is synchronous (§11.1).** An async-first core would be unimplementable in the majority of target ORMs.

L4 covers asynchronous key acquisition and, where the core offers the optional companions of §11.1, asynchronous index derivation as well — the same reasoning extends from fetching a key to deriving an index, and Argon2id makes the latter the more expensive of the two. An L4 claim states which of the two the adapter actually uses.

### 10.1 Level matrix

| ORM | L0 | L1 | L2 | L3 | L3-row | L4 |
|---|---|---|---|---|---|---|
| Django | ✅ | ✅ | ✅ (a)+(b) | ⚠️ side channel | ⚠️ client PK only | ❌ |
| SQLAlchemy | ✅ | ✅ | ✅ (a)+(b) | ⚠️ side channel | ⚠️ client PK only | ❌ |
| Hibernate | ✅ | ✅ | ✅ (a) | ✅ | ✅ sequence/UUID | ❌ |
| EF Core | ✅ | ✅ | ✅ (a)+(b) | ⚠️ side channel | ⚠️ client PK only | ⚠️ write only |
| GORM | ✅ | ⚠️ see §10.2 | ✅ (b) | ✅ | ⚠️ client PK only | ✅ |
| Prisma | ✅ | ✅ | ⚠️ (b), see §10.2 | ⚠️ partial | ❌ | ✅ |
| TypeORM | ✅ | ⚠️ see §10.2 | ⚠️ (a) only | ⚠️ tenant via CLS | ❌ | ❌ |

### 10.2 Mandatory adapter carve-outs (normative)

Each adapter MUST publish a coverage matrix stating exactly which write, read, and query paths it intercepts. Where a path is not intercepted and would silently write plaintext or silently return wrong results, the adapter **MUST throw**, not degrade silently.

Known cases requiring an explicit throw:

- **GORM:** map-based `Updates(map[string]interface{}{...})` and single-column `Update("col", v)` bypass the serializer entirely and **write plaintext**. Verified in `callbacks/update.go`. The adapter MUST intercept or reject these.
- **Prisma:** `where.field.in: [...]`, `contains:`, and `startsWith:` are not rewritten by the path-surgery approach; the value is *encrypted instead*, silently returning zero rows with no error. `orderBy` on an encrypted field MUST throw rather than being silently dropped.
  - An adapter MUST reject `in:` over an encrypted field **unless** it rewrites the predicate to the field's declared blind index as §7.10 membership (the N index values, `OR`'d or as a single `IN`), subject to §7.5 re-verification of the candidates. An adapter that cannot guarantee the rewrite — no declared index, or a filter path its interception surface does not reach — MUST reject rather than pass the shape through. The requirement this MUST encodes is *never silently mis-serve the query*, not *never serve it correctly*: the surveyed failure was implementations encrypting the filter operands, which §7.10 already lists as supported when done through the index.
  - `contains:` and `startsWith:` remain unconditional rejections: §7.1 forbids substring and prefix matching over a blind index outright. The §7.9 prefix mechanism is not an exception to that — a declared prefix index is queried as its own index through an explicit index-typed predicate, and an adapter MUST NOT silently rewrite `startsWith:` onto one, because the rewrite is sound only when the operand length happens to equal the declared prefix length and produces silently wrong results whenever it does not.
- **TypeORM:** the dirty-check (`SubjectChangedColumnsComputer`) runs the transform, and every registered suite is randomized, so every `save()` marks every encrypted column dirty and rewrites it with a fresh envelope. The adapter MUST document this spurious-rewrite behavior — it is correct, but it inflates UPDATE volume and WAL. Equality is available only through the explicit index-typed property (L2 (a), find-options); the adapter MUST NOT claim transparent L2 (b). A deterministic AEAD suite that would lift both constraints is deliberately not in the v0.1 registry — see §13.6.
- **All ORMs:** raw SQL parameters are never encrypted by any ORM surveyed. Django and GORM decrypt raw *results*; nobody encrypts raw *parameters*. Adapters MUST document this.
- **All ORMs:** application-level caches (Django's `django.core.cache`, Hibernate's second-level cache, EF Core second-level cache interceptors, `expire_on_commit=False` session identity maps) hold **plaintext**. Adapters MUST document which caches are affected and how to exclude encrypted fields. Hibernate's `UserType.disassemble()` is the correct place to keep ciphertext in the L2 cache; `AttributeConverter` gives no such control, which is a reason to prefer `UserType`.

### 10.3 Read modes (normative)

A mode fixes two independent behaviors: what a read does with non-envelope input, and whether operations that produce ciphertext for storage are permitted. Both are specified for every mode.

| Mode | Non-envelope input on read | Ciphertext-producing operations | Intended use |
|---|---|---|---|
| `strict` | Raises `NOT_CIPHERTEXT` | Permitted | The production steady state |
| `permissive` | Returned as-is | Permitted | Migration only |
| `readonly` | Returned as-is | Raise `MODE_VIOLATION` | Read replicas, analytics jobs, rollback windows |

In both `permissive` and `readonly`, implementations MUST warn when the mode is active and SHOULD emit a metric counting plaintext reads.

The ciphertext-producing operations are `encrypt()` and `rotate()` (§11.1). `decrypt()`, `is_ciphertext()`, and `blind_index()` are permitted in every mode. `blind_index()` in particular MUST NOT be refused in `readonly`: an index value is required to *construct* a query, not to write one, and a mode that could not compute one would be unable to look anything up — which is the entire purpose of a read-only client.

*Justification, with its cost stated.* `readonly` inherits `permissive`'s pass-through behavior rather than `strict`'s raise because the mode exists for migration and rollback windows, which are exactly the windows in which unmigrated plaintext is expected to be present; a `readonly` client that raised on it would fail precisely where it is meant to be deployed.

The alternative considered was making the two axes independently configurable. Three named modes cover three of the four combinations the axes allow, and the omitted one — raise on non-envelope input *and* refuse writes — is a legitimate configuration, not an absurd one: a fully migrated production read replica would reasonably want both. This specification does not currently offer it. That is a real limitation and is recorded here rather than glossed, on the reasoning that a fourth mode is cheap to add later once a deployment demonstrates the need, whereas an orthogonal-knob configuration surface is not cheap to remove once implementations and vectors depend on it. A deployment that needs the combination should raise a specification issue rather than adding a local option, because read-mode behavior is observable in the shared error vectors and a private fourth mode would put two implementations quietly out of agreement.

---

## 11. Core library API

### 11.1 Synchronous primary API (normative)

```
encrypt(plaintext: bytes, ctx: FieldContext) -> bytes          [SYNC]
decrypt(ciphertext: bytes, ctx: FieldContext) -> bytes         [SYNC]
blind_index(plaintext: bytes, ctx: FieldContext) -> bytes      [SYNC]
is_ciphertext(value: bytes) -> bool                            [SYNC]
rotate(ciphertext: bytes, ctx: FieldContext) -> bytes          [SYNC]
```

Every implementation MUST expose all five operations synchronously, and none of them may perform network I/O.

*Justification.* See L4 in §10. Django field hooks, SQLAlchemy type processors, TypeORM transformers, Hibernate converters, Rails `ActiveModel::Type`, and Sequelize getters are all synchronous by signature. A blocking KMS call inside any of them holds a pooled database connection inside an open transaction — a 20 ms round-trip during a flush of 1,000 rows holds the connection for 20 seconds and exhausts the pool under load.

**Asynchronous companions (OPTIONAL).** An implementation MAY additionally expose asynchronous companions to these operations. The sync forms remain mandatory and primary; a companion is additive surface, never a replacement. Where companions are offered:

- They MUST produce byte-identical output to their synchronous counterparts for identical input, and MUST raise the same §9 error for the same condition. The existing vectors govern both paths; there is no separate vector family, and an implementation exposing companions MUST run the suite through both.
- An implementation MUST NOT implement a synchronous operation by blocking on its own asynchronous companion where doing so changes error or timing semantics — in particular, it MUST NOT reintroduce network I/O into the value path by that route.
- Only an adapter claiming L4 may depend on a companion. An adapter that requires one in order to function on a synchronous ORM is non-conformant, because the ORM cannot await it.

This specification deliberately does not fix the names or signatures of the companions. The portability requirement is on the synchronous five, which every adapter in every language uses; a companion is consumed only by an L4 adapter written against one specific core in one language, so pinning its shape here would constrain a surface no cross-implementation test can observe, before any implementation has demonstrated what the shape should be.

*Justification, and the cost of the sync-only reading.* `blind_index` over an Argon2id domain costs 10–100 ms per query term (§7.3), and that cost lands differently per runtime: on a threaded server it occupies one request, which is the documented and accepted price, but on a single-threaded event loop it stalls *every* concurrent request in the process. That is a materially different failure mode, and it falls hardest on exactly the async-first adapters that L4 exists to accommodate. Reading §11.1 as forbidding companions outright would leave those implementations no conformant way to stay responsive; permitting them under the constraints above costs nothing to implementations that decline. Whether the spec-minimum Argon2id parameters are viable at all in such a request path is an open engineering question, to be answered with a benchmark during implementation rather than assumed here — if the answer is no, this section is revisited as a substantive change rather than an ergonomic one.

### 11.2 Asynchronous prefetch

```
warm(contexts: Iterable<FieldContext>) -> void                 [ASYNC OK]
```

All KMS interaction happens here or in a background refresh task. Never in the value path.

### 11.3 Separation of concerns (normative)

The core MUST NOT know about rows, columns, SQL, or ORMs beyond the opaque identifiers in `FieldContext`. Adapters MUST NOT contain cryptographic code. An adapter's only permitted calls into the core are the five functions in §11.1 plus `warm`.

---

## 12. Test vectors

An implementation MUST pass the full vector suite to claim any conformance level. Vectors are JSON, in `/vectors`, and MUST cover:

- Every registered suite: encrypt/decrypt round trip with fixed key, derivation seed, nonce, and context
- Key derivation: fixed tenant DEK + `key_id` + `msg_seed` + context → expected record key
- Index-key derivation: fixed tenant index key + context → expected per-index key
- Canonical context and AAD encoding: byte-exact output for representative contexts, including `row_id` present and absent, and including index declarations whose identifier violates the §6.1 `index-id` grammar — refused at declaration time, which the vector pins as a refusal rather than as an error code, configuration validation being outside the §9 taxonomy
- Blind index: fixed key + plaintext + normalization + truncation → expected index, for both Argon2id and HMAC IDFs — including at least three vectors whose truncation length is not a multiple of 8 (the §7.2 final-byte masking is observable only there) and one multiple-of-8 control
- Blind index storage: for every blind-index vector, the exact bytes written to the database per §7.11, and the hexadecimal form where an implementation supports it — asserted as its own field, because a stored-form divergence produces no error, only an empty result set
- Commitment values
- Every error case in §9, including deliberately malformed envelopes — and for the §10.3 modes, `encrypt()` under `readonly` raising `MODE_VIOLATION` alongside the positive controls that bound it: `decrypt()` of a valid envelope, `blind_index()`, and non-envelope input, each under `readonly`
- One exception to the preceding line: `LENGTH_EXCEEDED` (§3.5) is exempt from the literal-bytes rule, a 2-GiB vector file being an unreasonable thing to put in a repository. The bound is instead verified by an implementation-level test asserting the exact threshold, and the conformance report MUST state that it was verified this way rather than by a vector
- **Cross-implementation:** ciphertext produced by implementation A decrypted by implementation B. CI MUST fail on divergence. *This is the only test that proves the specification's central claim.*
- Where an implementation exposes the optional asynchronous companions of §11.1, the entire suite MUST additionally be run through them, asserting identical bytes and identical error codes

---

## 13. Open questions

**13.1 Profile the AWS structured-encryption format, or define fresh?**
[aws/aws-database-encryption-sdk-dynamodb/specification/structured-encryption/](https://github.com/aws/aws-database-encryption-sdk-dynamodb/blob/main/specification/structured-encryption/header.md) is a normative, RFC-2119 specification written against generic "Structured Data" with Terminal fields, not DynamoDB types. Profiling it buys interoperability with a shipping implementation and reduces novelty risk. Defining fresh buys freedom from DynamoDB item semantics and AWS KMS assumptions in the key-provider model. **This is the highest-leverage unresolved decision.** Under the split gate (PRD §8) it is settled *provisionally* before code and *finally* before freeze.

> **Gate 0a provisional decision (2026-08-22) — option C: fresh envelope, AWS-aligned constructions.** [ADR-0001](adr/0001-envelope-format-source.md) carries the reasoning. [Appendix A](adr/0001-appendix-a-expressibility-mapping.md)'s clause-level mapping found the strict AWS profile fails — §6.3 dual-layer binding is not expressible in the AWS format, and per-cell embedding costs 1.4×–2.4× the fresh envelope at the §3.3 benchmark — which the ADR itself already recorded as evidence favoring C. Provisional under §4.8: it unblocks implementation and leaves the envelope-novelty question open for Gate 0b ([Q7](16-reviewer-brief.md#q7)).

**13.2 Which FIPS-approvable AEAD for the mandatory suite (`0x0001`, provisionally `0xFF01`)?**

| Candidate | Expansion | Committing | FIPS | Nonce-misuse |
|---|---|---|---|---|
| AES-256-GCM + explicit commitment | 28 B + 32 B | via commitment | **Yes** (CAVP) | Catastrophic |
| AES-256-CBC-HMAC-SHA-512 | 49–64 B | **Yes, natively** | Yes, as a composition of approved primitives | Reveals prefix equality only |
| AES-256-GCM-SIV | 28 B | No | **No** — not in the SP 800-38 series, not CAVP-testable | **Graceful** |

The registry currently names AES-256-GCM plus an explicit commitment. AES-CBC-HMAC is committing natively and is what CipherSweet's FIPSCrypto backend and JOSE's `A256CBC-HS512` use, at 20–36 bytes more per field. **Caveat:** "FIPS-approved" for the composite rests on composing two approved primitives rather than a NIST-defined AEAD mode — a validation-strategy argument, not a CAVP algorithm listing. Confirm with a testing lab before asserting it to a buyer.

> **Gate 0a provisional decision (2026-08-22) — the status quo (AES-256-GCM + explicit commitment) is retained, and is explicitly *not* decided.** [ADR-0002](adr/0002-suite-0x0001-aead.md)'s own overhead evidence concludes the arithmetic does not settle this: criterion 1 (a testing lab's written opinion on option B's composition claim) and criterion 3 (a reviewer's endorsement that the per-write-key mitigation suffices in a database setting) dominate, and neither input exists yet. Retaining A is a **deferral, not a choice** — provisional suite `0xFF01` instantiates it so vectors and cores can be built, and that identifier is expendable if Gate 0b selects B. Of every provisional decision recorded here this is the one most likely to be overturned, and §4.8's arming gate exists largely because of it.

**13.3 Should the registry reserve space for a NIST accordion mode?**
NIST announced (6 June 2025) development of cryptographic accordion modes based on HCTR2 for future SP 800-197x publications. These are wide-block, tweakable, and are the eventual standards-track answer to precisely this problem. The suite registry should be structured to absorb one.

**13.4 Non-relational stores.**
Document stores, key-value stores, and search indexes have the same problem with different mechanics. Probably out of scope for v1.0.

**13.5 Vector and embedding encryption.**
As RAG stores become PII repositories, encrypting embeddings while retaining approximate-nearest-neighbor search becomes a real gap. IronCore's distance-preserving vector encryption is the only shipping option found and it is paid. Genuinely early; noted as future work.

**13.6 Should the registry add a deterministic AEAD suite (AES-SIV, [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297))?**
TypeORM's transformer cannot support a blind-index column transparently, and its dirty-check makes randomized encryption rewrite every encrypted column on every `save()` (§10.2). A deterministic suite would let ciphertext equality work through its existing type layer and would quiet the dirty-check — at the cost of moving the §7 leakage controls (cardinality gate, truncation, per-index keys) into the suite itself, where they are harder to enforce, and of deterministic ciphertext leaking equality by construction. AES-SIV is not FIPS-approved (composition arguments over CMAC+CTR notwithstanding), and a third suite strains the "one option, maybe two" commitment of §4.1. Deferred; revisit only with concrete adapter-demand evidence.

---

## 14. Contested claims — reviewer flag list

Stated explicitly so a reviewer does not have to find them.

1. **Range-reconstruction attack severity under realistic workloads is contested.** KKNO'16, LMP'18 and GLMP'18–'19 assume uniform or well-behaved query distributions. Kamara et al.'s [LEAKER SoK (EuroS&P '22)](https://encrypto.de/papers/KKMSTY22.pdf) found IKK achieved <15% recovery on real logs while SUBGRAPH was *stronger* than reported. Bindschaedler et al. ([VLDB '18](https://eprint.iacr.org/2017/1078.pdf)) show results are sensitive to auxiliary-data modeling. **Not contested:** OPE/ORE and deterministic-on-low-entropy attacks, which require no query observation at all — which is why §4.7 and §7.6 are unconditional.
2. **Whether key destruction satisfies GDPR Art. 17 is genuinely unsettled.** EDPB Guidelines 02/2025 (v2, July 2026) ¶51 states "encrypted personal data is still personal data" and conditions the argument on algorithm strength, key non-leakage and time; ¶104 says it is "not advisable" to register personal data in encrypted form where erasure may be required. CJEU C-413/23 P (*EDPS v SRB*, Sept 2025) cuts the other way on the relativity of personal data. **This specification does not claim key destruction is erasure.**
3. **NIST IR 8547 is still an initial public draft** (Nov 2024) as of August 2026. Cite as draft. Its position that symmetric standards need no PQC transition is the basis for scoping §5 to key wrapping rather than the field cipher; CNSA 2.0 (final) supplies the hard dates.
4. **SP 800-38D is under active revision.** A second pre-draft comment period closed 31 July 2026. Fixing tags at 128 bits (§4.5) is future-proof.
5. **AES-GCM-SIV's FIPS status could change** if the accordion-mode program delivers an approved misuse-resistant mode. See 13.3.
6. **Beacon-length formulas (§7.4) are AWS engineering heuristics**, not peer-reviewed leakage bounds. AWS hedges on them explicitly. Treat as a starting point requiring dataset-specific evaluation.
7. **The HHS breach safe harbor's technical basis is stale.** It points at NIST SP 800-111 (2007, *Guide to Storage Encryption Technologies for End User Devices* — scoped to end-user devices, not servers) and says "FIPS 140-2 validated," while all FIPS 140-2 certificates move to the CMVP Historical List on **22 September 2026**. This is a weakness in the cited authority, not in the design, and should be stated rather than papered over.

---

## 15. Normative references

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) — requirement keywords
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) — GCM/GMAC, §8 IV uniqueness, §8.3 invocation limits
- [NIST SP 800-57 Part 1 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) — key management; §5.2 single-purpose keys, §5.3.6 Table 1 cryptoperiods, §8.2.3.2 key-update prohibition, §8.3.4 key destruction
- [NIST SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final) / [SP 800-108 Rev. 1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) — key derivation
- [NIST SP 800-88 Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf) — media sanitization; §3.1.2, §3.2.2 cryptographic erase preconditions
- [NIST CSWP 39](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.39.pdf) — crypto agility; §3.2.3 downgrade, §5.1 data-at-rest algorithm replacement
- [FIPS 140-3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf) and the [CMVP transition schedule](https://csrc.nist.gov/projects/fips-140-3-transition-effort)
- [RFC 7518 §5.2](https://www.rfc-editor.org/rfc/rfc7518.html) — AAD length encoding for encrypt-then-MAC
- [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html) — AES-GCM-SIV
- [CNSA 2.0](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF) — AES-256 requirement and transition dates

## 16. Informative references

[AWS Database Encryption SDK structured-encryption spec](https://github.com/aws/aws-database-encryption-sdk-dynamodb/blob/main/specification/structured-encryption/header.md) · [AWS beacons](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/beacons.html) and [beacon length](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/choosing-beacon-length.html) · [AWS encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html) · [AWS external key stores](https://docs.aws.amazon.com/kms/latest/developerguide/keystore-external.html) · [AWS-2025-032](https://aws.amazon.com/security/security-bulletins/AWS-2025-032/) · [Tink wire format](https://developers.google.com/tink/wire-format) and [bind ciphertext to context](https://developers.google.com/tink/bind-ciphertext) · [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit) · [Rails Active Record Encryption](https://edgeguides.rubyonrails.org/active_record_encryption.html) · [CipherSweet](https://ciphersweet.paragonie.com/) · [ankane/blind_index](https://github.com/ankane/blind_index) · [Always Encrypted](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-database-engine) · [Naveed–Kamara–Wright CCS'15](https://cs.brown.edu/people/seny/pubs/edb.pdf) · [Grubbs et al. S&P'17](https://www.ieee-security.org/TC/SP2017/papers/433.pdf) · [Why Your Encrypted Database Is Not Secure, HotOS'17](https://eprint.iacr.org/2017/468) · [MongoDB QE analysis, USENIX'23](https://www.usenix.org/system/files/usenixsecurity23-gui_1.pdf) · [LEAKER SoK, EuroS&P'22](https://encrypto.de/papers/KKMSTY22.pdf) · [Partitioning Oracle Attacks, USENIX'21](https://www.usenix.org/system/files/sec21-len.pdf) · [Langley on crypto agility](https://www.imperialviolet.org/2016/05/16/agility.html) · [Soatok on versioned protocols](https://soatok.blog/2022/08/20/cryptographic-agility-and-superior-alternatives/) · [EDPB Guidelines 02/2025 v2](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf)
