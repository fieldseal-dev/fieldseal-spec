# ADR-0001 Appendix A — Expressibility mapping: spec §3–§6 onto the AWS structured-encryption format

**Date:** 2026-08-08 · **Status:** first-pass evidence for ADR-0001 (the "open analysis task" named in the ADR's option A). This appendix answers decision criterion 1 factually; it does **not** close the ADR — criterion 2's reviewer opinion is still required.

**Sources.** The AWS Database Encryption SDK specification, repository `aws/aws-database-encryption-sdk-dynamodb`, directory `specification/structured-encryption/` — files `header.md`, `footer.md`, `encrypt-structure.md`, `encrypt-path-structure.md` — **main branch as retrieved 2026-08-08** via web fetch with model-assisted summarization. Quoted phrases below are from those retrievals. **[VERIFY before ADR closure: pin a commit hash, re-read the four files directly (not summarized), and re-check every byte count in §6 against the pinned text.]**

---

## 1. The AWS format in one page

Scope: the format is **record-scoped**. "The header is metadata stored on encrypted structured data. It exists once per encrypted record, not per individual field." The footer likewise: "per-record, not per-field."

**Header** = partial header ‖ 32-byte header commitment. Partial header, in order: Format Version (1 B, `0x01`/`0x02`), Format Flavor (1 B — the second byte of the algorithm-suite ID), Message ID (32 B random), Encrypt Legend (2-byte length + one byte per field: `0x65` encrypted-and-signed / `0x73` signed-only / `0x63` signed-and-in-context), Encryption Context (2-byte pair count; UTF-8 key–value pairs, "sorted, by key, in ascending order according to the UTF-8 encoded binary value"), Encrypted Data Keys (1-byte count; each EDK = length-prefixed provider ID, provider info, and wrapped key material). The Header Commitment is "a 32-byte HMAC-SHA384 truncation calculated over the partial header using a commitment key derived via HKDF from the data key and message ID."

**Per-field encryption.** `FieldRootKey = HKDF(ikm = plaintext data key, no salt, info = "AWS_DBE_DERIVE_KEY" ‖ MessageID)`. Each field's key material is drawn deterministically from that root: `FieldKeyNonce(offset)` = ASCII `"AwsDbeField"` ‖ `0x2C` ‖ u32(3·offset) (16 B); the FieldKey is "the first 44 bytes of the aes256ctr_stream of the FieldRootKey" at that nonce — first 32 B = cipher key, remaining 12 B = the AEAD nonce. `offset` is the field's zero-based position among the ENCRYPT_AND_SIGN fields sorted by canonical path. Per-field AAD = the field's **canonical path** (built from table and attribute names). Encrypted terminal layout: type marker `0xFFFF`, then value = original 2-byte TypeID ‖ ciphertext ‖ tag. **No per-field nonce, key reference, version, algorithm identifier, or commitment is stored in the field bytes.**

**Footer** (a special terminal on the record): Recipient Tags (48 B HMAC per EDK) and, when the flavor is `0x01`, a 96-byte ECDSA-P384 signature; both computed over "the SHA384 of the canonical form of the record" — serialized header, encryption context, and every signed field in lexicographic canonical-path order with lengths, `ENCRYPTED`/`PLAINTEXT` literals, and TypeIDs.

## 2. The structural finding first

**F1 — record-scoped vs cell-scoped.** Fieldseal's unit of protection is a single database cell whose bytes are fully self-describing (§3.1) and self-detectable (§3.4). In the AWS format, everything that makes ciphertext self-describing — version, suite, key reference, message ID, commitment — lives in the *record* header attribute, and field bytes alone are unrecognizable and undecryptable. Profiling the AWS format for Fieldseal's cell-level model therefore forces the **one-Terminal-record embedding**: every cell carries a complete header *and* footer. All verdicts and arithmetic below assume that embedding, because nothing weaker satisfies §3.1/§3.4.

## 3. Clause-level mapping

Verdicts: **E** = expressible via a profile's fixed choices · **Ed** = expressible with profile discipline (we control the inputs the AWS spec leaves to the caller) · **D** = requires deviating from the AWS format or rewording Fieldseal normative text · **X** = not expressible without restructuring.

| Spec clause | Requirement | AWS construct | Verdict | Notes |
|---|---|---|---|---|
| §3.1 `fmt_ver` | 1-byte envelope version | Format Version (1 B) | **E** | Semantics differ (AWS `0x02` signals context-included fields) but a profile pins one value |
| §3.1 `suite_id` | 2-byte frozen-suite ID | Format Flavor (1 B, second byte of suite ID) | **Ed** | Profile maps each Fieldseal suite to one (Version, Flavor) pair; the ID space is AWS's, not ours — see criterion 4 |
| §3.1 `key_id` | 16-byte **opaque identifier**; key material lives with the provider | Encrypted Data Keys — length-prefixed provider ID/info **plus wrapped key material inline** | **D** | Semantic mismatch: EDKs carry envelope-encrypted keys; Fieldseal §5 deliberately stores only an identifier (DEKs cached per tenant, wrapped blobs in a key table). A profile must either carry a wrapped DEK per cell (bloat + contradicts §5.2 granularity) or define a provider whose EDK "ciphertext" is empty and whose provider-info is the key_id — a reinterpretation, not a subset |
| §3.1 `msg_seed` | 32-byte per-write CSPRNG seed feeding key derivation | Message ID (32 B) + `AWS_DBE_DERIVE_KEY` HKDF | **E** | Direct precedent — §3.1 already cites it. Derivation formula differs (next rows) |
| §3.1 `nonce` | Stored per-envelope, fresh CSPRNG | Not stored; deterministic from FieldRootKey keystream at offset-derived FieldKeyNonce | **D** | See §4.4 row |
| §3.1 `tag` | ≥16 B AEAD tag | AES-GCM tag in encrypted terminal | **E** | |
| §3.1 `commitment` | 32 B key commitment | Header Commitment (32 B, HMAC-SHA384 truncation) | **E** | Adoptable construction — feeds gap G1 regardless of this ADR (finding F7) |
| §3.2 header auth | Key-selection fields "MUST be included in the AEAD's additional authenticated data" | Per-field AAD is **canonical path only**; header fields are protected by the header commitment and footer tags/signature instead | **D** | The protection *exists* but not where §3.2 mandates it. Profiling requires rewording §3.2 to an equivalent-protection form — a normative weakening a reviewer must bless (finding F3) |
| §3.3 storage | Binary column MUST; base64 MAY with documented overhead | Bytes are bytes | **E** | Overhead table changes — §6 below |
| §3.4 `is_ciphertext` | Cell bytes alone recognizable; no trial decryption | Field bytes carry only `0xFFFF` + TypeID | **X** without F1's embedding; **E** with it | The one-Terminal-record embedding is load-bearing for §3.4 |
| §4.1 one frozen suite | No per-algorithm fields, no caller-settable alg | Algorithm suite fixed per record; no negotiation | **E** | Aligned philosophy |
| §4.2 registry | Fieldseal-defined suite table | AWS-defined suite/flavor space | **D** | Registry sovereignty: a profile pins AWS suite IDs at a pinned spec version; AWS "evolving their format unilaterally" is ADR criterion 4, and "tracks AWS main is not a spec" |
| §4.3 allow-list | Decrypt-side configured allow-list | Implementation policy, format-neutral | **E** | |
| §4.4 nonce policy | "the nonce MUST be freshly generated from a CSPRNG… MUST NOT be derived" | Per-field nonces are **deterministic** (offset-derived from the keystream) | **D** | Letter violated, spirit preserved: FieldRootKey is fresh per record write (fresh Message ID), so key+nonce pairs never repeat — the same *structural* argument §4.4 itself makes for per-write keys. Profiling requires §4.4 to be reworded around key+nonce-pair freshness (finding F4); reviewer sign-off required |
| §4.5 tag ≥128 bits | | AES-GCM full tag | **E** | |
| §4.6 commitment mandatory | | Header Commitment always present | **E** | |
| §5.1–§5.2 hierarchy, tenant DEK boundary | KEK → tenant DEK (+ sibling index key) | CMM/keyring model; hierarchical keyring approximates tenant DEK + cache | **Ed** | Conceptual fit; index-key siblings are out of the structured-encryption format entirely (searchable encryption is a separate AWS component with HMAC-SHA384 beacons only — no memory-hard option, so §7 stays Fieldseal-defined under every ADR outcome) |
| §5.3 record-key derivation | `HKDF(ikm=dek, salt=key_id‖msg_seed, info=canonical_context)` | `HKDF(ikm=data key, **no salt**, info="AWS_DBE_DERIVE_KEY"‖MessageID)` — context **not** in the KDF | **X** as a profile | Adopting AWS's derivation removes context from the KDF; keeping Fieldseal's is not the AWS format. This is one half of the §6.3 failure (F2) |
| §5.4 no key-update chaining | | Fresh derivation per record; no chaining | **E** | |
| §6.1 UUID surrogates | Bind to immutable surrogates, never SQL names | Canonical path is built from table/attribute **names** | **Ed** | We control the inputs in our adapters — feed UUIDs where AWS feeds names. Discipline, not format |
| §6.2 canonical encoding | u64be length-prefixed field encoding | AWS's own canonicalization (2-byte lengths, UTF-8-sorted context pairs, canonical paths) | **D** | Profiling replaces §6.2 wholesale with AWS canonicalization — also length-delimited, so the injectivity goal survives, but G4's null-encoding question must then be re-answered inside *their* encoding |
| §6.3 dual-layer binding | Context MUST be KDF info **and** AAD | Context is stored/signed (header + footer) but enters neither the field KDF nor (beyond canonical path) the field AAD | **X** | The clearest single expressibility failure (F2). A context mismatch in the AWS format is caught at header/footer verification, not as a wrong derived key — a different, weaker-at-the-cell failure mode than §6.3 mandates |
| §6.4 `row_id` optional | | An encryption-context pair | **E** | |
| §6.5 AAD contains nothing secret | | Identical rule — AWS's own CloudTrail warning is §6.5's citation | **E** | |
| §6.6 record-level MAC (RECOMMENDED) | Detect whole-record tampering incl. field deletion | The footer **is** this, verbatim — §6.6 already cites it | **E** | The strongest pro-profile argument in the mapping |

## 4. Findings

- **F1** — Record-vs-cell scope forces a full header+footer per cell (one-Terminal-record embedding); without it §3.1/§3.4 are unsatisfiable.
- **F2** — §6.3 dual-layer context binding is **not expressible**: the AWS field KDF takes no context and the field AAD is canonical path only. This is a normative MUST that profiling cannot satisfy without deviating from the AWS derivation.
- **F3** — §3.2's "key-selection fields in the AEAD AAD" is satisfied only by an equivalent-protection argument (commitment + footer), i.e., a rewording of Fieldseal normative text.
- **F4** — §4.4's fresh-CSPRNG-nonce letter is violated by AWS's deterministic offset nonces; the safety argument transposes to key+nonce-pair freshness, but that too is a rewording reviewers must bless.
- **F5** — `key_id`-vs-EDK semantic mismatch: identifier-only vs wrapped-material-inline; a profile must reinterpret the EDK fields.
- **F6** — The embedding's overhead exceeds the fresh envelope's at every configuration (§6 below).
- **F7** — Independently adoptable constructions, whatever the decision: the header-commitment construction (→ issue G1), the Message-ID per-write derivation (already cited in §3.1), and the footer as §6.6's model. These transfer under option C without any format adoption.

## 5. What §7 (blind indexes) adds — out of the §3–§6 task's scope, noted for completeness

AWS searchable encryption (beacons) is HMAC-SHA384-truncation only; §7.3's Argon2id requirement for enumerable domains has no AWS counterpart. Every ADR outcome leaves §7 Fieldseal-defined; the beacon-length band is already §7.4's cited source.

## 6. Overhead arithmetic (decision criterion 3) — first pass, [VERIFY] against pinned text

One-Terminal-record embedding, unsigned flavor (no 96 B signature), single EDK modeled minimally as provider ID `"fs"` (2 B), provider info = 16-byte key_id, empty wrapped-key field:

| Component | Bytes | Composition |
|---|---|---|
| Partial header, empty encryption context | 64 | 1 ver + 1 flavor + 32 MessageID + 3 legend (2-B len + `0x65`) + 2 context count + 25 EDK section (1 count + 4+18+2+... = 24 per EDK) |
| Header commitment | 32 | |
| Footer | 48 | one recipient tag; no signature |
| Encrypted terminal overhead | 20 | 2 (`0xFFFF`) + 2 (orig TypeID) + 16 (tag) |
| **Total fixed, context out-of-band** | **164** | vs. Fieldseal's 111 (§3.3) |
| Encryption-context pairs carrying §6 context in-format (tenant ≈21, table_uuid hex ≈38, column_uuid hex ≈38, purpose ≈12) | ≈ +109 | **≈ 273 total** |

At the §3.3 benchmark (9-byte SSN): **173–282 bytes vs. 120** — roughly **1.4×–2.4×** the fresh envelope. Note the structural asymmetry behind the range: Fieldseal *reconstructs* context at read time (stores none of it); the AWS format *stores* the encryption context in the header, and its footer canonicalization signs the stored copy — carrying §6's binding in-format costs the upper end of the range, while the lower end leaves tenant/purpose binding with no in-format home at all.

## 7. Reading against the ADR's decision criteria

1. **Expressibility without weakening — fails for a strict profile.** F2 is a hard X; F3/F4 each require rewording a Fieldseal MUST; F5 requires reinterpreting AWS fields. A "profile" carrying that many deviations is option C wearing option A's name.
2. **Novelty-surface reduction — partially available without profiling.** F7's constructions can be adopted piecemeal with case-by-case citations, which is exactly option C's definition.
3. **Overhead honesty — worse under A**, 1.4×–2.4× at the benchmark (§6).
4. **Unilateral-evolution risk — real**: Version/Flavor/suite space is AWS's; a profile needs a pinned-commit statement and a divergence policy.

**Net:** this first pass supports option C (fresh envelope, AWS-aligned constructions) over option A, and sharpens option C into a concrete work list: adopt the commitment construction (G1), keep the Message-ID precedent citation (§3.1), and model §6.6 on the footer. The ADR remains OPEN: criterion 2's other half — a cryptographic reviewer's opinion on whether the *fresh envelope itself* carries acceptable novelty risk — is evidence this appendix cannot supply.

## 8. Open verification items

1. Pin `aws/aws-database-encryption-sdk-dynamodb` at a commit; re-read the four spec files directly and re-verify every quoted phrase and byte count above (the retrieval was model-summarized).
2. Confirm the EDK minimum serialization (whether a zero-length wrapped-key field is legal) — it decides F5's "reinterpretation" cost and the §6 lower bound.
3. Confirm whether AWS's `0x02` version (context-included fields) changes the context-storage arithmetic.
4. `decrypt-path-structure.md` and `resolve-auth-actions.md` were not reviewed; check they do not contradict the per-field description taken from `encrypt-path-structure.md`.
