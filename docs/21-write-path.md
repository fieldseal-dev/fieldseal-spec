# The Write Path — one encrypted field, from save() to the database

**Date:** 2026-09-19 · **Status:** Draft 1 · **Purpose:** a picture of what the specification requires to happen when an application writes one encrypted, indexed field, drawn from the Python core and the Django adapter as they stand at 0.1.3. It is a reading aid for the specification, not a part of it.

**This document is informative.** Every step below cites the section of [`docs/02-spec-v0.1.md`](02-spec-v0.1.md) that requires it. **Where this document and the specification disagree, the specification is right and this one is wrong** — a diagram is a second copy of the text, and a second copy drifts. The specification has not been independently reviewed, every registered suite is provisional (§4.8), and nothing here is an invitation to adopt it.

![Sequence diagram: the Django app calls save; the fieldseal_django field asks the fieldseal core to encrypt, the core takes the tenant DEK from the key provider's cache and returns an envelope; the index field asks the core for a blind index, the core takes the separate index key and returns a truncated index; the adapter writes envelope and index in one INSERT or UPDATE.](figures/write-path.svg)

[Open the diagram at full size.](figures/write-path.svg)

---

## 1. The steps

The diagram follows one model with one encrypted field (`ssn`) and one blind index over it. Red dashed arrows are key requests; grey dashed arrows are returns.

### Encrypt — `get_db_prep_value`

1. **The application saves.** `model.save()` reaches the encrypted field's `get_db_prep_value`, which renders the value to bytes by the rules of [§3.6](02-spec-v0.1.md#36-plaintext-rendering-of-logical-types-normative) and passes them to the core with the field's context — table and column identifiers that survive a rename, tenant, purpose ([§6.1](02-spec-v0.1.md#61-what-context-is)).
2. **The core refuses before it touches a key.** A read-only client, an unarmed provisional suite ([§4.8](02-spec-v0.1.md#48-provisional-suites-normative)) and an over-length value ([§3.5](02-spec-v0.1.md#35-plaintext-length-bound-normative)) are all rejected here, before any key is fetched ([§9](02-spec-v0.1.md#9-errors)). The specification does not rank the three; the order is the core's.
3. **Fresh randomness, every time.** The core draws a 32-byte `msg_seed` and a nonce from the CSPRNG. This happens on every write, UPDATEs included; neither is derived from the row, counted, or stored anywhere but the envelope ([§3.1](02-spec-v0.1.md#31-layout), [§4.4](02-spec-v0.1.md#44-nonce-policy-normative)).
4. **The key provider answers from its cache.** `encryption_key(ctx)` ([§8](02-spec-v0.1.md#8-key-provider-interface)) returns the tenant DEK and its `key_id`. In `EnvelopeKeyProvider`, the production provider, this is a cache read and nothing else: the KMS is reached only by `warm()`, before the request, and a key that is not cached is `KEY_UNAVAILABLE` — the value path never blocks on the network ([§5.5](02-spec-v0.1.md#55-dek-caching-normative), [§8.1](02-spec-v0.1.md#81-kms-availability-is-a-hard-dependency-normative)).
5. **A key that is used once.** The record key is derived from the DEK, `key_id ‖ msg_seed` and the canonical context ([§5.3](02-spec-v0.1.md#53-record-key-derivation-normative)). Because `msg_seed` is fresh, no derived key ever encrypts a second value. The context is bound twice: as the derivation's `info`, and in the AEAD's additional data ([§6.3](02-spec-v0.1.md#63-dual-layer-binding-normative)).
6. **The envelope comes back.** Header, nonce, ciphertext, tag and a key commitment derived from the record key ([§4.6](02-spec-v0.1.md#46-key-commitment-normative)). Under suite `0xFF01` that is 111 bytes more than the plaintext ([§3.3](02-spec-v0.1.md#33-column-storage-type-normative)).

### Index — `pre_save`

7. **The index field reads the plaintext.** `pre_save` is the only Django field hook that receives the model instance, so the index field reads its sibling's plaintext there and asks the core for a blind index ([§7.2](02-spec-v0.1.md#72-construction-normative)).
8. **A different key.** The same `encryption_key` call, with an index purpose, returns the tenant *index* key — a sibling of the DEK under the KEK, never the DEK and never derived from it ([§5.2](02-spec-v0.1.md#52-tenant-dek-granularity-normative)). Rotating data keys therefore never invalidates an index.
9. **Normalize, derive, truncate.** The value is normalized as the column declares, run through the declared index function — Argon2id for enumerable domains ([§7.3](02-spec-v0.1.md#73-index-derivation-function-selection-normative)) — and truncated so that collisions are certain by design ([§7.4](02-spec-v0.1.md#74-truncation-length-normative)).

### Store

10. **One statement.** Django writes the envelope and the index in the same INSERT or UPDATE — binary columns by default, base64 text if the field is declared that way ([§3.3](02-spec-v0.1.md#33-column-storage-type-normative), [§7.11](02-spec-v0.1.md#711-index-column-storage-type-normative)). The database never sees the plaintext, the DEK, or the index key.

## 2. What the diagram leaves out

- **The order of the two phases is Django's, not the specification's.** On an INSERT, Django prepares one field completely before the next, in declaration order; on an UPDATE, every field's `pre_save` runs before any value is prepared. The diagram draws the INSERT order with the encrypted field declared first. The two results do not depend on each other, so the order does not change what is written.
- **`warm()`.** Filling the cache — the KMS unwrapping the tenant DEK and index key — happens before the request and is not drawn ([§5.5](02-spec-v0.1.md#55-dek-caching-normative), [§8](02-spec-v0.1.md#8-key-provider-interface)).
- **Reads and queries.** Decryption, and the equality query in which the blind index selects candidates that are then decrypted and re-verified, are separate flows. A blind index filters; it never answers ([§7.5](02-spec-v0.1.md#75-application-side-re-verification-normative)).
- **What the adapter refuses.** Writes that Django would compute in SQL — `update(ssn=F(...))` — never reach the core; the adapter raises instead ([`docs/12-adapter-django.md`](12-adapter-django.md)).

## 3. How the figure is made

The diagram is drawn with [Archify](https://github.com/tt-a1i/archify) from [`figures/write-path.sequence.json`](figures/write-path.sequence.json). Archify renders an interactive HTML page; [`tools/figures/svg_from_archify.py`](../tools/figures/svg_from_archify.py) extracts the diagram from that page as a static SVG with no script, which is what is committed and what the site serves. To change the figure, edit the JSON, render it, and re-extract — the commands are in [`tools/figures/README.md`](../tools/figures/README.md). Do not edit the SVG by hand.
