# The Read Path — one encrypted field, from the row to a value

**Date:** 2026-09-19 · **Status:** Draft 1 · **Purpose:** a picture of what the specification requires to happen when an application reads one encrypted field, drawn from the Python core and the Django adapter as they stand at 0.1.3. It is a reading aid for the specification, not a part of it. Its companions are [the write path](21-write-path.md) and [the equality query](23-query-path.md).

**This document is informative.** Every step below cites the section of [`docs/02-spec-v0.1.md`](02-spec-v0.1.md) that requires it. **Where this document and the specification disagree, the specification is right and this one is wrong.** The specification has not been independently reviewed, every registered suite is provisional (§4.8), and nothing here is an invitation to adopt it.

![Workflow: from_db_value hands the envelope bytes to the fieldseal core, which recognizes the envelope, authorizes its suite, asks the key provider for candidate keys, checks the key commitment and opens the AEAD; the adapter turns the plaintext back into a value. Each of the five gates has its own error: NOT_CIPHERTEXT, SUITE_NOT_ALLOWED or LENGTH_EXCEEDED, KEY_UNAVAILABLE, COMMITMENT_INVALID, TAG_INVALID.](figures/read-path.svg)

[Open the diagram at full size.](figures/read-path.svg)

---

## 1. The steps

A read is a line of gates, and every gate that fails has its own error. The specification forbids collapsing them into one "decryption failed" ([§9](02-spec-v0.1.md#9-errors)): each one sends the operator somewhere different.

1. **The row arrives.** Django loads the row and hands the column's bytes to the encrypted field's `from_db_value`, which passes them to the core's `decrypt` with the field's context ([§6.1](02-spec-v0.1.md#61-what-context-is)). A NULL stays NULL and never reaches the core.
2. **Recognize.** The core reads the header and decides which of three things it holds ([§3.4](02-spec-v0.1.md#34-detection)): an envelope; input under the reserved format version `0x02`, which raises `UNKNOWN_FORMAT_VERSION` in every mode; or something else. Something else is unmigrated plaintext as far as the core can tell. The read mode decides what happens to it ([§10.3](02-spec-v0.1.md#103-read-modes-normative)): `strict` raises `NOT_CIPHERTEXT`; `permissive` and `readonly` return it as-is and count it.
3. **Authorize.** An envelope whose length implies a plaintext over the bound is refused as `LENGTH_EXCEEDED` ([§3.5](02-spec-v0.1.md#35-plaintext-length-bound-normative)), and one whose suite is not on the decrypt allow-list as `SUITE_NOT_ALLOWED` ([§4.3](02-spec-v0.1.md#43-suite-allow-listing-normative)). The allow-list decides *authorization*, never *recognition*: a retired suite is still recognized as ciphertext, so it can never be mistaken for plaintext and re-encrypted. The suite used from here on is the one in the header, not the client's write suite — older envelopes stay readable during rotation.
4. **Candidate keys.** `decryption_keys(header)` ([§8](02-spec-v0.1.md#8-key-provider-interface)) returns every currently valid key version, in preference order ([§5.6](02-spec-v0.1.md#56-key-versions-normative)); the core's provider puts the version the header names first. In `EnvelopeKeyProvider` they come from the cache alone: a version that is not cached is not a candidate, and no candidates at all is `KEY_UNAVAILABLE`. No read waits on the KMS, so on this path the two degradation modes of [§8.1](02-spec-v0.1.md#81-kms-availability-is-a-hard-dependency-normative) behave the same.
5. **Commitment, before anything is opened.** For each candidate the core derives the record key ([§5.3](02-spec-v0.1.md#53-record-key-derivation-normative)), recomputes the key commitment and compares it with the envelope's in constant time ([§4.6](02-spec-v0.1.md#46-key-commitment-normative)). Only a key that commits may open the ciphertext. If none does, the result is `COMMITMENT_INVALID`.
6. **Open.** The committed key opens the AEAD with `AAD(header, ctx)` ([§6.3](02-spec-v0.1.md#63-dual-layer-binding-normative)). A failure here, after the key and context are proven, can only be damage to the ciphertext or tag: `TAG_INVALID`.
7. **Back to a value.** The adapter turns the plaintext bytes back into the field's type by the rules of [§3.6](02-spec-v0.1.md#36-plaintext-rendering-of-logical-types-normative).

## 2. What the diagram leaves out

- **`AAD_MISMATCH` never appears, and that is deliberate.** The context is bound into the key derivation as well as the AAD ([§6.3](02-spec-v0.1.md#63-dual-layer-binding-normative)), so a wrong context derives a wrong record key and fails the commitment check — indistinguishable from a wrong key. The core says so in its message rather than guess. How the §9 errors are ordered on this path is still provisional ([§9](02-spec-v0.1.md#9-errors), G5).
- **The permissive pass-through.** In `permissive` and `readonly`, non-envelope input skips every later gate and goes straight back to the adapter. The diagram draws only the `strict` exit.
- **Filling the cache.** As on the write path, the KMS is reached only by `warm()`, before the request.

## 3. How the figure is made

As for [the write path](21-write-path.md#3-how-the-figure-is-made): drawn with [Archify](https://github.com/tt-a1i/archify) from [`figures/read-path.workflow.json`](figures/read-path.workflow.json), extracted to a static SVG by [`tools/figures/svg_from_archify.py`](../tools/figures/svg_from_archify.py). Commands are in [`tools/figures/README.md`](../tools/figures/README.md). Do not edit the SVG by hand.
