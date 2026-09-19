# Keys — the hierarchy, and the life of a key version

**Date:** 2026-09-19 · **Status:** Draft 1 · **Purpose:** two pictures of the specification's key model: which keys exist and how each is made from the one above it, and what happens to one version of a tenant's keys from creation to destruction. Drawn from the specification and the two cores as they stand at 0.1.3. It is a reading aid for the specification, not a part of it. The paths that use these keys are [the write path](21-write-path.md), [the read path](22-read-path.md) and [the equality query](23-query-path.md).

**This document is informative.** Every statement below cites the section of [`docs/02-spec-v0.1.md`](02-spec-v0.1.md) that requires it. **Where this document and the specification disagree, the specification is right and this one is wrong.** The specification has not been independently reviewed, every registered suite is provisional (§4.8), and nothing here is an invitation to adopt it.

**Much of the lifecycle is not built yet, and this page says which part.** Both cores implement key versions, the active version, the cache and `rotate()`. The re-encryption sweep that moves data off an old version (`tools/backfill`, designed in [`docs/15-tooling.md`](15-tooling.md) §1) is not implemented, and neither core offers a key-destruction API. The lifecycle below is what the specification requires of them when they exist; §3 lists what exists today.

---

## 1. The hierarchy

![Key hierarchy: the root KEK in the KMS wraps two sibling tenant keys, the tenant DEK and the tenant index key, both held unwrapped in the cache; the DEK derives a single-use record key per write, which seals the envelope; the index key derives a blind-index key per index, which produces the truncated blind index; envelope and blind index are stored in the row.](figures/key-hierarchy.svg)

[Open the diagram at full size.](figures/key-hierarchy.svg)

1. **The root KEK never leaves the KMS.** It wraps the tenant keys; the deployment stores them wrapped ([§5.1](02-spec-v0.1.md#51-structure-normative)).
2. **Two tenant keys, siblings.** The tenant DEK encrypts; the tenant index key indexes. The index key is its own key under the KEK and is never derived from the DEK ([§5.2](02-spec-v0.1.md#52-tenant-dek-granularity-normative)). That is what lets data keys rotate without invalidating a single index. It is also why crypto-shredding a tenant must destroy both: an index value is a keyed hash of the plaintext and outlives the DEK.
3. **The tenant is the blast radius.** The tenant DEK is the crypto-shredding unit, and a single global DEK must not be the default. A deployment without tenants still has to define a DEK scope ([§5.2](02-spec-v0.1.md#52-tenant-dek-granularity-normative)).
4. **Unwrapped only by `warm()`, held only in the cache.** `warm()` asks the KMS to unwrap every version of a scope's keys into the in-memory cache. That cache evicts on age and on use count, at most 2³² uses, and zeroes what it evicts ([§5.5](02-spec-v0.1.md#55-dek-caching-normative)). Both cores keep cached keys in mutable buffers so that they can. Neither has `mlock`, so swap and core dumps remain a documented residual risk.
5. **Per-write and per-index keys are derived, never stored.** Each write derives a record key from the DEK, `key_id ‖ msg_seed` and the context ([§5.3](02-spec-v0.1.md#53-record-key-derivation-normative)); each (table, column, index) derives its own blind-index key from the index key ([§7.2](02-spec-v0.1.md#72-construction-normative)). The envelope carries the `key_id` that names which version to derive from again on read.

## 2. The life of a key version

![Lifecycle of one key version: New version, Active for write, Decrypt-only once a newer version is active, Re-encrypting while a sweep moves envelopes to the active version, Unreferenced when none remain; then Scheduled for destruction, which can be cancelled back to Unreferenced, and finally Destroyed. Destroying a version while it is still Decrypt-only leads to Rows lost.](figures/key-lifecycle.svg)

[Open the diagram at full size.](figures/key-lifecycle.svg)

1. **New version.** A new version of a tenant's keys is generated fresh and registered wrapped. It is never computed from the old one: deriving a new key version from the value of a previous one is forbidden ([§5.4](02-spec-v0.1.md#54-key-update-chaining-is-forbidden-normative)).
2. **Active for write.** Exactly one version is active for write, and every encryption uses it ([§5.6](02-spec-v0.1.md#56-key-versions-normative)). The Python core's in-memory key directory refuses, at startup, a key set whose active version is not one of its versions.
3. **Decrypt-only.** When a newer version becomes active, the old one stays decryptable. Every read tries each cached, currently valid version ([§5.6](02-spec-v0.1.md#56-key-versions-normative); [the read path](22-read-path.md)). Without this, rotation is a hard cutover and an outage.
4. **Re-encrypting.** A full background sweep reads each envelope whose header names a stale `key_id` or suite and calls `rotate()`, which decrypts and re-encrypts it under the active version ([§5.8](02-spec-v0.1.md#58-rotation-strategies), [§11.1](02-spec-v0.1.md#111-synchronous-primary-api-normative)). The sweep must be resumable, rate-limited and idempotent. It is also how a suite is retired ([§5.9](02-spec-v0.1.md#59-re-encryption-is-the-crypto-agility-mechanism-normative)).
5. **Unreferenced.** When no stored envelope names the version any more, it can be retired. Only a full sweep gets here. Lazy re-encryption on read never does, because cold rows are never read, so it never permits destroying an old key on its own ([§5.8](02-spec-v0.1.md#58-rotation-strategies)).
6. **Scheduled, then destroyed.** Destroying key material is unrecoverable data loss. Any destruction API must have a configurable delay window and an explicit confirmation step ([§8.2](02-spec-v0.1.md#82-key-destruction-is-unrecoverable-data-loss)). Cancelling within the window returns the version to Unreferenced.
7. **Rows lost.** Destroying a version that envelopes still name makes those rows permanently unreadable: `KEY_UNAVAILABLE` on every read, with no way back. This is the failure the whole sequence above exists to prevent.

### What rotation is not

- **Re-wrapping under a new KEK** replaces the wrapped blobs, in seconds to minutes. It is the required default posture. It does not limit how much data sits under any one DEK, so it moves nothing along this lifecycle ([§5.8](02-spec-v0.1.md#58-rotation-strategies)).
- **Rotating an index key** is a separate operation. It needs the index column rebuilt, because index parameters are fixed after the first write ([§7.8](02-spec-v0.1.md#78-immutability-after-first-write-normative)). Data-key rotation at any tier leaves every index valid.
- **Rotation on a schedule** is guidance, not a mandate. SP 800-57's cryptoperiods are non-binding, and this specification does not claim NIST requires annual rotation ([§5.7](02-spec-v0.1.md#57-cryptoperiods)).

## 3. What exists today

| Lifecycle part | Status at 0.1.3 |
|---|---|
| Key versions, one active version, lookup by `key_id` | In both cores (`KeyDirectory`, `EnvelopeKeyProvider`) |
| `warm()` and the §5.5 cache | In both cores |
| `rotate()` — one envelope to the active version | In both cores |
| The re-encryption sweep | Not built: `tools/backfill` is a placeholder; [`docs/15-tooling.md`](15-tooling.md) §1 is its design |
| Proving a version unreferenced | Not built: would be part of the sweep |
| Key destruction | Not offered by either core; §8.2 constrains any that is added |

## 4. How the figures are made

As for [the write path](21-write-path.md#3-how-the-figure-is-made): drawn with [Archify](https://github.com/tt-a1i/archify) from [`figures/key-hierarchy.architecture.json`](figures/key-hierarchy.architecture.json) and [`figures/key-lifecycle.lifecycle.json`](figures/key-lifecycle.lifecycle.json), extracted to static SVGs by [`tools/figures/svg_from_archify.py`](../tools/figures/svg_from_archify.py). Commands are in [`tools/figures/README.md`](../tools/figures/README.md). Do not edit the SVGs by hand.
