# fieldseal — Python core

The reference Python implementation of the Fieldseal specification, built to
[`docs/10-core-python.md`](../../docs/10-core-python.md).

> **Not for production use, and the library will refuse.** Every registered
> cipher suite is *provisional* (spec §4.8): its constructions have not been
> independently reviewed, and Gate 0b of the Phase 0 exit gate
> ([`docs/01-prd.md`](../../docs/01-prd.md) §8) is still open. `encrypt()` and
> `rotate()` raise `SUITE_PROVISIONAL` unless you explicitly acknowledge that.
> Decryption is deliberately ungated.

## Status

| | |
|---|---|
| Vector suite | 36/36 pinned vectors pass; 1 family held out |
| Gate and totality tests | 29 pass |
| Suites | `0xFF01` (AES-256-GCM). `0xFF02` needs an XChaCha backend — blocked on gap G7 |
| Milestone | **M1 met** for the families in the pinned suite. M2 (independent TypeScript reproduction) is what makes these values trustworthy |

## Running

```sh
py -3 -m venv .venv
.venv/Scripts/python -m pip install -e ".[argon2,dev]"
.venv/Scripts/python -m pytest tests -q
.venv/Scripts/python tests/run_vectors.py     # conformance report on stdout
```

## What is deliberately not proven yet

**Passing these vectors is weak evidence on its own.** The generator that
produced them is not an oracle ([`docs/08`](../../docs/08-test-vector-spec.md)
§7); what makes an expected value trustworthy is two independently written
implementations agreeing on it. This core is one. The TypeScript core, written
from the specification without reading this source, is the other, and that is
M2.

This core was written without importing anything from `tools/vector-gen/`, and
takes HKDF from pyca/cryptography where the generator hand-rolls it from `hmac`.
That is a deliberate divergence from `docs/10` §7, which anticipated the
generator importing `fieldseal.testing`. Had it done so, M1 would have been
close to tautological — the same code checking itself. See the divergence note
in [`docs/07`](../../docs/07-implementation-plan.md) §7.

**`blind-index/argon2id.json` is held out of the suite** and this core does not
run it. `idf_argon2id` is implemented and works, but the primitive has never
been checked against an external known-answer source: RFC 9106 §5.3's vector
supplies a nonzero secret (`K`) and associated data (`X`), both forbidden by
spec §7.3 and unsuppliable from Python. Two implementations agreeing on an
unverified assumption inherited from one generator would look like
corroboration and be worth nothing.

## Honest limitations

- **No zeroization.** CPython `bytes` are immutable and freely copied; true
  erasure is not achievable. Nothing here claims otherwise (`docs/09` §8.3).
- **No key caching, no KMS providers yet.** `StaticKeyProvider` is test-only and
  holds key material for the process lifetime.
- **Error precedence is provisional.** Which of `AAD_MISMATCH` and `TAG_INVALID`
  applies when GCM reports one `InvalidTag` is gap G5, unresolved. This core
  reports `TAG_INVALID`, the choice that claims least about why.
- **Argon2id holds the GIL** for most of its 10–100 ms per term. **[VERIFY]**
  whether `argon2-cffi` releases it; if not, that is a stated product
  constraint for threaded deployments, not a bug to fix.
