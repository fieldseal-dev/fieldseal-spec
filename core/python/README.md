# fieldseal — Python core

The reference Python implementation of the Fieldseal specification, built to
[`docs/10-core-python.md`](../../docs/10-core-python.md).

> **Not for production use, and the library will refuse.** Every registered
> cipher suite is *provisional* (spec §4.8): its constructions have not been
> independently reviewed, and Gate 0b of the Phase 0 exit gate
> ([`docs/01-prd.md`](../../docs/01-prd.md) §8) is still open. `encrypt()` and
> `rotate()` raise `SUITE_PROVISIONAL` unless you explicitly arm provisional
> use — `FIELDSEAL_ARM_PROVISIONAL_SUITES=1` in the environment, or
> `arm_provisional_suites=True` on the constructor. Decryption is deliberately
> ungated.

## Status

| | |
|---|---|
| Vector suite | **175/175** pinned results pass on suite `0.6.0-provisional` (144 vectors; `envelope/` counted in both directions, some `blind-index/` vectors also end to end — see `harness_notes` in the report); **no family held out**; both §3.5 out-of-band checks pass |
| Gate, parity and totality tests | 131 pass (`tests/test_gates.py`, `tests/test_parity.py`) |
| Suites | `0xFF01` (AES-256-GCM). `0xFF02` is registered and refused at construction — it needs an XChaCha backend, blocked on gap G7 |
| Conformance report | `tests/run_vectors.py` writes the [`docs/14`](../../docs/14-conformance-ci.md) §4 JSON to stdout, including `pinned_decisions` and `harness_notes`; the TypeScript core's report has the same shape and the same result ids, so the two diff cleanly |
| Milestone | **M1 met** for the families in the pinned suite. M2 (the independent TypeScript reproduction, [`docs/18`](../../docs/18-m2-report.md)) is what makes these values trustworthy |

## Running

```sh
py -3 -m venv .venv
.venv/Scripts/python -m pip install -e ".[argon2,dev]"
.venv/Scripts/python -m pytest tests -q
.venv/Scripts/python tests/run_vectors.py > conformance-python.json   # report on stdout, prose on stderr
.venv/Scripts/python -m mypy --strict src
```

## What the vectors do not reach, and what this core pins

Spec §9 leaves the precedence among its error codes open (gap G5) and obliges a
Gate 0a implementation to pin an order and declare it. This core follows
[`docs/09`](../../docs/09-core-architecture.md) §3.2 step for step and declares
every pin under `pinned_decisions` in its report, under the keys `docs/14` §4
reserves. The ones an operator will meet:

- **Read modes (spec §10.3).** `strict` raises `NOT_CIPHERTEXT` on non-envelope
  input; `permissive` and `readonly` return it as-is, warn at construction
  (`FieldsealWarning`) and count it in `Fieldseal.plaintext_reads`. `readonly`
  refuses `encrypt()` and `rotate()` with `MODE_VIOLATION` before reading
  anything. `rotate()` in `permissive` mode is literally decrypt-then-encrypt,
  so it *encrypts* unmigrated plaintext (D-13).
- **Recognition before policy (spec §3.4).** An unregistered suite, an
  unrecognized version byte or an implausible length is "not one of ours" —
  never `SUITE_NOT_ALLOWED`. Only a registered suite that the allow-list
  excludes is `SUITE_NOT_ALLOWED`. One exception: `fmt_ver = 0x02` at a
  plausible length raises `UNKNOWN_FORMAT_VERSION` in every mode (D-03).
- **Every currently-valid key version is tried (spec §8).**
  `KeyProvider.decryption_keys(header)` returns the candidates in preference
  order; the core verifies each one's commitment constant-time before any AEAD
  open. No candidate → `KEY_UNAVAILABLE`; none commits → `COMMITMENT_INVALID`;
  an open that fails after a verified commitment → `TAG_INVALID`.
  **`AAD_MISMATCH` is never raised**: under dual-layer binding a wrong context
  derives a wrong record key and is indistinguishable from key confusion (G5).
- **Blind indexes are bytes-in/bytes-out.** `nfc-casefold-v1` over bytes
  decodes strict UTF-8 first and refuses invalid input with `INVALID_ARGUMENT`
  rather than folding through replacement characters; `identity` and
  `digits-only-v1` never decode. An unknown IDF or normalizer is a
  `CONFIGURATION_ERROR`, never a default. The Unicode version is the
  interpreter's (`unicodedata.unidata_version`, reported in the report's
  `environment`) — CPython 3.14 folds with Unicode 16.0 where the TypeScript
  core vendors 17.0, which is a real cross-core risk for shared indexes until
  [`docs/09`](../../docs/09-core-architecture.md) §7 pins a table (D-10).

`fieldseal.testing.encrypt_with_materials` runs the same API boundary as
`encrypt()` — mode, arming and length gates included — and replaces only the two
entropy draws (docs/08 §6).

## What is deliberately not proven yet

**Passing these vectors is weak evidence on its own.** The generator that
produced them is not an oracle ([`docs/08`](../../docs/08-test-vector-spec.md)
§7); what makes an expected value trustworthy is two independently written
implementations agreeing on it. This core is one. The TypeScript core, written
from the specification without reading this source, is the other, and that is
M2. The behaviours listed above are *not* covered by any vector; they are
covered by `tests/test_parity.py` against this core's own pins, and the
`errors/` vector family that would make them a shared check does not exist yet.

This core was written without importing anything from `tools/vector-gen/`, and
takes HKDF from pyca/cryptography where the generator hand-rolls it from `hmac`.
That is a deliberate divergence from `docs/10` §7, which anticipated the
generator importing `fieldseal.testing`. Had it done so, M1 would have been
close to tautological — the same code checking itself. The cross-check is
narrower than "independent", though: the two share the `canonical_context`
layout by construction, so the independence is in HKDF only. See the
divergence note in [`docs/07`](../../docs/07-implementation-plan.md) §7.

**`blind-index/argon2id.json` is pinned** as of suite `0.6.0-provisional` (2026-08-31, `docs/07` §7) and this core runs it like any other family. It was held out while the primitive had no external known-answer source: RFC 9106 §5.3's vector supplies a nonzero secret (`K`) and associated data (`X`), both forbidden by spec §7.3 and unsuppliable from Python, so passing the project's own vectors would have proved only that two implementations copied one unverified assumption. That is answered — the generator checks argon2-cffi against libsodium's seven published `crypto_pwhash` answers on every run (libsodium cannot supply `K` or `X` either, which makes it the right source for the case §7.3 uses), and the TypeScript core reproduces the same values through `node:crypto`.

Promoting it also found what the hold-out had been hiding: eight of the family's nineteen vectors declared `idf: argon2id` with no `idf_params`, and both cores reject a missing cost as malformed rather than assuming the minimum (`docs/08` §4.4). Nothing had run them, so nothing had said so.

## Honest limitations

- **No zeroization.** CPython `bytes` are immutable and freely copied; true
  erasure is not achievable. Nothing here claims otherwise (`docs/09` §8.3).
- **No key caching, no KMS providers yet.** `StaticKeyProvider` is test-only,
  holds key material for the process lifetime, and does not yet emit the
  outside-test-configuration warning spec §8 asks for.
- **Error precedence is provisional.** Everything under "what this core pins"
  above may change at Gate 0b; the pins are declared so that a change is
  visible, not because they are settled.
- **Argon2id holds the GIL** for most of its 10–100 ms per term. **[VERIFY]**
  whether `argon2-cffi` releases it; if not, that is a stated product
  constraint for threaded deployments, not a bug to fix.
