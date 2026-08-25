# Python Core Technical Specification

**Date:** 2026-08-08 · **Status:** Draft 1 · **Purpose:** the Python binding of `docs/09-core-architecture.md`. First implementation built in Phase 1; it also hosts the vector generator (`docs/08-test-vector-spec.md` §7), which is why it comes first.

**Library-fact caveat:** dependency capabilities below were assessed from documentation knowledge as of early 2026 and are marked **[VERIFY]** where they must be re-confirmed against the versions current at implementation time, per the project's citation-or-flag rule.

---

## 1. Package identity and toolchain

| Item | Decision | Notes |
|---|---|---|
| Distribution name | `fieldseal` | PyPI name free per PRD naming note (checked 2026-08-08); claim before first push |
| Import package | `fieldseal` | src layout: `core/python/src/fieldseal/` |
| Python versions | ≥ 3.10 | Chosen for `match` statements and modern typing without excluding current LTS distros. **[VERIFY]** floor against pyca/cryptography's supported floor at implementation time; raise ours to theirs if higher |
| Build backend | `hatchling` via `pyproject.toml` | Pure-Python wheel; no compiled code of our own, ever — primitives come from dependencies |
| Type checking | mypy `--strict`; `py.typed` marker shipped | The API is small; strictness is cheap here |
| Lint/format | ruff (lint + format) | One tool, deterministic in CI |
| Tests | pytest + hypothesis | Hypothesis for codec round-trip and `is_ciphertext` property tests (docs/09 §4) |

## 2. Dependencies

| Purpose | Dependency | Status |
|---|---|---|
| AES-256-GCM, HKDF-SHA-512, HMAC, constant-time compare | `cryptography` (pyca) | Core required dependency. `AESGCM` accepts AAD and 12-byte nonces; `HKDF` with `hashes.SHA512()`; `constant_time.bytes_eq`. **[VERIFY]** exact minimum version at implementation |
| Argon2id raw output | `argon2-cffi` | `argon2.low_level.hash_secret_raw(secret=…, salt=…, time_cost=3, memory_cost=32768, parallelism=1, hash_len=64, type=Type.ID, version=19)` — raw output with an explicit 16-byte salt, which is exactly the spec §7.3 invocation. **Viable as of the 2026-08-22 narrowing:** §7.3 now excludes Argon2's `K`, and everything it does require is in this supported API. **Naming trap, keep it in review checklists:** argon2-cffi's `secret=` keyword is the **password**, *not* RFC 9106's secret value `K`. An implementer reading the RFC and this API together can satisfy both readings and be silently wrong — no exception, just a divergent index. Pass `normalize(plaintext)` there and nothing else. **[VERIFY]** that `version=19` is the default and that `hash_len=64` is accepted |
| XChaCha20-Poly1305 (suite 0xFF02) | `PyNaCl` (libsodium binding), optional extra `fieldseal[xchacha]` | pyca `cryptography` ships `ChaCha20Poly1305` but **not** XChaCha20-Poly1305 **[VERIFY — if pyca has added it, drop PyNaCl]**. PyNaCl's `crypto_aead_xchacha20poly1305_ietf_*` is the de-facto-normative libsodium construction (spec gap G7) |
| KMS wrappers | `fieldseal[aws]` → `boto3`, `fieldseal[gcp]`, `fieldseal[azure]` optional extras | Never in the required set (docs/09 §11); each implements the `Wrapper` interface only |
| CSPRNG | stdlib `secrets.token_bytes` | Kernel-backed, fork-safe; no dependency |

Rule: the **required** dependency set is `cryptography` alone. Everything else is an extra. This is what keeps the core auditable and keeps FIPS conversations tractable (PRD CL-9: FIPS validation is a property of the build — a deployment swapping in a FIPS-validated OpenSSL underneath pyca is the intended path; document, don't promise).

## 3. Module layout

Mirrors docs/09 §1 exactly:

```
src/fieldseal/
  __init__.py        exports: Fieldseal, FieldContext, errors, providers — and nothing from testing
  api.py             Fieldseal client class
  envelope.py        EnvelopeHeader, parse, serialize, is_ciphertext
  registry.py        SUITES table (frozen dataclasses), allow-list checks
  context.py         FieldContext (frozen dataclass), canonical_context(), aad()
  kdf.py             record_key(), index_key()
  aead/__init__.py   AeadBackend protocol
  aead/gcm.py        suite 0xFF01 backend
  aead/xchacha.py    suite 0xFF02 backend (import guarded by the extra)
  commitment.py      pending spec gap G1 — module exists with NotImplementedError + issue link
  blindindex.py      IDFs, truncate, normalizers (argon2 construction pending G2; its
                     per-column cost and truncate are pinned, spec §7.2, §7.3);
                     IndexDeclaration and validate_index_declaration — the §7.4 band and §7.6
                     cardinality gate, checked once at construction
  keyprovider.py     KeyProvider protocol, StaticKeyProvider, DerivedKeyProvider, EnvelopeKeyProvider
  cache.py           DekCache
  config.py          FieldsealConfig — not yet split out; construction-time validation currently
                     lives in Fieldseal.__init__, and IndexDeclaration in blindindex.py
  errors.py          FieldsealError hierarchy
  testing/__init__.py  encrypt_with_materials — separate subpackage, imported only by tests;
                       inert unless armed: every function raises unless the environment variable
                       FIELDSEAL_TEST_MODE=1 is set at import time (docs/08 §6 arming gate)
py.typed
```

## 4. Public API shape

```python
from fieldseal import Fieldseal, FieldContext
from fieldseal.keyprovider import EnvelopeKeyProvider

fs = Fieldseal(
    key_provider=provider,
    allowed_suites={0xFF01},
    write_suite=0xFF01,
    read_mode="strict",
    arm_provisional_suites=False,      # spec §4.8; or FIELDSEAL_ARM_PROVISIONAL_SUITES=1 (docs/14 §4)
    cache=CachePolicy(max_age=timedelta(minutes=10), max_uses=1_000_000, capacity=10_000),
    indexes=[IndexDeclaration(...)],
)

ct: bytes  = fs.encrypt(b"...", ctx)
pt: bytes  = fs.decrypt(ct, ctx)
bx: bytes  = fs.blind_index("...", ctx)   # str or bytes; str is the preferred form
ok: bool   = fs.is_ciphertext(ct)
ct2: bytes = fs.rotate(ct, ctx)
await fs.warm([ctx, ...])          # the only coroutine on the client
```

- **`blind_index` takes `str | bytes`; every other operation takes `bytes`.** This asymmetry predates G16 and is now the normative shape (docs/09 §7.1): normalization is a text operation, encryption is not, so index derivation is the only place where the difference between a string and its encoding changes the answer. Passing `str` is the preferred form because it is the only one that cannot have lost information already — this core's `bytes` path is safe too (`str.encode("utf-8")` raises on a lone surrogate rather than substituting, unlike JavaScript's `TextEncoder`), but that is a property of CPython rather than of the API. What CPython raises is a `UnicodeEncodeError`, which is outside the §9 taxonomy; the normalizers re-raise it as `InvalidArgument` so that the refusal carries the same code as the TypeScript core's and so that `on_unindexable` can recognise it.
- **Index parameters come from the declaration, never from the call.** `blind_index(value, ctx)` takes only the value and the context; the IDF, normalizer, truncation length and `on_unindexable` policy all come from the `IndexDeclaration` registered at construction, resolved by `(table_uuid, column_uuid, ctx.purpose)`. This is what gives the §7.4 band and the §7.6 cardinality gate somewhere to run: both ask how many distinct values a *column* holds, which a per-call argument cannot answer. `ctx.purpose` must already name the index (`ctx.for_index("email-eq")`), matching the TypeScript core. The Argon2id cost is one of those parameters: `IndexDeclaration(idf="argon2id", argon2=Argon2Params(time_cost=4, memory_kib=65536), …)` raises it for that column, `Argon2Params` is exported from the package for the purpose, and absent means the spec §7.3 minima. Below either minimum, or given on an `hmac-sha512` index, it is a `ConfigurationError` at construction. This core carried the cost as a module constant until [#62](https://github.com/fieldseal-dev/fieldseal-spec/issues/62), which made a raised cost inexpressible here and expressible in TypeScript — the two cores agreeing on every vector, since the vectors pin the minima, and diverging silently on the first column that raised it (docs/09 §7).
- `FieldContext` is a frozen dataclass with `__slots__`; adapters build one per column at model-definition time and pass it per call (docs/09 §12). Adapters never set `suite_id` — the core fills that member itself: `config.write_suite` on encrypt, and the parsed envelope header on decrypt (docs/09 §3.2 step 4 — a client whose write suite is 0xFF02 must still derive the correct key for a 0xFF01 envelope during mixed-suite reads and rotation).
- All five operations are strictly synchronous and perform no I/O (spec §11.1). `warm` is `async def`; a sync convenience `warm_blocking()` wraps it for WSGI apps (it may do network I/O — it is not in the value path).
- Errors: `FieldsealError` → `UnknownFormatVersion`, `SuiteNotAllowed`, `KeyUnavailable`, `AadMismatch`, `TagInvalid`, `CommitmentInvalid`, `NotCiphertext`, `ModeViolation` (spec §9 code `MODE_VIOLATION`, added by G6), `LengthExceeded` (code `LENGTH_EXCEEDED`, added by G10 — spec §3.5), `SuiteProvisional` (code `SUITE_PROVISIONAL`, spec §4.8), and two implementation-local codes docs/09 §9 permits outside §9: `ConfigurationError` (construction time) and `InvalidArgument` (an operand refused at the API boundary — an index purpose handed to `encrypt`, invalid UTF-8 handed to a text normalizer). Each carries `.code: str` equal to the vector-suite string (docs/09 §9). `FieldsealWarning` is the spec §10.3 warning for the pass-through modes.
- `KeyProvider` is spec §8's interface by name: `encryption_key(ctx) -> (key_material, key_id)` with purpose routing, and `decryption_keys(header) -> Sequence[bytes]` returning every currently-valid version in preference order; the client tries each candidate's commitment in turn (docs/09 §3.2 step 6).

## 5. Security-relevant implementation notes

- **Zeroization honesty (docs/09 §8.3):** Python `bytes` are immutable and interned-copyable; true erasure is not achievable in CPython. The cache stores DEKs in `bytearray` and overwrites on eviction — this narrows, but does not close, the memory-exposure window, and intermediate `bytes` copies inside pyca calls are outside our control. The module docstring and user docs state this in exactly those terms; claiming more would violate the no-overclaim rule. `mlock` is not provided (docs/09 §8.3 deviation, documented).
- **Constant-time compares:** all commitment/tag-adjacent comparisons via `cryptography.hazmat.primitives.constant_time.bytes_eq`; never `==` on secret-derived values.
- **GIL and threading:** the client is thread-safe; the cache uses a single `threading.Lock` around metadata with the singleflight pattern for refresh (docs/09 §8.3). No `asyncio` primitives in the sync path.
- **Fork-safety:** `secrets` is kernel-backed. Docs carry the prefork-server guidance from docs/09 §10 (construct the client after fork in gunicorn `post_fork`).
- **Argon2id blocking cost:** 10–100 ms per term (spec §7.3) *holds the GIL* for most of that time in a CFFI call **[VERIFY: whether argon2-cffi releases the GIL during hashing — if it does, note it; if not, this is a stated product constraint for threaded Django deployments]**.

## 6. Testing plan

1. **Vector harness** (`tests/vectors/`): implements the full contract of docs/08 §5 — manifest hash check, schema validation (`jsonschema` dev-dependency), both-direction envelope runs, exact error-code mapping, machine-readable report emission (docs/14 §4). Vector path resolved from the repo root so `core/python` never copies vectors.
2. **Unit tests** per module, including: codec truncation at every byte offset of a valid envelope (must never panic — always a typed error); allow-list vs registry decoupling (spec §3.4 double-encryption regression case, verification-log defect #6); cache max-age/max-uses/zeroize-on-evict, with use counting per `encryption_key` return — `decryption_keys` candidate reads must not deplete `max_uses` (docs/09 §8.3; mirror the TypeScript `providers.test.ts` "decrypt-path candidate reads do not deplete §5.5 max-uses" case — this test is written down here *before* `cache.py`/`EnvelopeKeyProvider` exist so the bug fixed in PR #55 is not re-introduced when they land); provider purpose-routing (index purpose must never return the DEK — spec §8).
3. **Property tests** (hypothesis): `parse(serialize(h))` identity; `is_ciphertext` total on arbitrary bytes (never raises); `decrypt(encrypt(p, ctx), ctx) == p` for random valid inputs with the real CSPRNG path.
4. **Cross-output producer**: a pytest-invocable script emitting the `cross/` file (docs/08 §4.7) from the production path.
5. **Negative import test:** `import fieldseal` must not import `fieldseal.testing`; enforced by a test asserting `"fieldseal.testing" not in sys.modules` after a clean import. A second test asserts `encrypt_with_materials` raises when `FIELDSEAL_TEST_MODE` is unset (the docs/08 §6 arming gate). The module docstring carries the consequence verbatim: *"an implementation that accepts a caller-supplied nonce or seed outside of vector-test mode is non-conformant"* (`vectors/README.md`).

## 7. Non-goals for the Python core

No Django/SQLAlchemy awareness of any kind (that's `adapters/`); no CLI (the vector generator lives in `tools/vector-gen/`); no PyPy claims until CI covers it.

**Divergence recorded 2026-08-22 — the generator does *not* import `fieldseal.testing`.** This section originally said it would, "deliberately". Building both showed that to be a mistake: if the generator produces expected values using this core's code, then this core passing those values is close to tautological, and M1 would certify nothing. `tools/vector-gen/` is therefore standalone, and takes a different route to the same primitives — it hand-rolls HKDF from `hmac` where this core uses pyca/cryptography's. The two agreeing on the suite is a real cross-check of *HKDF* — and of HKDF only: the generator and this core share the `canonical_context` layout, the envelope assembly and the commitment label by construction, written by the same hands from the same sections, so agreement there is agreement of one reading with itself. The same code agreeing with itself would have checked nothing at all; this checks one primitive. What checks the rest is M2 (`docs/18`).

The cost is honest: HKDF, `canonical_context` and the envelope layout each exist twice in this repository, and a spec change touches both. That is the price of M1 meaning anything before M2 lands, and M2 — an independently written TypeScript core reproducing these values from the specification alone (`docs/11` §6) — remains the real check. Revisit only if the duplication starts drifting rather than being caught.

No async value-path variants either — but as of G9 (issue #9) that is this core's choice rather than a prohibition: spec §11.1 permits optional async companions, and the Python core declines them because its target frameworks (Django, SQLAlchemy) are the ones that cannot await in the value path at all, so the companions would carry the dual-path vector obligation for no adapter that could use it. Revisit only if a Python adapter credibly claims L4.
