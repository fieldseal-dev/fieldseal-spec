# vector-gen

Generates the Fieldseal cross-implementation test vectors (`vectors/`) from a
single source of inputs, per `docs/08-test-vector-spec.md` §7.

**This tool is not an oracle.** It produces expected values; agreement between
two independently-written implementations is what makes them trustworthy
(`docs/08` §7). Vectors it emits are `-provisional` until Gate 0b closes
(PRD §8) — every suite identifier it writes is in the reserved `0xFF00`–`0xFFFF`
range of spec §4.8.

## Running

```sh
py -3 -m venv .venv
.venv/Scripts/python -m pip install -e .        # Windows
# .venv/bin/python -m pip install -e .          # POSIX

.venv/Scripts/python -m fieldseal_vectorgen --out ../../vectors
```

Families needing no third-party dependency — `context/`, `kdf/`, `commitment/`,
`blind-index/hmac-sha512.json` — also run under a bare interpreter:

```sh
py -3 -m fieldseal_vectorgen --out ../../vectors --stdlib-only
```

## Layout

| Module | Responsibility |
|---|---|
| `primitives.py` | HKDF-SHA-512, `truncate`, constant-width integer encodings |
| `context.py` | `canonical_context` and `AAD` (spec §6.2), presence bitmap |
| `keys.py` | Record-key and index-key derivation (spec §5.3, §7.2) |
| `blindindex.py` | HMAC-SHA-512 and Argon2id IDFs (spec §7.3) |
| `envelope.py` | Envelope assembly and commitment (spec §3.1, §4.6) |
| `families/` | One module per vector family; each returns a file dict |
| `manifest.py` | `MANIFEST.json` with per-file sha256 |

## Determinism

Every input is fixed in `inputs.py`. The generator uses no CSPRNG and no clock,
so re-running it on unchanged inputs reproduces byte-identical files — which is
what makes `MANIFEST.json`'s hashes meaningful and keeps regeneration diffs
reviewable. Real implementations MUST use a CSPRNG for `msg_seed` and `nonce`
(spec §3.1, §4.4); the fixed values here are a testing affordance only, and
`docs/08` §6 governs how a core is allowed to accept them.
