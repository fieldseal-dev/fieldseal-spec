# `ucd-gen` — vendored Unicode tables

Generates the Unicode tables that `nfc-casefold-v1` is defined over
(`docs/09-core-architecture.md` §7.1), from the published Unicode Character
Database, into three places:

| Target | Contents |
|---|---|
| `core/python/src/fieldseal/unicode/_tables.py` | data only; the algorithms live in that package's `__init__.py` |
| `core/typescript/src/unicode/tables-17.0.0.ts` | data only; the algorithms live in `src/unicode/index.ts` |
| `tools/vector-gen/fieldseal_vectorgen/_ucd_tables.py` | data only; the generator's own algorithms live in `normalizer.py` |

**Pinned version: Unicode 17.0.0.**

## Why the tables are vendored at all

A blind index is derived from normalized bytes. If a core took NFC or case
folding from its runtime, the same value would index differently on CPython
3.12 (Unicode 15.0), CPython 3.14 (16.0) and Node with ICU 78 (17.0) — and the
failure is a lookup that silently returns nothing, not an error anybody sees.
`docs/09` §7.1 pins the version and requires the tables; this tool is how they
get there honestly.

The repository carries the *output* rather than the input: the three UCD source
files total about 3.7 MB, more than the tables they produce.

## Why three copies rather than one shared module

The two cores are independent implementations (`docs/17`), and the vector
generator imports neither — its expected values must not come from the code
they are meant to check, or a bug in a core would be published as the answer
every other implementation is verified against.

Sharing the *data* does not weaken that: the data is the Unicode Character
Database, and all three copies are byte-identical by construction and checked
in CI. Sharing an *implementation* would weaken it, so each of the three
carries its own transcription of UAX #15 — canonical decomposition, canonical
ordering, canonical composition — over the same tables. All three are verified
independently:

- the Python core and the generator against the official `NormalizationTest.txt`
  (60,102 cases, all passing);
- the TypeScript core against ICU exhaustively, in `tests/unicode.test.ts`,
  wherever the runtime's Unicode is at least the pin.

## Usage

```sh
# from a local UCD directory
python tools/ucd-gen/generate.py --ucd path/to/ucd

# or fetch the pinned version first (what CI does)
python tools/ucd-gen/generate.py --download

# verify the committed tables are exactly what the UCD produces
python tools/ucd-gen/generate.py --download --check
```

`--check` writes nothing and exits non-zero if any target is stale. The
`unicode-tables` job in `.github/workflows/conformance.yml` runs it, so a
hand-edited table fails the build — one wrong folding entry is a silent
divergence, which is precisely what the pin exists to remove.

Required UCD files: `CaseFolding.txt`, `UnicodeData.txt`,
`DerivedNormalizationProps.txt`.

## Bumping the pin

Changing the Unicode version changes stored index values for any input
containing a character whose folding or decomposition changed. That is a
breaking change to a normalizer, so it needs **a new normalizer id**
(`nfc-casefold-v2`) and a re-index, not a silent table update — see
`docs/09` §7.1 clause 1.

The steps: download the new UCD, change `VERSION` in `generate.py`, re-run,
add the new id to the normalizer set in both cores and the generator, and
regenerate the vector suite. Keep the old id working for as long as stored
values under it exist.
