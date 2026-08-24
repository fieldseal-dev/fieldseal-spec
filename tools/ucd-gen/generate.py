"""Emit the vendored Unicode tables that every core ships (docs/09 §7).

`nfc-casefold-v1` is pinned to one Unicode version. A core that took its
normalization or folding from the platform would produce different blind
index values on different runtimes -- the platform's Unicode version is not
a property of the deployment anyone controls, and a mismatch is a silent
lookup miss rather than an error. So the tables are vendored, generated
here from the published UCD files, and both reference cores read them
rather than their runtime's.

Usage:
    python generate.py --ucd <dir>   [--check]
    python generate.py --download    [--check]

`<dir>` holds the UCD files for the pinned version, downloaded from
https://www.unicode.org/Public/<version>/ucd/ :

    CaseFolding.txt  UnicodeData.txt  DerivedNormalizationProps.txt

`--download` fetches them into a temporary directory instead, which is how CI
runs the `--check`: the three files total ~3.7 MB, which is more than the
generated tables they produce, so the repository carries the output rather
than the input.

`--check` regenerates into memory and diffs against what is on disk,
exiting non-zero if they differ; that is what CI runs so a hand-edited
table cannot survive.

Bumping the pin (17.0.0 -> 18.0.0) means: download the new UCD, change
VERSION below, re-run, and re-run both cores' vector suites. The stored
index values change for any input containing a code point whose folding or
decomposition changed, which is why the pin is part of the normalizer id
and a bump needs a new id (`nfc-casefold-v2`) rather than a silent update.
"""

from __future__ import annotations

import argparse
import io
import os
import sys

VERSION = "17.0.0"

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY_OUT = os.path.join(REPO, "core", "python", "src", "fieldseal", "unicode", "_tables.py")
TS_OUT = os.path.join(REPO, "core", "typescript", "src", "unicode", "tables-%s.ts" % VERSION)
# The vector generator imports neither core, so it gets its own copy of the
# data and carries its own implementation of the algorithms over it. Sharing
# the published UCD is not a dependency; sharing an implementation would be,
# and would let one core's bug be blessed as the expected value.
GEN_OUT = os.path.join(REPO, "tools", "vector-gen", "fieldseal_vectorgen", "_ucd_tables.py")


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def _lines(ucd: str, name: str) -> list[str]:
    with io.open(os.path.join(ucd, name), encoding="utf-8") as fh:
        return fh.read().splitlines()


def parse_casefold(ucd: str) -> dict[int, list[int]]:
    """Statuses C (common) and F (full) -- "full case folding" per UAX #44.

    T (Turkic) is excluded deliberately: it makes the folding depend on the
    caller's locale, and a blind index has no locale. S (simple) is
    superseded by F wherever both exist.
    """
    out: dict[int, list[int]] = {}
    for line in _lines(ucd, "CaseFolding.txt"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        cp, status, mapping = [f.strip() for f in line.split(";")[:3]]
        if status in ("C", "F"):
            out[int(cp, 16)] = [int(h, 16) for h in mapping.split()]
    return out


def parse_unicodedata(ucd: str):
    """Assigned ranges, canonical combining classes, canonical decompositions.

    UnicodeData.txt encodes large blocks as a First/Last row pair rather
    than one row per code point, so the assigned set is accumulated as
    ranges and adjacent singletons are coalesced.
    """
    rows = []
    for line in _lines(ucd, "UnicodeData.txt"):
        f = line.split(";")
        if len(f) < 15:
            continue
        rows.append((int(f[0], 16), f[1], int(f[3]), f[5]))

    assigned: list[list[int]] = []
    ccc: dict[int, int] = {}
    decomp: dict[int, list[int]] = {}
    i = 0
    while i < len(rows):
        cp, name, klass, d = rows[i]
        if klass:
            ccc[cp] = klass
        if d and not d.startswith("<"):          # "<compat>" forms are not canonical
            decomp[cp] = [int(h, 16) for h in d.split()]
        if name.endswith(", First>"):
            assigned.append([cp, rows[i + 1][0]])
            i += 2
            continue
        if assigned and assigned[-1][1] == cp - 1:
            assigned[-1][1] = cp
        else:
            assigned.append([cp, cp])
        i += 1
    return [(a, b) for a, b in assigned], ccc, decomp


def parse_exclusions(ucd: str) -> set[int]:
    """Full_Composition_Exclusion -- the derived property, which already folds
    in singleton and non-starter decompositions as well as the script-specific
    exclusion list."""
    out: set[int] = set()
    for line in _lines(ucd, "DerivedNormalizationProps.txt"):
        line = line.split("#", 1)[0].strip()
        if not line or ";" not in line:
            continue
        parts = [x.strip() for x in line.split(";")]
        if len(parts) < 2 or parts[1] != "Full_Composition_Exclusion":
            continue
        rng = parts[0]
        if ".." in rng:
            a, b = rng.split("..")
            out.update(range(int(a, 16), int(b, 16) + 1))
        else:
            out.add(int(rng, 16))
    return out


# --------------------------------------------------------------------------
# encoding
# --------------------------------------------------------------------------

def enc_map(m: dict[int, list[int]]) -> str:
    return ";".join("%x>%s" % (k, ",".join("%x" % c for c in v))
                    for k, v in sorted(m.items()))


def enc_ccc(m: dict[int, int]) -> str:
    return ";".join("%x:%x" % (k, v) for k, v in sorted(m.items()))


def enc_ranges(rs: list[tuple[int, int]]) -> str:
    return ";".join("%x" % a if a == b else "%x-%x" % (a, b) for a, b in rs)


def enc_set(s: set[int]) -> str:
    return ";".join("%x" % c for c in sorted(s))


def wrap(s: str, width: int, indent: str, quote: str = '"') -> str:
    """Chunk a long literal so the generated file stays diffable."""
    chunks = [s[i:i + width] for i in range(0, len(s), width)]
    joiner = "\n" + indent
    return joiner.join("%s%s%s" % (quote, c, quote) for c in chunks)


# --------------------------------------------------------------------------
# emit
# --------------------------------------------------------------------------

BANNER = (
    "GENERATED FILE -- do not edit by hand.\n"
    "Source: Unicode Character Database %s (CaseFolding.txt, UnicodeData.txt,\n"
    "DerivedNormalizationProps.txt), via tools/ucd-gen/generate.py.\n"
    "Regenerate with:  python tools/ucd-gen/generate.py --ucd <ucd-dir>\n"
    "CI runs the same command with --check, so a hand edit fails the build."
)


def emit_python(casefold, assigned, ccc, decomp, excl2) -> str:
    b = "\n".join("# " + l if l else "#" for l in BANNER.split("\n"))
    return '''{banner}

"""Vendored Unicode {v} data for `nfc-casefold-v1` (docs/09 §7).

The tables are stored as compact strings and expanded once, lazily, on first
use -- importing `fieldseal` should not pay for a normalizer the caller may
never reach.
"""

UNICODE_VERSION = "{v}"

CASEFOLD_ENTRY_COUNT = {ncf}
ASSIGNED_RANGE_COUNT = {nas}
DECOMPOSITION_COUNT = {ndc}

# code point > folded code points, hex, ";"-separated (statuses C and F)
_CASEFOLD = (
    {casefold}
)

# assigned code points as "lo-hi" ranges (general category != Cn)
_ASSIGNED = (
    {assigned}
)

# code point : canonical combining class, non-zero only
_CCC = (
    {ccc}
)

# code point > canonical decomposition
_DECOMP = (
    {decomp}
)

# code points with a two-character canonical decomposition that must NOT
# recompose (Full_Composition_Exclusion)
_EXCLUSIONS = (
    {excl}
)
'''.format(banner=b, v=VERSION, ncf=len(casefold), nas=len(assigned), ndc=len(decomp),
           casefold=wrap(enc_map(casefold), 92, "    "),
           assigned=wrap(enc_ranges(assigned), 92, "    "),
           ccc=wrap(enc_ccc(ccc), 92, "    "),
           decomp=wrap(enc_map(decomp), 92, "    "),
           excl=wrap(enc_set(excl2), 92, "    "))


def emit_ts(casefold, assigned, ccc, decomp, excl2) -> str:
    b = "\n".join("// " + l if l else "//" for l in BANNER.split("\n"))
    return '''{banner}

export const UNICODE_VERSION = "{v}";

export const CASEFOLD_ENTRY_COUNT = {ncf};
export const ASSIGNED_RANGE_COUNT = {nas};
export const DECOMPOSITION_COUNT = {ndc};

/** code point > folded code points, hex, ";"-separated (statuses C and F) */
export const CASEFOLD =
  {casefold};

/** assigned code points as "lo-hi" ranges (general category != Cn) */
export const ASSIGNED =
  {assigned};

/** code point : canonical combining class, non-zero only */
export const CCC =
  {ccc};

/** code point > canonical decomposition */
export const DECOMP =
  {decomp};

/** two-character canonical decompositions that must NOT recompose */
export const EXCLUSIONS =
  {excl};
'''.format(banner=b, v=VERSION, ncf=len(casefold), nas=len(assigned), ndc=len(decomp),
           casefold=wrap(enc_map(casefold), 96, "  ").replace('"\n  "', '" +\n  "'),
           assigned=wrap(enc_ranges(assigned), 96, "  ").replace('"\n  "', '" +\n  "'),
           ccc=wrap(enc_ccc(ccc), 96, "  ").replace('"\n  "', '" +\n  "'),
           decomp=wrap(enc_map(decomp), 96, "  ").replace('"\n  "', '" +\n  "'),
           excl=wrap(enc_set(excl2), 96, "  ").replace('"\n  "', '" +\n  "'))


UCD_FILES = ("CaseFolding.txt", "UnicodeData.txt", "DerivedNormalizationProps.txt")
UCD_URL = "https://www.unicode.org/Public/%s/ucd/%s"


def download(dest: str) -> str:
    """Fetch the pinned version's UCD files. Used by CI so the repository can
    carry the generated tables rather than the larger sources."""
    import urllib.request

    os.makedirs(dest, exist_ok=True)
    for name in UCD_FILES:
        url = UCD_URL % (VERSION, name)
        with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310
            body = r.read()
        with open(os.path.join(dest, name), "wb") as fh:
            fh.write(body)
        print("fetched %s (%d bytes)" % (url, len(body)))
    return dest


def main() -> int:
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ucd", help="directory holding the UCD .txt files")
    src.add_argument("--download", action="store_true",
                     help="fetch the UCD files for the pinned version first")
    ap.add_argument("--check", action="store_true",
                    help="diff against the files on disk instead of writing")
    args = ap.parse_args()

    if args.download:
        import tempfile
        args.ucd = download(os.path.join(tempfile.mkdtemp(prefix="ucd-"), VERSION))

    casefold = parse_casefold(args.ucd)
    assigned, ccc, decomp = parse_unicodedata(args.ucd)
    excl = parse_exclusions(args.ucd)
    # Only two-character canonical decompositions can recompose, so only their
    # exclusions need shipping; the rest of Full_Composition_Exclusion is
    # singletons and non-starters, which the algorithm never composes anyway.
    excl2 = {cp for cp, d in decomp.items() if len(d) == 2 and cp in excl}

    print("unicode %s: casefold=%d assigned-ranges=%d ccc=%d decomp=%d excl2=%d"
          % (VERSION, len(casefold), len(assigned), len(ccc), len(decomp), len(excl2)))

    py = emit_python(casefold, assigned, ccc, decomp, excl2)
    targets = [(PY_OUT, py),
               (TS_OUT, emit_ts(casefold, assigned, ccc, decomp, excl2)),
               (GEN_OUT, py)]

    rc = 0
    for path, text in targets:
        if args.check:
            cur = io.open(path, encoding="utf-8").read() if os.path.exists(path) else None
            if cur != text:
                print("STALE: %s" % os.path.relpath(path, REPO))
                rc = 1
            else:
                print("ok:    %s" % os.path.relpath(path, REPO))
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            print("wrote: %s (%d bytes)" % (os.path.relpath(path, REPO), len(text)))
    return rc


if __name__ == "__main__":
    sys.exit(main())
