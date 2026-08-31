"""Unicode NFC and full case folding over vendored UCD 17.0.0 tables.

`nfc-casefold-v1` is pinned to one Unicode version (docs/09 §7). Neither step
may come from the platform here: CPython's `unicodedata` carries whatever
version that interpreter shipped with (3.12 → 15.0.0, 3.13 → 15.1.0,
3.14 → 16.0.0), so a deployment that upgraded Python would silently change
its blind index values, and two cores on two runtimes would disagree with no
error anywhere. The tables in `_tables.py` are generated from the published
UCD by `tools/ucd-gen/generate.py`.

The spec permits taking NFC from the platform when the platform's Unicode
version is at least the pinned one and the core proves agreement
exhaustively in its own tests. This core does not take that route -- CPython
has not shipped 17.0.0 yet, and once it does, the vendored path costs little
enough that dropping it would trade determinism for nothing.

Everything here operates on `str`. Decoding bytes and refusing invalid UTF-8
is the caller's job (`blindindex._as_text`).
"""

from __future__ import annotations

import bisect
from typing import Dict, List, NamedTuple, Optional, Tuple

from ._tables import (
    _ASSIGNED,
    _CASEFOLD,
    _CCC,
    _DECOMP,
    _EXCLUSIONS,
    ASSIGNED_RANGE_COUNT,
    CASEFOLD_ENTRY_COUNT,
    DECOMPOSITION_COUNT,
    UNICODE_VERSION,
)

__all__ = [
    "UNICODE_VERSION",
    "CASEFOLD_ENTRY_COUNT",
    "ASSIGNED_RANGE_COUNT",
    "DECOMPOSITION_COUNT",
    "casefold_full",
    "nfc",
    "first_unassigned",
    "Unassigned",
    "combining_class",
]

# Hangul, composed algorithmically rather than from the tables (UAX #15 §3.12).
_S_BASE, _L_BASE, _V_BASE, _T_BASE = 0xAC00, 0x1100, 0x1161, 0x11A7
_L_COUNT, _V_COUNT, _T_COUNT = 19, 21, 28
_N_COUNT = _V_COUNT * _T_COUNT
_S_COUNT = _L_COUNT * _N_COUNT

_casefold: Optional[Dict[int, str]] = None
_ccc: Optional[Dict[int, int]] = None
_decomp: Optional[Dict[int, List[int]]] = None
_comp: Optional[Dict[Tuple[int, int], int]] = None
_lo: Optional[List[int]] = None
_hi: Optional[List[int]] = None


def _load() -> None:
    """Expand the compact tables. Done once, on first use, so importing
    `fieldseal` does not pay for a normalizer the caller may never reach."""
    global _casefold, _ccc, _decomp, _comp, _lo, _hi
    if _casefold is not None:
        return

    cf: Dict[int, str] = {}
    for entry in _CASEFOLD.split(";"):
        src, _, dst = entry.partition(">")
        cf[int(src, 16)] = "".join(chr(int(h, 16)) for h in dst.split(","))

    cc: Dict[int, int] = {}
    for entry in _CCC.split(";"):
        src, _, val = entry.partition(":")
        cc[int(src, 16)] = int(val, 16)

    dc: Dict[int, List[int]] = {}
    for entry in _DECOMP.split(";"):
        src, _, dst = entry.partition(">")
        dc[int(src, 16)] = [int(h, 16) for h in dst.split(",")]

    excluded = {int(h, 16) for h in _EXCLUSIONS.split(";") if h}
    cp_pairs: Dict[Tuple[int, int], int] = {}
    for cp, d in dc.items():
        if len(d) == 2 and cp not in excluded:
            cp_pairs[(d[0], d[1])] = cp

    los: List[int] = []
    his: List[int] = []
    for rng in _ASSIGNED.split(";"):
        a, _, b = rng.partition("-")
        los.append(int(a, 16))
        his.append(int(b, 16) if b else int(a, 16))

    _casefold, _ccc, _decomp, _comp, _lo, _hi = cf, cc, dc, cp_pairs, los, his


def combining_class(cp: int) -> int:
    _load()
    assert _ccc is not None
    return _ccc.get(cp, 0)


class Unassigned(NamedTuple):
    """What `first_unassigned` found: the code point, and where it is.

    `offset` is counted in **code points**, not UTF-16 units. In Python the two
    coincide, because `str` iterates code points -- but the unit is part of the
    contract, not an accident of this binding: the TypeScript core returns the
    same number for the same string, and its natural unit is UTF-16. Stating
    the unit is what keeps them agreeing. `docs/12` §10.2 renders this to a
    person as "the Nth character", which is code points or it is wrong.

    A tuple, so the older `(index, char)`-shaped call sites read unchanged and
    a caller may unpack it; named, so `stray.code_point` is what appears in a
    message rather than `stray[0]`.
    """

    code_point: int
    offset: int


def first_unassigned(text: str) -> Optional[Unassigned]:
    """The first code point not assigned in the pinned Unicode version, and its
    position, or None if every code point is assigned.

    Surrogates count as unassigned here. UnicodeData.txt does list them (as
    category Cs), but a lone surrogate has no UTF-8 encoding, so a normalizer
    that accepted one could not produce the bytes the index is derived from.

    Exported from the package root because `docs/09` §7.1 requires it: an
    adapter that still holds the text can refuse the value where it can be
    attributed to a form field, instead of catching an exception from inside a
    write and parsing its message for the character. G22 (#88).
    """
    _load()
    assert _lo is not None and _hi is not None
    for offset, ch in enumerate(text):
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            return Unassigned(cp, offset)
        i = bisect.bisect_right(_lo, cp) - 1
        if i < 0 or cp > _hi[i]:
            return Unassigned(cp, offset)
    return None


def casefold_full(text: str) -> str:
    """Full case folding, UCD CaseFolding.txt statuses C + F, per code point.

    Not `str.casefold`: that uses the interpreter's table, which is the drift
    this module exists to remove.
    """
    _load()
    assert _casefold is not None
    table = _casefold
    out: List[str] = []
    for ch in text:
        folded = table.get(ord(ch))
        out.append(ch if folded is None else folded)
    return "".join(out)


def _decompose(text: str) -> List[int]:
    """Canonical decomposition followed by canonical ordering (UAX #15 D68)."""
    _load()
    assert _decomp is not None and _ccc is not None
    decomp, ccc = _decomp, _ccc
    out: List[int] = []

    def expand(cp: int) -> None:
        if _S_BASE <= cp < _S_BASE + _S_COUNT:
            i = cp - _S_BASE
            out.append(_L_BASE + i // _N_COUNT)
            out.append(_V_BASE + (i % _N_COUNT) // _T_COUNT)
            if i % _T_COUNT:
                out.append(_T_BASE + i % _T_COUNT)
            return
        d = decomp.get(cp)
        if d is None:
            out.append(cp)
            return
        for c in d:
            expand(c)

    for ch in text:
        expand(ord(ch))

    # Canonical ordering: a stable sort by combining class within each run of
    # non-starters. Stability matters -- equal classes keep their input order.
    i = 0
    n = len(out)
    while i < n:
        if ccc.get(out[i], 0) == 0:
            i += 1
            continue
        j = i
        while j < n and ccc.get(out[j], 0) != 0:
            j += 1
        out[i:j] = sorted(out[i:j], key=lambda c: ccc.get(c, 0))
        i = j
    return out


def _compose(cps: List[int]) -> str:
    """Canonical composition (UAX #15 D69)."""
    if not cps:
        return ""
    assert _ccc is not None and _comp is not None
    ccc, comp = _ccc, _comp

    out: List[int] = [cps[0]]
    starter = 0 if ccc.get(cps[0], 0) == 0 else -1
    last_cc = ccc.get(cps[0], 0)

    for cp in cps[1:]:
        cc = ccc.get(cp, 0)
        # `cp` is blocked from the last starter when something between them
        # has a combining class greater than or equal to its own.
        if starter >= 0 and (last_cc == 0 or last_cc < cc):
            base = out[starter]
            composite = None
            if (_L_BASE <= base < _L_BASE + _L_COUNT
                    and _V_BASE <= cp < _V_BASE + _V_COUNT):
                composite = _S_BASE + ((base - _L_BASE) * _V_COUNT
                                       + (cp - _V_BASE)) * _T_COUNT
            elif (_S_BASE <= base < _S_BASE + _S_COUNT
                  and (base - _S_BASE) % _T_COUNT == 0
                  and _T_BASE < cp < _T_BASE + _T_COUNT):
                composite = base + (cp - _T_BASE)
            else:
                composite = comp.get((base, cp))
            if composite is not None:
                out[starter] = composite
                continue          # `cp` is consumed; `last_cc` is unchanged
        out.append(cp)
        if cc == 0:
            starter = len(out) - 1
            last_cc = 0
        else:
            last_cc = cc

    return "".join(chr(c) for c in out)


def nfc(text: str) -> str:
    """Normalization Form C, at the pinned Unicode version."""
    _load()
    return _compose(_decompose(text))
