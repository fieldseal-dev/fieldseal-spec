"""Index declarations and the `"declaration"` assertion (docs/08 §4, #210, #211).

A declaration refusal is a configuration-level outcome: the core rejects the
index when it is declared, and no §9 error code exists for that (docs/09 §9).
So the vector asserts *refused* or *accepted* and deliberately names no code.
It is not the `codec/` family's `{"refused": true}` (an adapter that does not
support a type), and it is not an `errors/` vector (those name a §9 code).

The rules below are written from the specification text, not from either core:
spec §6.1's `index-id` grammar, §7.4's truncation band, and §7.6's
default-deny gate with its recorded override. `violations()` returns every rule
a declaration breaks, and generation asserts that a refused case breaks exactly
the one rule it is about -- a case refused for two reasons pins neither, since
a core that enforced only the other rule would still pass it.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from . import inputs as I

INDEX_ID_RE = re.compile(r"\A[a-z0-9-]{1,32}\Z")  # spec §6.1, ASCII only
CARDINALITY_GATE = 1 << 10                          # spec §7.6
RAW_BITS = 64 * 8                                   # both IDFs emit 64 bytes

# A recorded override (spec §7.6): all three fields present and non-empty.
OVERRIDE = {"reason": "vector: reviewed low-cardinality column",
            "approved_by": "vectors", "date": "2026-09-27"}


@dataclass(frozen=True)
class Declaration:
    """docs/09 §7 `IndexDeclaration`, every field explicit (docs/08 §1.3)."""

    index_id: str
    projected_population: int
    truncate_bits: int
    skewed: bool = False
    cardinality_override: dict | None = None
    idf: str = "hmac-sha512"
    normalize: str = "identity"
    on_unindexable: str = "refuse"
    table_uuid: bytes = field(default=I.TABLE_UUID)
    column_uuid: bytes = field(default=I.COLUMN_UUID)

    def to_json(self) -> dict:
        return {
            "table_uuid": self.table_uuid.hex(),
            "column_uuid": self.column_uuid.hex(),
            "index_id": self.index_id,
            "idf": self.idf,
            "idf_params": {},
            "normalize": self.normalize,
            "truncate_bits": self.truncate_bits,
            "projected_population": self.projected_population,
            "skewed": self.skewed,
            "cardinality_override": self.cardinality_override,
            "on_unindexable": self.on_unindexable,
        }


def _recorded(o: dict | None) -> bool:
    return o is not None and all(o.get(k) for k in
                                 ("reason", "approved_by", "date"))


def violations(d: Declaration) -> list[str]:
    """Every rule `d` breaks, by name. Empty means the declaration is valid."""
    out = []
    if not INDEX_ID_RE.match(d.index_id):
        out.append("§6.1 index-id")
    p, b = d.projected_population, d.truncate_bits
    if p < 16 or not 1 <= b <= RAW_BITS or not (2 <= p / 2 ** b < math.sqrt(p)):
        out.append("§7.4 band")
    if (p < CARDINALITY_GATE or d.skewed) and not _recorded(
            d.cardinality_override):
        out.append("§7.6 gate")
    return out


def vector(vid: str, description: str, spec_ref: str, d: Declaration,
           expect: str, rule: str | None) -> dict:
    """One `"declaration"` vector. `rule` is the single rule a refused case
    breaks; generation fails if the declaration breaks any other, or if an
    accepted case breaks any rule at all."""
    found = violations(d)
    if expect == "refused":
        assert found == [rule], f"{vid}: refused for {found}, not only {rule}"
    else:
        assert expect == "accepted" and rule is None and not found, (
            f"{vid}: an accepted case breaks {found}")
    return {
        "id": vid,
        "description": description,
        "spec_ref": spec_ref,
        "assertion": "declaration",
        "suite_id": "0xFF01",
        "inputs": {"declaration": d.to_json()},
        "expected": {"declaration": expect},
    }
