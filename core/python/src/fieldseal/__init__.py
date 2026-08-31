"""Fieldseal Python core.

Nothing from `fieldseal.testing` is exported here, and importing this package
must not import it. `tests/test_arming_gates.py` enforces both.
"""

from __future__ import annotations

from . import errors
from .api import Fieldseal
from .blindindex import (
    NORMALIZER_IDS,
    Argon2Params,
    CardinalityOverride,
    IndexDeclaration,
    ValidatedIndex,
    index_registry_key,
    normalize,
    validate_index_declaration,
)
from .context import FieldContext
from .registry import SUITES, is_provisional

# `ValidatedIndex`, `validate_index_declaration` and `index_registry_key` are
# public as of G18: `Fieldseal.indexes` returns the first, and a caller
# comparing its own declarations against a client's registry needs the other
# two to build the same keys and resolve the same defaults. Reconstructing
# either by hand is the coupling the accessor exists to remove.
# docs/09 §7.1, normative: "Cores MUST still export the assigned-code-point
# check (`first_unassigned` / `firstUnassigned`) for adapters that hold the text
# earlier and can give a better-sited error." It lived in `fieldseal.unicode`
# and never reached this root, so the MUST had no public surface. G22 (#88).
# `UNICODE_VERSION` travels with it: an adapter rendering "not assigned in
# Unicode 17.0.0" needs the version the check was made against, and a constant
# of its own is how two copies drift apart.
from .unicode import UNICODE_VERSION, Unassigned, first_unassigned

__all__ = ["Fieldseal", "FieldContext", "IndexDeclaration", "ValidatedIndex",
           "Argon2Params", "CardinalityOverride", "index_registry_key",
           "validate_index_declaration", "normalize", "NORMALIZER_IDS",
           "first_unassigned", "Unassigned", "UNICODE_VERSION",
           "errors", "SUITES",
           "is_provisional"]
__version__ = "0.1.0.dev0"
