"""Fieldseal Python core.

Nothing from `fieldseal.testing` is exported here, and importing this package
must not import it. `tests/test_arming_gates.py` enforces both.
"""

from __future__ import annotations

from . import errors
from .api import Fieldseal
from .blindindex import (
    Argon2Params,
    CardinalityOverride,
    IndexDeclaration,
    ValidatedIndex,
    index_registry_key,
    validate_index_declaration,
)
from .context import FieldContext
from .registry import SUITES, is_provisional

# `ValidatedIndex`, `validate_index_declaration` and `index_registry_key` are
# public as of G18: `Fieldseal.indexes` returns the first, and a caller
# comparing its own declarations against a client's registry needs the other
# two to build the same keys and resolve the same defaults. Reconstructing
# either by hand is the coupling the accessor exists to remove.
__all__ = ["Fieldseal", "FieldContext", "IndexDeclaration", "ValidatedIndex",
           "Argon2Params", "CardinalityOverride", "index_registry_key",
           "validate_index_declaration", "errors", "SUITES",
           "is_provisional"]
__version__ = "0.1.0.dev0"
