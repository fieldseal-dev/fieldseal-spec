"""Fieldseal Python core.

Nothing from `fieldseal.testing` is exported here, and importing this package
must not import it. `tests/test_arming_gates.py` enforces both.
"""

from __future__ import annotations

from . import errors
from .api import Fieldseal
from .blindindex import CardinalityOverride, IndexDeclaration
from .context import FieldContext
from .registry import SUITES, is_provisional

__all__ = ["Fieldseal", "FieldContext", "IndexDeclaration",
           "CardinalityOverride", "errors", "SUITES", "is_provisional"]
__version__ = "0.1.0.dev0"
