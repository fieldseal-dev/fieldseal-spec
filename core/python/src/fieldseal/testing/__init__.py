"""Determinism injection for vector reproduction (docs/08 §6).

Inert unless armed: every function here raises unless FIELDSEAL_TEST_MODE=1 is
set when this module is imported.

From `vectors/README.md`, verbatim, because it is the whole reason this module
is quarantined rather than convenient:

    an implementation that accepts a caller-supplied nonce or seed outside of
    vector-test mode is non-conformant

The production `Fieldseal.encrypt` accepts no seed or nonce parameter in any
form -- not a keyword, not a config field. This module reaches the same
assembly path from outside, and it is a separate subpackage so that
`import fieldseal` does not pull it in.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from ..context import FieldContext
from ..errors import ModeViolation

if TYPE_CHECKING:
    from ..api import Fieldseal

_ARMED = os.environ.get("FIELDSEAL_TEST_MODE") == "1"


def _require_armed() -> None:
    if not _ARMED:
        raise ModeViolation(
            "fieldseal.testing is inert: set FIELDSEAL_TEST_MODE=1 before "
            "import to arm determinism injection (docs/08 §6). An "
            "implementation that accepts a caller-supplied nonce or seed "
            "outside vector-test mode is non-conformant.")


def encrypt_with_materials(client: Fieldseal, plaintext: bytes, ctx: FieldContext,
                           msg_seed: bytes, nonce: bytes) -> bytes:
    """The full production pipeline except CSPRNG generation -- same boundary
    gates, same KDF, same AAD, same commitment, same assembly (docs/08 §6).

    docs/09 §3.1: this "replaces exactly [the two entropy draws] and nothing
    else". In particular it does not bypass the API boundary: a readonly
    client refuses with MODE_VIOLATION, an unarmed one with SUITE_PROVISIONAL,
    an over-bound plaintext with LENGTH_EXCEEDED -- exactly as `encrypt` would.
    A seam that skipped the gates would let a harness certify an
    implementation whose gates do not work.
    """
    _require_armed()
    suite = client._write_boundary(plaintext, ctx)
    if len(msg_seed) != 32:
        raise ValueError("msg_seed is 32 bytes (spec §3.1)")
    if len(nonce) != suite.nonce_len:
        raise ValueError(f"suite {suite.suite_id:#06x} takes a "
                         f"{suite.nonce_len}-byte nonce")
    return client._encrypt_with(suite, plaintext, ctx, msg_seed, nonce)
