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

from ..context import FieldContext
from ..errors import ModeViolation

_ARMED = os.environ.get("FIELDSEAL_TEST_MODE") == "1"


def _require_armed() -> None:
    if not _ARMED:
        raise ModeViolation(
            "fieldseal.testing is inert: set FIELDSEAL_TEST_MODE=1 before "
            "import to arm determinism injection (docs/08 §6). An "
            "implementation that accepts a caller-supplied nonce or seed "
            "outside vector-test mode is non-conformant.")


def encrypt_with_materials(client, plaintext: bytes, ctx: FieldContext,
                           msg_seed: bytes, nonce: bytes) -> bytes:
    """The full production pipeline except CSPRNG generation -- same KDF, same
    AAD, same commitment, same assembly (docs/08 §6)."""
    _require_armed()
    from ..registry import SUITES

    suite = SUITES[client._write_suite]
    if len(msg_seed) != 32:
        raise ValueError("msg_seed is 32 bytes (spec §3.1)")
    if len(nonce) != suite.nonce_len:
        raise ValueError(f"suite {suite.suite_id:#06x} takes a "
                         f"{suite.nonce_len}-byte nonce")
    bound = ctx.with_suite(client._write_suite)
    key_id, tenant_dek = client._provider.dek_for(bound)
    return client._assemble(suite, bound, tenant_dek, key_id, msg_seed,
                            nonce, plaintext)
