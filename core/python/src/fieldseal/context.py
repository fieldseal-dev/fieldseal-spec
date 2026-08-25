"""FieldContext, canonical_context and AAD (spec §6.1, §6.2)."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from .errors import ConfigurationError

PRESENCE_TENANT_ID = 0x01
PRESENCE_ROW_ID = 0x02

_PURPOSE_RE = re.compile(r"\A(encrypt|index:[a-z0-9-]{1,32})\Z")


def _u64be(n: int) -> bytes:
    return n.to_bytes(8, "big")


def _lv(value: bytes) -> bytes:
    return _u64be(len(value)) + value


@dataclass(frozen=True, slots=True)
class FieldContext:
    table_uuid: bytes
    column_uuid: bytes
    purpose: str = "encrypt"
    tenant_id: bytes | None = None
    row_id: bytes | None = None
    # Filled by the core, never by the caller (docs/09 §3.2 step 4): the write
    # suite on encrypt, the parsed header's suite on decrypt.
    suite_id: int | None = None

    def __post_init__(self) -> None:
        if len(self.table_uuid) != 16:
            raise ConfigurationError("table_uuid must be 16 bytes (spec §6.1)")
        if len(self.column_uuid) != 16:
            raise ConfigurationError("column_uuid must be 16 bytes (spec §6.1)")
        if not _PURPOSE_RE.match(self.purpose):
            raise ConfigurationError(
                f"purpose {self.purpose!r} is outside the §6.1 grammar")

    def with_suite(self, suite_id: int) -> "FieldContext":
        return replace(self, suite_id=suite_id)

    def for_index(self, index_id: str) -> "FieldContext":
        """Spec §7.2: retarget purpose, drop row_id. An index spans rows, so
        binding one to a row would make every lookup miss."""
        return replace(self, purpose=f"index:{index_id}", row_id=None)

    @property
    def index_id(self) -> str | None:
        """The index-id this context names, or None for any other purpose.

        `__post_init__` has already checked `purpose` against the §6.1
        grammar, so anything carrying the prefix carries a well-formed id."""
        prefix = "index:"
        if not self.purpose.startswith(prefix):
            return None
        return self.purpose[len(prefix):]

    @property
    def presence(self) -> int:
        bits = 0
        if self.tenant_id is not None:
            bits |= PRESENCE_TENANT_ID
        if self.row_id is not None:
            bits |= PRESENCE_ROW_ID
        return bits


def canonical_context(ctx: FieldContext) -> bytes:
    """Spec §6.2. An absent optional field contributes nothing at all; a
    present one contributes its length prefix even at zero length. That is what
    keeps `tenant_id=None` and `tenant_id=b""` distinct."""
    if ctx.suite_id is None:
        raise ConfigurationError(
            "suite_id is unset; the core fills it, callers must not")
    out = bytearray()
    out.append(ctx.presence)
    out += _lv(ctx.suite_id.to_bytes(2, "big"))
    out += _lv(ctx.table_uuid)
    out += _lv(ctx.column_uuid)
    if ctx.tenant_id is not None:
        out += _lv(ctx.tenant_id)
    if ctx.row_id is not None:
        out += _lv(ctx.row_id)
    out += _lv(ctx.purpose.encode("ascii"))
    return bytes(out)


def aad(fmt_ver: int, key_id: bytes, msg_seed: bytes,
        ctx: FieldContext) -> bytes:
    """Spec §6.2. The envelope-bound fields enter here and nowhere else."""
    return (_lv(bytes([fmt_ver])) + _lv(key_id) + _lv(msg_seed)
            + canonical_context(ctx))
