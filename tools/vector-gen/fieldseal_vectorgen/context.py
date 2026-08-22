"""Canonical context encoding and AAD construction (spec §6.2).

The presence bitmap is the part worth reading twice: an absent optional field
contributes nothing at all -- no length, no value -- while a present one
contributes its length prefix even when the length is zero. That is what makes
`tenant_id = None` and `tenant_id = b""` encode differently, which the earlier
positional form could not do.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .primitives import lv, u8

PRESENCE_TENANT_ID = 0x01
PRESENCE_ROW_ID = 0x02

PURPOSE_RE = re.compile(r"^(encrypt|index:[a-z0-9-]{1,32})$")


@dataclass(frozen=True)
class FieldContext:
    """Spec §6.1. `suite_id` is filled by the core, never by the caller."""

    suite_id: int
    table_uuid: bytes
    column_uuid: bytes
    purpose: str
    tenant_id: bytes | None = None
    row_id: bytes | None = None

    def __post_init__(self) -> None:
        if len(self.table_uuid) != 16 or len(self.column_uuid) != 16:
            raise ValueError("table_uuid and column_uuid are 16 bytes (spec §6.1)")
        if not PURPOSE_RE.match(self.purpose):
            raise ValueError(f"purpose outside the §6.1 grammar: {self.purpose!r}")

    def presence(self) -> int:
        bits = 0
        if self.tenant_id is not None:
            bits |= PRESENCE_TENANT_ID
        if self.row_id is not None:
            bits |= PRESENCE_ROW_ID
        return bits

    def for_index(self, index_id: str) -> "FieldContext":
        """The context §7.2 derives an index key under: purpose retargeted,
        row_id dropped. An index spans rows, so binding one to a row would make
        every lookup miss."""
        return FieldContext(
            suite_id=self.suite_id,
            table_uuid=self.table_uuid,
            column_uuid=self.column_uuid,
            purpose=f"index:{index_id}",
            tenant_id=self.tenant_id,
            row_id=None,
        )


def canonical_context(ctx: FieldContext) -> bytes:
    out = bytearray()
    out += u8(ctx.presence())
    out += lv(ctx.suite_id.to_bytes(2, "big"))
    out += lv(ctx.table_uuid)
    out += lv(ctx.column_uuid)
    if ctx.tenant_id is not None:
        out += lv(ctx.tenant_id)
    if ctx.row_id is not None:
        out += lv(ctx.row_id)
    out += lv(ctx.purpose.encode("ascii"))
    return bytes(out)


def aad(fmt_ver: int, key_id: bytes, msg_seed: bytes, ctx: FieldContext) -> bytes:
    """Spec §6.2. The envelope-bound fields enter here and only here."""
    return (
        lv(bytes([fmt_ver]))
        + lv(key_id)
        + lv(msg_seed)
        + canonical_context(ctx)
    )
