"""The cursor and the batch's select (PROCEDURE §5.1, §5.2 step 4).

Keyset pagination over the primary key, ascending; never `OFFSET`. Ordering
and comparison are the database's: the cursor is only ever compared by the
database that produced it.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

from django.db import models

from . import BackfillError


def _scalar_kind(field: Any) -> str | None:
    """§5.1's type of a key or tenant column, from its declared type."""
    if isinstance(field, models.UUIDField):
        return "uuid"
    if isinstance(field, models.IntegerField):
        return "int"
    if isinstance(field, models.CharField | models.TextField):
        return "text"
    return None


def key_field(model: Any) -> tuple[Any, str]:
    """The model's primary key and its §5.1 type, or a refusal."""
    name = model.__name__
    pk = model._meta.pk
    if pk is None or len(getattr(model._meta, "pk_fields", [pk])) != 1:
        raise BackfillError(
            f"{name} has no single-column primary key. The procedure's cursor "
            "is the primary key (PROCEDURE §5.1), and this frontend takes one "
            "key column.")
    kind = None if isinstance(pk, models.ForeignKey) else _scalar_kind(pk)
    if kind is None:
        raise BackfillError(
            f"{name}'s primary key is a {type(pk).__name__}. PROCEDURE §5.1 "
            "supports int, uuid and text key columns.")
    return pk, kind


def tenant_type(field: Any) -> str:
    """The §5.5 type of a tenant column, or a refusal.

    The frontend's mapping of the column's declared type, as `key_field`'s
    is, and not the operator's statement. A foreign key is its target's.
    """
    from ..fields import Encrypted, EncryptedIndex

    name = f"{field.model.__name__}.{field.name}"
    if isinstance(field, Encrypted | EncryptedIndex):
        raise BackfillError(
            f"{name} is a column the adapter encrypts, so it stores an "
            "envelope or an index value and not a tenant (PROCEDURE §5.5).")
    seen = field
    while isinstance(seen, models.ForeignKey):
        seen = seen.target_field
    kind = _scalar_kind(seen)
    if kind is not None:
        return kind
    if isinstance(seen, models.BinaryField):
        return "binary"
    raise BackfillError(
        f"{name} is a {type(seen).__name__}. PROCEDURE §5.5 takes a tenant "
        "column of type text, binary, int or uuid.")


_UUID_TEXT = re.compile(
    r"[0-9a-fA-F]{32}"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{12}")


def tenant_bytes(kind: str, value: Any) -> bytes | None:
    """The `tenant_id` of PROCEDURE §5.5's table, from a stored value.

    None means the row has no tenant, and the caller records
    `CONTEXT_UNAVAILABLE`. That is NULL; a stored value that is not of the
    column's type (SQLite keeps a value's old storage class after an
    `AlterField`, and coercing it, `bytes(5)` or `str(b"abc")`, would bind a
    tenant nobody has); and an empty text or binary value, which a
    provider may map to the same key scope as no tenant at all. Only these
    are taken:

    - binary: non-empty bytes, bytearray or memoryview;
    - text: a non-empty str;
    - int: int, but not bool;
    - uuid: `uuid.UUID`, or a str that is 32 hex digits or the canonical
      hyphenated form and nothing else.

    Int and uuid are rendered as §5.1 renders a key (`encode`).
    """
    if value is None:
        return None
    if kind == "binary":
        if isinstance(value, bytes | bytearray | memoryview) and len(value):
            return bytes(value)
        return None
    if kind == "text":
        if isinstance(value, str) and value:
            return value.encode("utf-8")
        return None
    if kind == "int":
        if isinstance(value, int) and not isinstance(value, bool):
            return encode(kind, value).encode("ascii")
        return None
    if kind == "uuid":
        if isinstance(value, uuid.UUID) or (
                isinstance(value, str) and _UUID_TEXT.fullmatch(value)):
            return encode(kind, value).encode("ascii")
        return None
    return None


def encode(kind: str, value: Any) -> str:
    """One key value in §5.1's encoding."""
    if kind == "int":
        return str(int(value))
    if kind == "uuid":
        return str(value if isinstance(value, uuid.UUID) else uuid.UUID(value))
    return str(value)


def decode(kind: str, text: str) -> Any:
    if kind == "int":
        return int(text)
    if kind == "uuid":
        return uuid.UUID(text)
    return text


def encode_key(kind: str, value: Any) -> str:
    """`cursor_value` / `row_key`: a JSON array of strings, one per column."""
    return json.dumps([encode(kind, value)])


def decode_key(kind: str, text: str) -> Any:
    (only,) = json.loads(text)
    return decode(kind, only)


@dataclass(frozen=True)
class Row:
    key: Any
    #: The stored value of each target column, as the driver returned it.
    stored: tuple[Any, ...]
    #: For each target, whether its legacy source column is NULL (None when
    #: the target is in place).
    source_null: tuple[bool | None, ...]
    #: The stored value of the tenant column, as the driver returned it
    #: (None when the run has no tenant column, or the row's is NULL).
    tenant: Any = None


def select_batch(
    connection: Any,
    model: Any,
    pk: Any,
    targets: list[tuple[Any, Any]],
    *,
    after: Any,
    limit: int,
    lock: bool,
    tenant: Any = None,
) -> list[Row]:
    """Up to `limit` rows with key greater than `after`, in key order.

    Reads the **stored** bytes of each target column, which the ORM cannot
    give: `values()` and `raw()` both decrypt. With `lock`, the rows are
    locked against concurrent writers until commit where the database has
    `SELECT ... FOR UPDATE`, and locked rows are waited for, never skipped;
    on SQLite the batch's `BEGIN IMMEDIATE` is the lock.

    `tenant` is the run's tenant column (PROCEDURE §5.5), selected once, in
    this same locked statement, so a row's tenant cannot change between the
    read and the write.

    Only a legacy source column's NULL-ness is read here. Its value is read
    through the ORM (PROCEDURE §6.3 rule 1).
    """
    q = connection.ops.quote_name
    select = [q(pk.column)]
    for field, source in targets:
        select.append(q(field.column))
        if source is not None:
            select.append(
                f"CASE WHEN {q(source.column)} IS NULL THEN 1 ELSE 0 END")
    if tenant is not None:
        select.append(q(tenant.column))
    sql = f"SELECT {', '.join(select)} FROM {q(model._meta.db_table)}"
    params: list[Any] = []
    if after is not None:
        sql += f" WHERE {q(pk.column)} > %s"
        params.append(pk.get_db_prep_value(after, connection))
    sql += f" ORDER BY {q(pk.column)} LIMIT {int(limit)}"
    if lock and connection.features.has_select_for_update:
        sql += " " + connection.ops.for_update_sql()
    with connection.cursor() as cur:
        cur.execute(sql, params)
        fetched = cur.fetchall()
    rows = []
    for record in fetched:
        values = iter(record[1:])
        stored, source_null = [], []
        for _, source in targets:
            stored.append(next(values))
            source_null.append(
                None if source is None else bool(next(values)))
        rows.append(Row(pk.to_python(record[0]), tuple(stored),
                        tuple(source_null),
                        None if tenant is None else next(values)))
    return rows


def stored_bytes(value: Any, storage: str) -> bytes | None:
    """`T` of PROCEDURE §6.2: the stored value as bytes, base64 decoded.

    None means "not an envelope whatever it is": a `base64` column whose
    value does not decode. Decoding is strict, the same decode the
    adapter's read makes (#245), and this result only ever feeds
    `is_ciphertext` (PROCEDURE §6.2).
    """
    if storage == "base64":
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError, TypeError):
            return None
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytes | bytearray):
        return bytes(value)
    return None
