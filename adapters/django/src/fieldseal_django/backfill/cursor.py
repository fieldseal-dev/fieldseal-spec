"""The cursor and the batch's select (PROCEDURE §5.1, §5.2 step 4).

Keyset pagination over the primary key, ascending; never `OFFSET`. Ordering
and comparison are the database's: the cursor is only ever compared by the
database that produced it.
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from dataclasses import dataclass
from typing import Any

from django.db import models

from . import BackfillError


def key_field(model: Any) -> tuple[Any, str]:
    """The model's primary key and its §5.1 type, or a refusal."""
    name = model.__name__
    pk = model._meta.pk
    if pk is None or len(getattr(model._meta, "pk_fields", [pk])) != 1:
        raise BackfillError(
            f"{name} has no single-column primary key. The procedure's cursor "
            "is the primary key (PROCEDURE §5.1), and this frontend takes one "
            "key column.")
    if isinstance(pk, models.ForeignKey):
        kind = None
    elif isinstance(pk, models.UUIDField):
        kind = "uuid"
    elif isinstance(pk, models.IntegerField):
        kind = "int"
    elif isinstance(pk, models.CharField | models.TextField):
        kind = "text"
    else:
        kind = None
    if kind is None:
        raise BackfillError(
            f"{name}'s primary key is a {type(pk).__name__}. PROCEDURE §5.1 "
            "supports int, uuid and text key columns in version 1.")
    return pk, kind


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


def select_batch(
    connection: Any,
    model: Any,
    pk: Any,
    targets: list[tuple[Any, Any]],
    *,
    after: Any,
    limit: int,
    lock: bool,
) -> list[Row]:
    """Up to `limit` rows with key greater than `after`, in key order.

    Reads the **stored** bytes of each target column, which the ORM cannot
    give: `values()` and `raw()` both decrypt. With `lock`, the rows are
    locked against concurrent writers until commit where the database has
    `SELECT ... FOR UPDATE`, and locked rows are waited for, never skipped;
    on SQLite the batch's `BEGIN IMMEDIATE` is the lock.

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
                        tuple(source_null)))
    return rows


def stored_bytes(value: Any, storage: str) -> bytes | None:
    """`T` of PROCEDURE §6.2: the stored value as bytes, base64 decoded.

    None means "not an envelope whatever it is": a `base64` column whose
    value does not decode. Decoding is strict here, unlike the adapter's
    read (#245), because this result only ever feeds `is_ciphertext`.
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
