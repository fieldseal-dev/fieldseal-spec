"""The configuration document and its comparison (PROCEDURE §4).

A resumed run must write what the run it resumes was writing, so a run
records what decides its stored bytes and refuses to resume under anything
else. Nothing operational is in here: batch size, rate and `max_failures`
may change on resume.
"""

from __future__ import annotations

import json
from typing import Any

from fieldseal import index_registry_key

from . import PROCEDURE_VERSION, BackfillError
from .confighash import sha256_hex


def build(
    *,
    job: str,
    table_uuid: bytes,
    write_suite: int,
    cursor: list[tuple[str, str]],
    targets: list[tuple[Any, str | None]],
    indexes: Any,
) -> dict[str, Any]:
    """The `config` object for a run.

    `targets` is `(Encrypted field, legacy column name or None)`; `indexes`
    is the client's **validated** registry, which is where an index's
    resolved parameters are read from, never the declaration as written.
    """
    columns = []
    for field, source in targets:
        entries = []
        if job == "encrypt" and field.index is not None:
            validated = indexes[index_registry_key(
                table_uuid, field.column_uuid, field.index.index_id)]
            argon2 = validated.argon2
            entries.append({
                "index_id": validated.index_id,
                "idf": validated.idf,
                "argon2": None if argon2 is None else {
                    "memory_kib": argon2.memory_kib,
                    "time_cost": argon2.time_cost,
                },
                "normalize": validated.normalize,
                "truncate_bits": validated.truncate_bits,
                "on_unindexable": validated.on_unindexable,
                # The registry has no storage member: `EncryptedIndex` is a
                # `BinaryField`, and this adapter has no hex form.
                "storage": "binary",
            })
        columns.append({
            "column_uuid": field.column_uuid.hex(),
            "logical_type": field.logical_type,
            "storage": field.storage,
            "source": source,
            "indexes": sorted(entries, key=lambda e: str(e["index_id"])),
        })
    return {
        "procedure_version": PROCEDURE_VERSION,
        "job": job,
        "table_uuid": table_uuid.hex(),
        "write_suite": write_suite,
        "cursor": [{"name": name, "type": kind} for name, kind in cursor],
        "columns": sorted(columns, key=lambda c: str(c["column_uuid"])),
    }


def serialize(config: Any) -> str:
    """PROCEDURE §4's serialization. Refuses what it cannot write unescaped."""
    _check(config)
    return json.dumps(config, sort_keys=True, separators=(",", ":"))


def digest(text: str) -> str:
    return sha256_hex(text.encode("ascii"))


def _check(value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool):
        raise BackfillError("a configuration member is a boolean")
    if isinstance(value, int):
        if value < 0:
            raise BackfillError("a configuration integer is negative")
        return
    if isinstance(value, str):
        if any(not 0x20 <= ord(ch) <= 0x7E or ch in '"\\' for ch in value):
            raise BackfillError(
                f"the name {value!r} cannot be recorded: PROCEDURE §4 takes "
                "ASCII 0x20-0x7E without a double quote or a backslash, so "
                "that the configuration is hashed with no escape in it.")
        return
    if isinstance(value, list):
        for item in value:
            _check(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _check(key)
            _check(item)
        return
    raise BackfillError(
        f"a configuration member is a {type(value).__name__}")


def differences(stored: Any, live: Any, path: str = "") -> list[str]:
    """The members at which `live` differs from `stored`, by name.

    Names and parameters only; there is nothing secret in `config`.
    """
    if isinstance(stored, dict) and isinstance(live, dict):
        out: list[str] = []
        for key in sorted(set(stored) | set(live)):
            where = f"{path}.{key}" if path else str(key)
            if key not in stored or key not in live:
                out.append(where)
            else:
                out.extend(differences(stored[key], live[key], where))
        return out
    if isinstance(stored, list) and isinstance(live, list):
        label = _label(path)
        if label is None:
            if len(stored) != len(live):
                return [path]
            out = []
            for i, (a, b) in enumerate(zip(stored, live, strict=True)):
                out.extend(differences(a, b, f"{path}[{i}]"))
            return out
        a_by = {item.get(label): item for item in stored}
        b_by = {item.get(label): item for item in live}
        out = []
        for key in sorted(set(a_by) | set(b_by), key=str):
            where = f"{path}[{key}]"
            if key not in a_by or key not in b_by:
                out.append(where)
            else:
                out.extend(differences(a_by[key], b_by[key], where))
        return out
    return [] if stored == live and type(stored) is type(live) else [path]


def _label(path: str) -> str | None:
    """The member that identifies an element of the list at `path`."""
    if path == "columns":
        return "column_uuid"
    if path.endswith(".indexes"):
        return "index_id"
    return None
