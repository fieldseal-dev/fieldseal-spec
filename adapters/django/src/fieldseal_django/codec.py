"""Value <-> bytes, for the inner field's Python value (docs/12 §2).

The core encrypts bytes. A Django field holds a `str`, an `int`, a `Decimal`,
a `date`. Something has to bridge those, and *what* it is is a security
decision rather than a convenience one.

**Never pickle.** Rails shipped `Marshal` as the serializer for encrypted
attributes, which turns any attacker who can write a ciphertext -- or any
operator restoring a doctored backup -- into remote code execution on
decrypt (`docs/04` §8). The codec here is fixed, non-executing, and refuses
types it does not know rather than reaching for a general serializer.

The encoding is Django's own `value_to_string` contract wherever it exists,
so a value that round-trips through `dumpdata`/`loaddata` today round-trips
through encryption too, and the bytes are the field's documented text form
rather than a private format this package invented.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .errors import FieldsealNotSupported

if TYPE_CHECKING:  # pragma: no cover - typing only
    from django.db.models import Field

#: Serializers whose output is a plain `str` we encode as UTF-8. Anything not
#: reachable through one of these is refused: an adapter that guessed here
#: would produce bytes one language can write and another cannot read, which
#: is the failure the whole project exists to prevent.
_TEXT_TYPES = (str,)


def to_bytes(field: Field[Any, Any], value: Any) -> bytes:
    """Serialize `value` for encryption, using `field` for the type rules.

    `bytes` passes through untouched -- a `BinaryField` inner type is already
    in the target representation, and re-encoding it would be lossy.
    """
    if value is None:
        raise FieldsealNotSupported(
            "None cannot be encrypted: a NULL column is indistinguishable "
            "from an absent value to every reader, so the adapter stores "
            "NULL as NULL rather than encrypting a placeholder that would "
            "claim the row has a value it does not"
        )
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    if isinstance(value, _TEXT_TYPES):
        return value.encode("utf-8")

    # Everything else goes through the inner field's own text form. Django
    # implements `value_to_string` on a model instance, so the value is
    # adapted through `get_prep_value` first and rendered by the field's
    # documented rules -- dates as ISO-8601, decimals without float error.
    try:
        prepared = field.get_prep_value(value)
    except Exception as e:  # noqa: BLE001 - re-raised as a typed refusal
        raise FieldsealNotSupported(
            f"{type(field).__name__} could not prepare "
            f"{type(value).__name__} for storage: {e}"
        ) from e
    if isinstance(prepared, _TEXT_TYPES):
        return prepared.encode("utf-8")
    if isinstance(prepared, bytes):
        return prepared
    if prepared is None:
        raise FieldsealNotSupported(
            f"{type(field).__name__}.get_prep_value returned None for a "
            f"non-None value of type {type(value).__name__}"
        )
    # int, float, Decimal, date, datetime, UUID, bool all land here and all
    # have a lossless str() under their prepared form.
    return str(prepared).encode("utf-8")


def from_bytes(field: Field[Any, Any], raw: bytes) -> Any:
    """Inverse of `to_bytes`, delegating the type work to the inner field.

    `to_python` is the right hook rather than `from_db_value`: the value has
    already come back from the database and been decrypted, so what is left
    is exactly the "coerce this text into the field's Python type" job that
    `to_python` is defined to do, and it is the hook a custom inner field is
    documented to override.
    """
    if _is_binary_field(field):
        return raw
    try:
        return field.to_python(raw.decode("utf-8"))
    except UnicodeDecodeError as e:
        # The plaintext is not UTF-8, which means it was not written by this
        # codec. Say so rather than surfacing a decode error from three
        # frames down, because the likely cause is a column encrypted by
        # something else or a codec change between write and read.
        raise FieldsealNotSupported(
            "decrypted bytes are not valid UTF-8, so they were not written "
            "by this adapter's codec; a BinaryField inner type stores raw "
            "bytes, every other inner type stores UTF-8"
        ) from e


def _is_binary_field(field: Field[Any, Any]) -> bool:
    return bool(field.get_internal_type() == "BinaryField")
