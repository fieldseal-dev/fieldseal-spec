"""Value <-> bytes, for the inner field's Python value (docs/12 §2, spec §3.6).

The core encrypts bytes. A Django field holds a `str`, an `int`, a `Decimal`,
a `date`. Something has to bridge those, and *what* it is is a security
decision rather than a convenience one.

**Never pickle.** Rails shipped `Marshal` as the serializer for encrypted
attributes, which turns any attacker who can write a ciphertext -- or any
operator restoring a doctored backup -- into remote code execution on
decrypt (`docs/04` §8). The codec here is fixed, non-executing, and refuses
types it does not know rather than reaching for a general serializer.

**The rendering is spec §3.6's, not Django's.** Until G25 (#123) this module
rendered through `get_prep_value()` and `str()`, which is CPython's text form
rather than any specified one: `Decimal("1.5")` and `Decimal("1.50")` became
different bytes and so different blind-index values, `True` became `b"True"`,
and a `float` rendered `1e+16` where the other adapter wrote
`10000000000000000`. Every inner field now maps to one of §3.6's eight logical
types (`logical_type`), the value goes through the inner field's own
`get_prep_value` / `to_python` for Django's input coercion, and the bytes are
§3.6's canonical rendering of the result. Reading is exactly as strict: bytes
that are not the canonical rendering are refused, never coerced.
"""

from __future__ import annotations

import datetime as dt
import math
import re
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from django.db import models

from .errors import FieldsealNotSupported

if TYPE_CHECKING:  # pragma: no cover - typing only
    from django.db.models import Field

#: The inner field classes each §3.6 logical type is reached through, checked
#: in this order. Order matters twice: `DateTimeField` subclasses `DateField`,
#: and `BooleanField` must win before anything numeric could claim it.
_MAPPING: tuple[tuple[type[Any], str], ...] = (
    (models.BinaryField, "bytes"),
    (models.BooleanField, "boolean"),
    (models.DateTimeField, "datetime"),
    (models.DateField, "date"),
    (models.DecimalField, "decimal"),
    (models.FloatField, "float"),
    (models.IntegerField, "int"),
    (models.CharField, "string"),
    (models.TextField, "string"),
)


def logical_type(field: Field[Any, Any]) -> str | None:
    """The spec §3.6 logical type `field` holds, or None if §3.6 pins none.

    `UUIDField`, `TimeField`, `DurationField`, `JSONField`,
    `GenericIPAddressField` and every other type return None, and
    `Encrypted()` refuses them at declaration: a refused column is a schema
    change, a column rendered by `str()` is a backfill once another language
    reads it differently.
    """
    for cls, name in _MAPPING:
        if isinstance(field, cls):
            return name
    return None


def to_bytes(field: Field[Any, Any], value: Any) -> bytes:
    """Serialize `value` for encryption under spec §3.6."""
    if value is None:
        raise FieldsealNotSupported(
            "None cannot be encrypted: a NULL column is indistinguishable "
            "from an absent value to every reader, so the adapter stores "
            "NULL as NULL rather than encrypting a placeholder that would "
            "claim the row has a value it does not"
        )
    kind = _require_type(field)
    try:
        return _RENDER[kind](field, value)
    except FieldsealNotSupported:
        raise
    except Exception as e:  # noqa: BLE001 - Django's coercion failed: typed refusal
        # Django's own coercion error quotes the input ("'abc' value must be
        # an integer"), so neither its text nor the exception itself travels
        # with this one: chained, it would print in every traceback. Spec §9:
        # an error message never includes plaintext.
        raise FieldsealNotSupported(
            f"{type(field).__name__} (§3.6 `{kind}`) could not take the "
            f"{type(value).__name__} it was given ({type(e).__name__}; its "
            "message is not repeated, since it can quote the value)"
        ) from None


def from_bytes(field: Field[Any, Any], raw: bytes, *,
               label: str | None = None, decrypted: bool = True) -> Any:
    """Inverse of `to_bytes`: refuse anything but the canonical rendering.

    `decrypted` says what `raw` is. True: the plaintext of an envelope that
    verified -- key, context and commitment all right -- so a refusal means
    the bytes were written by something that does not render §3.6, or the
    column's declared type changed after the row was written. False: the
    stored value was not an envelope and the core passed it through (spec
    §10.3), so nothing was decrypted and nothing was authenticated; a refusal
    means legacy plaintext that is not §3.6's rendering. Either way a coerced
    value would hide it. The message never carries the value (spec §9).
    """
    kind = _require_type(field)
    try:
        value = _PARSE[kind](raw)
    except _NotCanonical:
        raise _refuse(kind, label, decrypted) from None
    if kind in ("bytes", "string"):
        return value
    # A custom inner field may post-process its own type; the built-in ones
    # return the value unchanged.
    return field.to_python(value)


# -- write --------------------------------------------------------------------

def _render_string(field: Field[Any, Any], value: Any) -> bytes:
    prepared = field.get_prep_value(value)
    if not isinstance(prepared, str):
        raise FieldsealNotSupported(
            f"{type(field).__name__}.get_prep_value returned "
            f"{type(prepared).__name__}, not str")
    try:
        return prepared.encode("utf-8")
    except UnicodeEncodeError as e:
        raise FieldsealNotSupported(
            "the string contains an unpaired surrogate, which is not a Unicode "
            "scalar value and has no UTF-8 encoding (spec §3.6)") from e


def _render_bytes(field: Field[Any, Any], value: Any) -> bytes:
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value)
    raise FieldsealNotSupported(
        f"a BinaryField takes bytes, not {type(value).__name__}")


def _render_int(field: Field[Any, Any], value: Any) -> bytes:
    prepared = field.get_prep_value(value)
    if type(prepared) is not int:
        raise FieldsealNotSupported(f"not an int: {type(prepared).__name__}")
    return str(prepared).encode("ascii")


def _render_decimal(field: Field[Any, Any], value: Any) -> bytes:
    if isinstance(value, float):
        # DecimalField.to_python would round a float to the field's context;
        # §3.6 refuses rather than rounds.
        raise FieldsealNotSupported(
            "a float is not a decimal: pass Decimal or str so no binary64 "
            "rounding happens before the value is encrypted")
    prepared = field.get_prep_value(value)
    if not isinstance(prepared, Decimal):
        raise FieldsealNotSupported(f"not a Decimal: {type(prepared).__name__}")
    return render_decimal(prepared)


def _render_float(field: Field[Any, Any], value: Any) -> bytes:
    prepared = field.get_prep_value(value)
    if not isinstance(prepared, float):
        raise FieldsealNotSupported(f"not a float: {type(prepared).__name__}")
    return render_float(prepared)


def _render_boolean(field: Field[Any, Any], value: Any) -> bytes:
    prepared = field.get_prep_value(value)
    if not isinstance(prepared, bool):
        raise FieldsealNotSupported(f"not a bool: {type(prepared).__name__}")
    return b"true" if prepared else b"false"


def _render_date(field: Field[Any, Any], value: Any) -> bytes:
    if isinstance(value, dt.datetime):
        # DateField.to_python would convert an aware datetime to the default
        # time zone's date and drop the time; §3.6 refuses rather than truncates.
        raise FieldsealNotSupported(
            "a datetime is not a date: pass datetime.date, so the calendar "
            "date stored is the one the application chose")
    prepared = field.to_python(value)
    if not isinstance(prepared, dt.date) or isinstance(prepared, dt.datetime):
        raise FieldsealNotSupported(f"not a date: {type(prepared).__name__}")
    return prepared.isoformat().encode("ascii")


def _render_datetime(field: Field[Any, Any], value: Any) -> bytes:
    # `to_python`, not `get_prep_value`: under USE_TZ the latter makes a naive
    # value aware in the default zone, which is exactly the assumption §3.6
    # forbids.
    prepared = field.to_python(value)
    if not isinstance(prepared, dt.datetime):
        raise FieldsealNotSupported(f"not a datetime: {type(prepared).__name__}")
    if prepared.tzinfo is None or prepared.utcoffset() is None:
        raise FieldsealNotSupported(
            "a naive datetime has no instant: spec §3.6 refuses rather than "
            "assuming a time zone. Pass an aware datetime")
    try:
        u = prepared.astimezone(dt.UTC)
    except OverflowError as e:
        raise FieldsealNotSupported("outside years 0001-9999 in UTC") from e
    return (f"{u.year:04d}-{u.month:02d}-{u.day:02d}T{u.hour:02d}:"
            f"{u.minute:02d}:{u.second:02d}.{u.microsecond:06d}Z").encode("ascii")


def render_decimal(d: Decimal) -> bytes:
    """Spec §3.6 canonical decimal. From `as_tuple()`, never `normalize()`,
    which rounds to the 28-digit context precision."""
    if not d.is_finite():
        raise FieldsealNotSupported("a decimal must be finite")
    sign, digit_tuple, exp = d.as_tuple()
    assert isinstance(exp, int)
    digits = "".join(map(str, digit_tuple)).lstrip("0")
    if not digits:
        return b"0"
    stripped = digits.rstrip("0")
    exp += len(digits) - len(stripped)
    if exp >= 0:
        body = stripped + "0" * exp
    else:
        point = len(stripped) + exp
        body = (stripped[:point] + "." + stripped[point:] if point > 0
                else "0." + "0" * -point + stripped)
    return (("-" if sign else "") + body).encode("ascii")


def render_float(x: float) -> bytes:
    """Spec §3.6: ECMA-262 Number::toString(x), with negative zero as `-0`.

    `repr` is CPython's shortest round-trip digit string; this lays those
    digits out by ECMAScript's rules, which is where CPython differs (it
    writes `1e+16` and `1e-07` where ECMAScript writes `10000000000000000`
    and `1e-7`).
    """
    if not math.isfinite(x):
        raise FieldsealNotSupported("a float must be finite")
    if x == 0:
        return b"-0" if math.copysign(1.0, x) < 0 else b"0"
    if x < 0:
        return b"-" + render_float(-x)
    mant, _, e = repr(x).partition("e")
    ip, _, fp = mant.partition(".")
    raw = (ip + fp).lstrip("0")
    s = raw.rstrip("0")
    k = len(s)
    n = k + int(e or 0) - len(fp) + (len(raw) - k)
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * -n + s
    else:
        out = ((s if k == 1 else s[0] + "." + s[1:])
               + "e" + ("+" if n > 0 else "-") + str(abs(n - 1)))
    return out.encode("ascii")


# -- read ---------------------------------------------------------------------

_INT = re.compile(r"0|-?[1-9][0-9]*")
_DECIMAL = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?")
_FLOAT = re.compile(r"-?[0-9]+(\.[0-9]+)?(e[+-][0-9]+)?")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_DATETIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


class _NotCanonical(Exception):
    """The bytes are not §3.6's rendering. Carries nothing: `from_bytes` words
    the refusal, because only it knows whether the bytes were decrypted."""


def _refuse(kind: str, label: str | None,
            decrypted: bool) -> FieldsealNotSupported:
    where = f"{label}: " if label else ""
    if decrypted:
        return FieldsealNotSupported(
            f"{where}the decrypted value is not spec §3.6's canonical "
            f"`{kind}` rendering. The envelope was authentic, so this is not "
            "tampering: the row was written by something that does not "
            "render §3.6, or the column's declared type changed after it was "
            "written. Changing the type is a new plaintext encoding and "
            "needs a backfill, not an edit.")
    return FieldsealNotSupported(
        f"{where}the stored value is not an envelope: it is legacy plaintext "
        "the core passed through under the read mode (spec §10.3), and its "
        f"bytes are not this column's spec §3.6 `{kind}` rendering. Nothing "
        "was decrypted. Either the row needs migrating with the backfill "
        "(`tools/backfill/PROCEDURE.md`), or the column's declared type does "
        "not match what the legacy column holds.")


def _ascii(raw: bytes) -> str:
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        raise _NotCanonical() from None


def _parse_string(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _NotCanonical() from e


def _parse_int(raw: bytes) -> int:
    s = _ascii(raw)
    if not _INT.fullmatch(s):
        raise _NotCanonical()
    return int(s)


def _parse_decimal(raw: bytes) -> Decimal:
    s = _ascii(raw)
    if s == "-0" or not _DECIMAL.fullmatch(s):
        raise _NotCanonical()
    return Decimal(s)


def _parse_float(raw: bytes) -> float:
    s = _ascii(raw)
    if not _FLOAT.fullmatch(s):
        raise _NotCanonical()
    x = float(s)
    if not math.isfinite(x) or render_float(x) != raw:
        raise _NotCanonical()
    return x


def _parse_boolean(raw: bytes) -> bool:
    if raw == b"true":
        return True
    if raw == b"false":
        return False
    raise _NotCanonical()


def _parse_date(raw: bytes) -> dt.date:
    s = _ascii(raw)
    if not _DATE.fullmatch(s):
        raise _NotCanonical()
    try:
        return dt.date.fromisoformat(s)
    except ValueError as e:
        raise _NotCanonical() from e


def _parse_datetime(raw: bytes) -> dt.datetime:
    s = _ascii(raw)
    if not _DATETIME.fullmatch(s):
        raise _NotCanonical()
    try:
        return dt.datetime(int(s[0:4]), int(s[5:7]), int(s[8:10]),
                           int(s[11:13]), int(s[14:16]), int(s[17:19]),
                           int(s[20:26]), tzinfo=dt.UTC)
    except ValueError as e:  # year 0000, hour 24, second 60, February 30
        raise _NotCanonical() from e


_RENDER = {
    "string": _render_string, "bytes": _render_bytes, "int": _render_int,
    "decimal": _render_decimal, "float": _render_float,
    "boolean": _render_boolean, "date": _render_date,
    "datetime": _render_datetime,
}
_PARSE = {
    "string": _parse_string, "bytes": lambda raw: raw, "int": _parse_int,
    "decimal": _parse_decimal, "float": _parse_float,
    "boolean": _parse_boolean, "date": _parse_date,
    "datetime": _parse_datetime,
}


def _require_type(field: Field[Any, Any]) -> str:
    kind = logical_type(field)
    if kind is None:  # Encrypted() refuses these at declaration; defensive
        raise FieldsealNotSupported(unmapped_message(field))
    return kind


def unmapped_message(field: Field[Any, Any]) -> str:
    return (
        f"{type(field).__name__} has no spec §3.6 rendering. The pinned "
        "logical types are string (CharField, TextField and subclasses), "
        "bytes (BinaryField), int (IntegerField family), decimal "
        "(DecimalField), float (FloatField), boolean (BooleanField), date "
        "(DateField) and datetime (DateTimeField). Store anything else as a "
        "CharField holding a rendering your application owns.")
