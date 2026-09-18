"""Spec §3.6: logical-type rendering, as the generator's own implementation.

The rules are written here from the specification text and nothing else. The
two adapter codecs are separate implementations of the same section; this one
exists so that the `codec/` family's expected values come from a third place
rather than from either adapter checking itself (docs/08 §7's principle, one
layer up).

Every renderer raises `Refused` where §3.6 says a writer MUST refuse, and every
parser raises it where a reader MUST. Neither ever coerces.
"""

from __future__ import annotations

import math
import re
import struct
from datetime import date, datetime, timezone
from decimal import Decimal


class Refused(ValueError):
    """§3.6 refusal: the value or the bytes are outside what the type admits."""


# -- string / bytes -----------------------------------------------------------

def render_string(s: str) -> bytes:
    try:
        # CPython's strict UTF-8 codec refuses surrogate code points, which is
        # exactly §3.6's "not a sequence of Unicode scalar values".
        return s.encode("utf-8")
    except UnicodeEncodeError as e:
        raise Refused(f"not a sequence of Unicode scalar values: {e.reason}") from e


def parse_string(b: bytes) -> str:
    try:
        return b.decode("utf-8")  # strict: overlongs and encoded surrogates refused
    except UnicodeDecodeError as e:
        raise Refused(f"not UTF-8: {e.reason}") from e


# -- int ----------------------------------------------------------------------

_INT = re.compile(r"0|-?[1-9][0-9]*")


def render_int(n: int) -> bytes:
    return str(n).encode("ascii")


def parse_int(b: bytes) -> int:
    s = _ascii(b)
    if not _INT.fullmatch(s):
        raise Refused(f"not a canonical int: {s!r}")
    return int(s)


# -- decimal ------------------------------------------------------------------

_DECIMAL = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?")


def render_decimal(d: Decimal) -> bytes:
    """Canonical by value. Works from `as_tuple()`, never from `normalize()`,
    because `normalize()` rounds to the context precision (28 digits)."""
    if not d.is_finite():
        raise Refused(f"not finite: {d!r}")
    sign, digit_tuple, exp = d.as_tuple()
    assert isinstance(exp, int)
    digits = "".join(map(str, digit_tuple)).lstrip("0")
    if not digits:
        return b"0"
    stripped = digits.rstrip("0")
    exp += len(digits) - len(stripped)
    digits = stripped
    if exp >= 0:
        body = digits + "0" * exp
    else:
        point = len(digits) + exp
        body = (digits[:point] + "." + digits[point:] if point > 0
                else "0." + "0" * (-point) + digits)
    return (("-" if sign else "") + body).encode("ascii")


def parse_decimal(b: bytes) -> Decimal:
    s = _ascii(b)
    if s == "-0" or not _DECIMAL.fullmatch(s):
        raise Refused(f"not a canonical decimal: {s!r}")
    return Decimal(s)


# -- float --------------------------------------------------------------------

_FLOAT_SHAPE = re.compile(r"-?[0-9]+(\.[0-9]+)?(e[+-][0-9]+)?")


def render_float(x: float) -> bytes:
    """ECMA-262 Number::toString(x), radix 10, with negative zero as `-0`.

    CPython's `repr` yields the shortest digit string that round-trips, which
    is the `k`-minimal `s` the ECMAScript algorithm asks for; this function
    only re-lays those digits out by ECMAScript's rules.
    """
    if not math.isfinite(x):
        raise Refused(f"not finite: {x!r}")
    if x == 0:
        return b"-0" if math.copysign(1.0, x) < 0 else b"0"
    if x < 0:
        return b"-" + render_float(-x)
    mant, _, e = repr(x).partition("e")
    ip, _, fp = mant.partition(".")
    raw = (ip + fp).lstrip("0")
    s = raw.rstrip("0")
    exp10 = int(e or 0) - len(fp) + (len(raw) - len(s))  # x = int(s) * 10**exp10
    k = len(s)
    n = k + exp10
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s
    else:
        sign = "+" if n - 1 >= 0 else "-"
        out = (s if k == 1 else s[0] + "." + s[1:]) + "e" + sign + str(abs(n - 1))
    return out.encode("ascii")


def parse_float(b: bytes) -> float:
    s = _ascii(b)
    if not _FLOAT_SHAPE.fullmatch(s):
        raise Refused(f"not a float rendering: {s!r}")
    x = float(s)
    if not math.isfinite(x) or render_float(x) != b:
        raise Refused(f"not the canonical rendering of the value it parses to: {s!r}")
    return x


def float_bits(x: float) -> str:
    return struct.pack(">d", x).hex()


def float_from_bits(h: str) -> float:
    return struct.unpack(">d", bytes.fromhex(h))[0]


# -- boolean ------------------------------------------------------------------

def render_boolean(v: bool) -> bytes:
    return b"true" if v else b"false"


def parse_boolean(b: bytes) -> bool:
    if b == b"true":
        return True
    if b == b"false":
        return False
    raise Refused(f"not a canonical boolean: {b!r}")


# -- date / datetime ----------------------------------------------------------

_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_DATETIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


def render_date(d: date) -> bytes:
    if isinstance(d, datetime):
        raise Refused("a datetime is not a date")
    return d.isoformat().encode("ascii")  # CPython's date is already 0001..9999


def parse_date(b: bytes) -> date:
    s = _ascii(b)
    if not _DATE.fullmatch(s):
        raise Refused(f"not a canonical date: {s!r}")
    try:
        return date.fromisoformat(s)
    except ValueError as e:  # 0000-01-01, 2026-02-30
        raise Refused(f"not a calendar date: {s!r}") from e


def render_datetime(dt: datetime) -> bytes:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise Refused("a naive datetime has no instant; refusing to assume a zone")
    try:
        u = dt.astimezone(timezone.utc)
    except OverflowError as e:  # 0001-01-01T00:30+01:00 is in year 0 UTC
        raise Refused("outside years 0001-9999 once expressed in UTC") from e
    # Explicit fields rather than strftime: glibc's %Y does not zero-pad
    # years below 1000, and §3.6 requires four digits.
    return (f"{u.year:04d}-{u.month:02d}-{u.day:02d}T{u.hour:02d}:"
            f"{u.minute:02d}:{u.second:02d}.{u.microsecond:06d}Z").encode("ascii")


def parse_datetime(b: bytes) -> datetime:
    s = _ascii(b)
    if not _DATETIME.fullmatch(s):
        raise Refused(f"not a canonical datetime: {s!r}")
    try:
        return datetime(int(s[0:4]), int(s[5:7]), int(s[8:10]), int(s[11:13]),
                        int(s[14:16]), int(s[17:19]), int(s[20:26]),
                        tzinfo=timezone.utc)
    except ValueError as e:  # year 0000, hour 24, second 60, February 30
        raise Refused(f"not a valid instant: {s!r}") from e


def _ascii(b: bytes) -> str:
    try:
        return b.decode("ascii")
    except UnicodeDecodeError as e:
        raise Refused(f"not ASCII: {b!r}") from e


RENDER = {
    "string": render_string, "bytes": lambda v: bytes(v), "int": render_int,
    "decimal": render_decimal, "float": render_float, "boolean": render_boolean,
    "date": render_date, "datetime": render_datetime,
}
PARSE = {
    "string": parse_string, "bytes": lambda b: b, "int": parse_int,
    "decimal": parse_decimal, "float": parse_float, "boolean": parse_boolean,
    "date": parse_date, "datetime": parse_datetime,
}
