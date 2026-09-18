"""`codec/logical-types.json` -- spec §3.6, logical type <-> plaintext bytes.

The one family that binds adapters rather than cores (MANIFEST.adapter_files,
docs/08 §4.8). Inputs are listed here by hand; every expected value is
computed by `..codec`, and every refusal is asserted to be one, so a case whose
comment says "refused" but which the rules admit fails generation rather than
shipping a wrong vector.

Value literals (docs/08 §4.8), one shape per type, used for both a write
vector's `input` and a read vector's `expected.value`:

    string    {"text": "..."}  or  {"utf16": "<hex UTF-16BE code units>"}
    bytes     {"hex": "..."}
    int       {"decimal": "..."}      arbitrary size, so never a JSON number
    decimal   {"decimal": "..."}      any notation on input; canonical on output
    float     {"binary64": "<16 hex digits, big-endian>"}
    boolean   {"boolean": true}
    date      {"date": "YYYY-MM-DD"}  or, for platforms without a calendar
              date, {"utc_midnight_instant": "<RFC 3339>"}
    datetime  {"instant": "<RFC 3339 with offset>"}  or  {"naive": "..."}

`requires` names platform capabilities; a harness whose platform lacks one
reports the vector skipped with that reason and MUST NOT count it as passed.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal

from .. import codec
from ._common import wrapper

SPEC = "§3.6"

CAPABILITIES = {
    "calendar-date": "the platform has a date type with no time or zone (CPython's date)",
    "date-as-utc-midnight-instant": "the platform has no calendar date; §3.6's stated "
        "convention is an instant at 00:00:00.000 UTC (JavaScript's Date)",
    "microsecond-instants": "the platform's instants hold microseconds (CPython's datetime)",
    "millisecond-instants": "the platform's instants hold milliseconds only (JavaScript's Date)",
    "naive-datetimes": "the platform can represent a datetime with no time zone",
}


def _native(t: str, lit: dict):
    """Literal -> the Python value the generator renders. Only called for
    literals CPython can represent; the others are platform-only cases."""
    if t == "string":
        if "utf16" in lit:
            return bytes.fromhex(lit["utf16"]).decode("utf-16-be", "surrogatepass")
        return lit["text"]
    if t == "bytes":
        return bytes.fromhex(lit["hex"])
    if t == "int":
        return int(lit["decimal"])
    if t == "decimal":
        return Decimal(lit["decimal"])
    if t == "float":
        return codec.float_from_bits(lit["binary64"])
    if t == "boolean":
        return lit["boolean"]
    if t == "date":
        if "naive" in lit:  # a datetime handed to a date column
            return datetime.fromisoformat(lit["naive"])
        return date.fromisoformat(lit["date"])
    if t == "datetime":
        if "naive" in lit:
            return datetime.fromisoformat(lit["naive"])
        return datetime.fromisoformat(lit["instant"])
    raise AssertionError(t)


def _literal(t: str, v) -> dict:
    """Parsed Python value -> the literal a read vector expects."""
    if t == "string":
        return {"text": v}
    if t == "bytes":
        return {"hex": v.hex()}
    if t in ("int", "decimal"):
        return {"decimal": codec.RENDER[t](v).decode("ascii")}
    if t == "float":
        return {"binary64": codec.float_bits(v)}
    if t == "boolean":
        return {"boolean": v}
    if t == "date":
        return {"date": v.isoformat()}
    if t == "datetime":
        return {"instant": codec.render_datetime(v).decode("ascii")}
    raise AssertionError(t)


def _f(x: float) -> dict:
    return {"binary64": codec.float_bits(x)}


# (slug, literal, refused?, requires, description). `refused` is a claim the
# generator checks, never a label it trusts.
WRITES: dict[str, list[tuple]] = {
    "string": [
        ("ascii", {"text": "ada@example.com"}, False, [], "plain ASCII"),
        ("empty", {"text": ""}, False, [], "the empty string is a present value (§10.2 NULL invariant)"),
        ("nfc", {"text": "Zoë"}, False, [], "precomposed e-diaeresis"),
        ("nfd", {"text": "Zoë"}, False, [], "decomposed: different bytes, because rendering does not normalize"),
        ("astral", {"text": "\U0001d4b3"}, False, [], "a supplementary-plane scalar is four UTF-8 bytes"),
        ("lone-high-surrogate", {"utf16": "0061d800"}, True, [], "an unpaired high surrogate is not a scalar value"),
        ("lone-low-surrogate", {"utf16": "dc00"}, True, [], "an unpaired low surrogate is not a scalar value"),
    ],
    "bytes": [
        ("empty", {"hex": ""}, False, [], "empty bytes"),
        ("binary", {"hex": "00ff10"}, False, [], "passed through unchanged"),
    ],
    "int": [
        ("zero", {"decimal": "0"}, False, [], "zero"),
        ("negative", {"decimal": "-42"}, False, [], "a negative integer"),
        ("beyond-int64", {"decimal": "18446744073709551616"}, False, [], "2^64: unbounded"),
        ("below-int64", {"decimal": "-9223372036854775809"}, False, [], "-2^63 - 1"),
    ],
    "decimal": [
        ("trailing-zero", {"decimal": "1.50"}, False, [], "scale is not preserved: 1.50 renders as 1.5"),
        ("plain", {"decimal": "1.5"}, False, [], "the same value, the same bytes"),
        ("negative-exponent", {"decimal": "15E-1"}, False, [], "exponent notation on input, none on output"),
        ("positive-exponent", {"decimal": "1E+2"}, False, [], "1E+2 renders as 100"),
        ("negative-zero", {"decimal": "-0.00"}, False, [], "zero is 0, never -0"),
        ("small", {"decimal": "1E-7"}, False, [], "no exponent however small"),
        ("negative-scaled", {"decimal": "-123.4500"}, False, [], "sign kept, trailing zeros dropped"),
        ("beyond-binary64", {"decimal": "12345678901234567.89"}, False, [], "exact: the value G25 measured changing"),
        ("beyond-context-precision", {"decimal": "12345678901234567890123456789.5"}, False, [], "30 digits: no rounding to a 28-digit context"),
        ("nan", {"decimal": "NaN"}, True, [], "NaN is not a decimal value"),
        ("infinity", {"decimal": "Infinity"}, True, [], "infinity is not a decimal value"),
        ("negative-infinity", {"decimal": "-Infinity"}, True, [], "neither is its negative"),
    ],
    "float": [
        ("one-and-a-half", _f(1.5), False, [], "1.5"),
        ("one-tenth", _f(0.1), False, [], "shortest round-trip digits"),
        ("1e16", _f(1e16), False, [], "no exponent below 1e21 (CPython writes 1e+16)"),
        ("1e21", _f(1e21), False, [], "exponent from 1e21 up"),
        ("1e-6", _f(1e-6), False, [], "no exponent down to 1e-6"),
        ("1e-7", _f(1e-7), False, [], "exponent below 1e-6, no zero padding (CPython writes 1e-07)"),
        ("large-integral", _f(123456789012345680000.0), False, [], "integral, twenty-one digits"),
        ("negative-small", _f(-1.5e-10), False, [], "negative with exponent"),
        ("min-subnormal", _f(5e-324), False, [], "the smallest positive subnormal"),
        ("max", _f(1.7976931348623157e308), False, [], "the largest finite value"),
        ("zero", _f(0.0), False, [], "positive zero"),
        ("negative-zero", _f(-0.0), False, [], "negative zero keeps its sign (ECMAScript alone would write 0)"),
        ("nan", {"binary64": "7ff8000000000000"}, True, [], "NaN"),
        ("infinity", {"binary64": "7ff0000000000000"}, True, [], "+Infinity"),
        ("negative-infinity", {"binary64": "fff0000000000000"}, True, [], "-Infinity"),
    ],
    "boolean": [
        ("true", {"boolean": True}, False, [], "true"),
        ("false", {"boolean": False}, False, [], "false"),
    ],
    "date": [
        ("ordinary", {"date": "2026-09-08"}, False, [], "a calendar date"),
        ("first", {"date": "0001-01-01"}, False, [], "the first representable date"),
        ("last", {"date": "9999-12-31"}, False, [], "the last representable date"),
        ("three-digit-year", {"date": "0999-05-01"}, False, [], "the year is zero-padded to four digits"),
        ("instant-at-utc-midnight", {"utc_midnight_instant": "2026-09-08T00:00:00.000Z"}, False,
         ["date-as-utc-midnight-instant"], "the convention's midnight renders as the date"),
        ("instant-not-at-midnight", {"utc_midnight_instant": "2026-09-08T05:00:00.000Z"}, True,
         ["date-as-utc-midnight-instant"], "local midnight at UTC-5: refused rather than truncated to a date"),
        ("instant-year-10000", {"utc_midnight_instant": "+010000-01-01T00:00:00.000Z"}, True,
         ["date-as-utc-midnight-instant"], "outside 0001-9999"),
        ("datetime-for-date", {"naive": "2026-09-08T00:00:00"}, True,
         ["calendar-date", "naive-datetimes"], "a datetime is not a date, even at midnight"),
    ],
    "datetime": [
        ("utc", {"instant": "2026-09-08T12:00:00Z"}, False, [], "six fractional digits always"),
        ("offset", {"instant": "2026-09-08T17:30:00+05:30"}, False, [], "an offset is normalized to UTC"),
        ("milliseconds", {"instant": "2026-09-08T12:00:00.123Z"}, False, [], "milliseconds padded to six digits"),
        ("microseconds", {"instant": "2026-09-08T12:00:00.123456Z"}, False,
         ["microsecond-instants"], "microseconds kept"),
        ("first", {"instant": "0001-01-01T00:00:00Z"}, False, [], "the first representable instant"),
        ("last-ms", {"instant": "9999-12-31T23:59:59.999Z"}, False, [], "the last millisecond"),
        ("year-zero-in-utc", {"instant": "0001-01-01T00:30:00+01:00"}, True, [],
         "valid locally, year 0000 in UTC: refused"),
        ("naive", {"naive": "2026-09-08T12:00:00"}, True, ["naive-datetimes"],
         "no time zone: refused rather than assumed"),
    ],
}

# (slug, plaintext bytes, refused?, requires, description)
READS: dict[str, list[tuple]] = {
    "string": [
        ("ascii", b"ada@example.com", False, [], "plain ASCII"),
        ("astral", "\U0001d4b3".encode(), False, [], "four-byte scalar"),
        ("encoded-surrogate", bytes.fromhex("eda080"), True, [], "CESU-style encoded surrogate is not UTF-8"),
        ("overlong", bytes.fromhex("c0af"), True, [], "overlong encoding"),
        ("invalid-byte", bytes.fromhex("ff"), True, [], "0xFF never appears in UTF-8"),
    ],
    "bytes": [
        ("binary", bytes.fromhex("00ff"), False, [], "any bytes"),
    ],
    "int": [
        ("zero", b"0", False, [], "zero"),
        ("negative", b"-42", False, [], "negative"),
        ("big", b"123456789012345678901234567890", False, [], "beyond 64 bits"),
        ("negative-zero", b"-0", True, [], "-0 is not canonical"),
        ("leading-zero", b"007", True, [], "leading zeros"),
        ("plus", b"+5", True, [], "explicit plus"),
        ("space", b" 5", True, [], "whitespace"),
        ("exponent", b"1e3", True, [], "exponent"),
        ("non-ascii-digit", "٣".encode(), True, [], "ARABIC-INDIC DIGIT THREE"),
        ("empty", b"", True, [], "empty"),
    ],
    "decimal": [
        ("plain", b"1.5", False, [], "canonical"),
        ("exact", b"12345678901234567.89", False, [], "exact beyond binary64"),
        ("negative-fraction", b"-0.5", False, [], "negative with a zero integer part"),
        ("trailing-zero", b"1.50", True, [], "trailing zero"),
        ("exponent", b"1E+2", True, [], "exponent"),
        ("leading-zero", b"01.5", True, [], "leading zero"),
        ("negative-zero", b"-0", True, [], "-0"),
        ("zero-fraction", b"0.0", True, [], "zero with a fraction"),
        ("bare-point", b"1.", True, [], "a point with nothing after it"),
        ("leading-point", b".5", True, [], "no integer part"),
        ("plus", b"+1.5", True, [], "explicit plus"),
        ("nan", b"NaN", True, [], "NaN"),
        ("comma", b"1,5", True, [], "a locale's decimal comma"),
    ],
    "float": [
        ("one-and-a-half", b"1.5", False, [], "canonical"),
        ("1e16", b"10000000000000000", False, [], "canonical"),
        ("1e-7", b"1e-7", False, [], "canonical"),
        ("negative-zero", b"-0", False, [], "negative zero"),
        ("cpython-exponent", b"1e+16", True, [], "CPython's rendering of 1e16"),
        ("cpython-padding", b"1e-07", True, [], "CPython's rendering of 1e-7"),
        ("trailing-zero", b"1.50", True, [], "not shortest"),
        ("point-zero", b"0.0", True, [], "not canonical"),
        ("negative-point-zero", b"-0.0", True, [], "not canonical"),
        ("upper-exponent", b"1E+21", True, [], "uppercase exponent"),
        ("nan", b"NaN", True, [], "not finite"),
        ("infinity", b"Infinity", True, [], "not finite"),
    ],
    "boolean": [
        ("true", b"true", False, [], "true"),
        ("false", b"false", False, [], "false"),
        ("python-true", b"True", True, [], "CPython's str(True), which Django wrote before §3.6"),
        ("one", b"1", True, [], "an integer"),
        ("upper", b"TRUE", True, [], "uppercase"),
    ],
    "date": [
        ("ordinary", b"2026-09-08", False, [], "canonical"),
        ("first", b"0001-01-01", False, [], "canonical"),
        ("instant", b"2026-09-08T00:00:00.000Z", True, [], "an instant is not a date (Prisma wrote this before §3.6)"),
        ("unpadded", b"2026-9-8", True, [], "unpadded"),
        ("february-30", b"2026-02-30", True, [], "not a calendar date"),
        ("year-zero", b"0000-01-01", True, [], "outside 0001-9999"),
        ("basic-format", b"20260908", True, [], "ISO 8601 basic format"),
        ("trailing-space", b"2026-09-08 ", True, [], "trailing whitespace"),
    ],
    "datetime": [
        ("utc", b"2026-09-08T12:00:00.000000Z", False, [], "canonical"),
        ("milliseconds", b"2026-09-08T12:00:00.123000Z", False, [], "millisecond value, six digits"),
        ("microseconds", b"2026-09-08T12:00:00.123456Z", False, ["microsecond-instants"], "held exactly"),
        ("microseconds-on-ms-platform", b"2026-09-08T12:00:00.123456Z", True, ["millisecond-instants"],
         "refused rather than truncated to .123"),
        ("no-fraction", b"2026-09-08T12:00:00Z", True, [], "fraction omitted"),
        ("three-digits", b"2026-09-08T12:00:00.123Z", True, [], "three fractional digits (Prisma wrote this before §3.6)"),
        ("offset", b"2026-09-08T12:00:00.000000+00:00", True, [], "an offset instead of Z"),
        ("lowercase", b"2026-09-08t12:00:00.000000z", True, [], "lowercase t and z"),
        ("space", b"2026-09-08 12:00:00.000000Z", True, [], "space separator"),
        ("hour-24", b"2026-09-08T24:00:00.000000Z", True, [], "hour 24"),
        ("leap-second", b"2026-12-31T23:59:60.000000Z", True, [], "no leap second"),
        ("year-zero", b"0000-01-01T00:00:00.000000Z", True, [], "outside 0001-9999"),
    ],
}


def _platform_only(lit: dict) -> bool:
    return "utc_midnight_instant" in lit


def _check_platform_only(t: str, lit: dict, refused: bool) -> None:
    """The utc-midnight-instant cases have no CPython value; check them by the
    §3.6 rule directly so their `refused` flag is still verified."""
    s = lit["utc_midnight_instant"]
    ok = (len(s) == 24 and s.endswith("T00:00:00.000Z") and not s.startswith(("+", "-"))
          and s[:4] != "0000")
    assert ok != refused, f"{t}: {s} refused={refused} disagrees with §3.6"


def generate() -> dict:
    vectors: list[dict] = []
    for t, cases in WRITES.items():
        for slug, lit, refused, requires, desc in cases:
            vid = f"codec/{t}/write/{slug}"
            v = {"id": vid, "description": desc, "spec_ref": SPEC, "logical_type": t,
                 "direction": "write", "requires": requires, "input": lit}
            if _platform_only(lit):
                _check_platform_only(t, lit, refused)
                v["expected"] = ({"refused": True} if refused else
                                 {"plaintext": lit["utc_midnight_instant"][:10].encode().hex()})
            else:
                try:
                    out = codec.RENDER[t](_native(t, lit))
                    assert not refused, f"{vid}: expected a refusal, rendered {out!r}"
                    v["expected"] = {"plaintext": out.hex()}
                except codec.Refused:
                    assert refused, f"{vid}: refused, but the case says it renders"
                    v["expected"] = {"refused": True}
            vectors.append(v)
    for t, cases in READS.items():
        for slug, raw, refused, requires, desc in cases:
            vid = f"codec/{t}/read/{slug}"
            v = {"id": vid, "description": desc, "spec_ref": SPEC, "logical_type": t,
                 "direction": "read", "requires": requires, "plaintext": raw.hex()}
            if "millisecond-instants" in requires:
                # The generator's platform holds microseconds; the refusal is
                # §3.6's precision rule, checked directly.
                assert refused and codec.parse_datetime(raw).microsecond % 1000 != 0, vid
                v["expected"] = {"refused": True}
            else:
                try:
                    val = codec.PARSE[t](raw)
                    assert not refused, f"{vid}: expected a refusal, parsed {val!r}"
                    v["expected"] = {"value": _literal(t, val)}
                except codec.Refused:
                    assert refused, f"{vid}: refused, but the case says it parses"
                    v["expected"] = {"refused": True}
            vectors.append(v)
    out = wrapper("codec", vectors)
    out["binds"] = "adapters (spec §3.6, §10.2); a core's conformance run does not iterate this file"
    out["capabilities"] = CAPABILITIES
    return out


# Round-trip self-check: every rendered write parses back to its own value.
def selfcheck() -> int:
    n = 0
    for t, cases in WRITES.items():
        for _slug, lit, refused, _req, _d in cases:
            if refused or _platform_only(lit):
                continue
            v = _native(t, lit)
            back = codec.PARSE[t](codec.RENDER[t](v))
            if t == "datetime":
                assert back == v.astimezone(timezone.utc), (t, lit)
            elif t == "float":
                assert codec.float_bits(back) == codec.float_bits(v), (t, lit)
            else:
                assert back == v, (t, lit)
            n += 1
    return n
