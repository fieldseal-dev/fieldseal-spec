"""The `codec/` vector family (spec §3.6) through this adapter's real codec.

`MANIFEST.adapter_files` is the adapter half of the suite: a core never sees a
logical type, so these vectors bind adapters. Every vector either runs or is
skipped for a platform capability this adapter does not have -- never skipped
for any other reason, and never counted as passed when skipped.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import struct
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from django.db import models

from fieldseal_django import codec
from fieldseal_django.errors import FieldsealConfigurationError, FieldsealNotSupported
from fieldseal_django.fields import Encrypted

VECTORS = Path(__file__).resolve().parents[3] / "vectors"

#: What CPython and Django can represent (docs/08 §4.8). The two capabilities
#: this adapter lacks -- date-as-utc-midnight-instant, millisecond-instants --
#: describe JavaScript's Date, and their vectors are skipped here with that
#: reason.
CAPABILITIES = {"calendar-date", "microsecond-instants", "naive-datetimes"}

FIELDS: dict[str, models.Field[Any, Any]] = {
    "string": models.TextField(),
    "bytes": models.BinaryField(),
    "int": models.BigIntegerField(),
    "decimal": models.DecimalField(max_digits=40, decimal_places=10),
    "float": models.FloatField(),
    "boolean": models.BooleanField(),
    "date": models.DateField(),
    "datetime": models.DateTimeField(),
}


def _adapter_vectors() -> list[dict[str, Any]]:
    manifest = json.loads((VECTORS / "MANIFEST.json").read_text("utf-8"))
    out = []
    for entry in manifest["adapter_files"]:
        raw = (VECTORS / entry["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"], entry["path"]
        doc = json.loads(raw)
        assert doc["status"] == "pinned"
        out.extend(doc["vectors"])
    return out


VECS = _adapter_vectors()


def _value(t: str, lit: dict[str, Any]) -> Any:
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
        return struct.unpack(">d", bytes.fromhex(lit["binary64"]))[0]
    if t == "boolean":
        return lit["boolean"]
    if "naive" in lit:
        return dt.datetime.fromisoformat(lit["naive"])
    if t == "date":
        return dt.date.fromisoformat(lit["date"])
    if t == "datetime":
        return dt.datetime.fromisoformat(lit["instant"])
    raise AssertionError((t, lit))


def _assert_value(t: str, got: Any, lit: dict[str, Any]) -> None:
    want = _value(t, lit)
    if t == "float":
        assert struct.pack(">d", got) == struct.pack(">d", want)
    elif t == "decimal":
        assert isinstance(got, Decimal) and got.as_tuple() == want.as_tuple()
    elif t == "datetime":
        assert got == want and got.utcoffset() == dt.timedelta(0)
    else:
        assert type(got) is type(want) and got == want


@pytest.mark.parametrize("vec", VECS, ids=[v["id"] for v in VECS])
def test_codec_vector(vec: dict[str, Any]) -> None:
    missing = set(vec["requires"]) - CAPABILITIES
    if missing:
        pytest.skip(f"platform capability not held: {sorted(missing)}")
    t, field, exp = vec["logical_type"], FIELDS[vec["logical_type"]], vec["expected"]
    if vec["direction"] == "write":
        value = _value(t, vec["input"])
        if exp.get("refused"):
            with pytest.raises(FieldsealNotSupported):
                codec.to_bytes(field, value)
        else:
            assert codec.to_bytes(field, value).hex() == exp["plaintext"]
    else:
        raw = bytes.fromhex(vec["plaintext"])
        if exp.get("refused"):
            with pytest.raises(FieldsealNotSupported):
                codec.from_bytes(field, raw)
        else:
            _assert_value(t, codec.from_bytes(field, raw), exp["value"])


def test_every_skip_is_a_capability_skip() -> None:
    """A skip for any reason but a missing capability would be a vector this
    adapter silently does not run (docs/08 §5 item 7)."""
    skipped = [v["id"] for v in VECS if set(v["requires"]) - CAPABILITIES]
    assert len(VECS) == 124 and len(skipped) == 4, (len(VECS), skipped)


@pytest.mark.parametrize("inner", [
    models.UUIDField(), models.TimeField(), models.DurationField(),
    models.JSONField(), models.GenericIPAddressField(),
], ids=lambda f: type(f).__name__)
def test_unpinned_types_are_refused_at_declaration(
        inner: models.Field[Any, Any]) -> None:
    with pytest.raises(FieldsealConfigurationError, match="no spec §3.6 rendering"):
        Encrypted(inner, column_uuid="0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b")


@pytest.mark.parametrize(("inner", "kind"), [
    (models.EmailField(), "string"), (models.SlugField(), "string"),
    (models.URLField(), "string"), (models.SmallIntegerField(), "int"),
    (models.PositiveBigIntegerField(), "int"), (models.DateTimeField(), "datetime"),
    (models.DateField(), "date"), (models.BooleanField(), "boolean"),
], ids=lambda x: type(x).__name__ if isinstance(x, models.Field) else x)
def test_subclasses_map_to_their_logical_type(
        inner: models.Field[Any, Any], kind: str) -> None:
    field = Encrypted(inner, column_uuid="0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b")
    assert field.logical_type == kind


def test_equal_decimals_index_identically() -> None:
    """G25's same-adapter finding: before §3.6, 1.5 and 1.50 were different
    plaintexts and so different blind-index values."""
    f = FIELDS["decimal"]
    assert codec.to_bytes(f, Decimal("1.5")) == codec.to_bytes(f, Decimal("1.50")) \
        == codec.to_bytes(f, "1.500") == b"1.5"


def test_float_is_refused_for_a_decimal_column() -> None:
    with pytest.raises(FieldsealNotSupported, match="not a decimal"):
        codec.to_bytes(FIELDS["decimal"], 0.1)
