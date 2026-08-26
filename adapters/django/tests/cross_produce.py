"""Cross-language producer: rows written by **Django**, read by any core.

This is the project's central claim at the layer people actually deploy. The
core-level cross harness (`core/*/tests/cross_*`) already proves that a value
encrypted by one core decrypts in another. What it cannot prove is that the
bytes an **ORM adapter** puts in a database column are those bytes -- because
three decisions between the application value and the stored column belong to
the adapter and to nothing the cores test:

- **the codec.** `IntegerField(42)` is not self-evidently `b"42"`. The adapter
  chooses that rendering (`codec.to_bytes`), and a consumer in another
  language gets whatever it chose. A core round trip never sees it.
- **the storage form.** `binary` stores raw envelope bytes; `base64` stores
  ASCII. A consumer handed the wrong one fails at the length gate with an
  error that points at the envelope rather than at the column.
- **context assembly.** `table_uuid`, `column_uuid` and the tenant come from
  model declarations and a contextvar (`docs/12` §4), not from a caller. A
  consumer that reconstructs them differently derives a different record key
  and gets `COMMITMENT_INVALID` -- a decrypt-side error for a write-side
  configuration mismatch.

So this writes rows through the **real ORM path** -- real `save()`, runtime
CSPRNG, no test-mode injection -- then reads the raw column back through a
database cursor and emits the standard `fieldseal-vectors/cross/v1` document.
That schema is deliberate: **every existing consumer reads this file
unmodified**, so the Django adapter joins the N×N matrix as one more producer
rather than needing a bespoke checker.

Key material is resolved by `key_ref` against `vectors/keys/test-keys.json`,
the same public file the core producers use, so no key is embedded here.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "vectors"

H = bytes.fromhex

#: The shared key this producer writes under. One is enough: what varies here
#: is the adapter's own decisions, not the key hierarchy, which the core
#: producers already cover across tenants.
KEY_REF = "tenant-a-dek-v1"


def _commit() -> str:
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
            text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _configure(key: dict) -> None:
    """Boot Django against the shared test key and an in-memory database."""
    import django
    from django.conf import settings
    from fieldseal.keyprovider import StaticKeyProvider

    settings.configure(
        SECRET_KEY="fieldseal-cross-producer-not-a-real-secret",
        USE_TZ=True,
        INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth",
                        "fieldseal_django", "tests"],
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3",
                               "NAME": ":memory:"}},
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        FIELDSEAL={
            "KEY_PROVIDER": lambda: StaticKeyProvider(
                key_id=H(key["key_id"]),
                tenant_dek=H(key["tenant_dek"]),
                tenant_index_key=H(key["tenant_index_key"]),
            ),
            "ALLOWED_SUITES": {int(key["suite_id"], 16)},
            "WRITE_SUITE": int(key["suite_id"], 16),
            "READ_MODE": "strict",
            # Spec §4.8: writing under a provisional suite is an affirmative
            # act here as everywhere.
            "ARM_PROVISIONAL_SUITES": True,
        },
    )
    django.setup()

    from django.core.management import call_command

    call_command("migrate", run_syncdb=True, verbosity=0)


def _raw_column(table: str, column: str, pk: int) -> bytes | str:
    """The bytes the database actually holds.

    Read through a cursor rather than the ORM on purpose: `from_db_value`
    would decrypt, and what a consumer in another language receives is the
    stored column, not the adapter's view of it.
    """
    from django.db import connection

    with connection.cursor() as cur:
        cur.execute(f'SELECT "{column}" FROM "{table}" WHERE id = %s', [pk])
        (value,) = cur.fetchone()
    if isinstance(value, memoryview):
        return value.tobytes()
    return value


def _stored_envelope(field: object, raw: bytes | str) -> bytes:
    import base64

    if getattr(field, "storage", "binary") == "base64":
        return base64.b64decode(raw)
    return bytes(raw)  # type: ignore[arg-type]


def _case(case_id: str, model: object, field_name: str, pk: int,
          plaintext: bytes, tenant: bytes | None) -> dict:
    field = model._meta.get_field(field_name)  # type: ignore[attr-defined]
    raw = _raw_column(model._meta.db_table, field.column, pk)  # type: ignore[attr-defined]
    envelope = _stored_envelope(field, raw)
    ctx = field.fieldseal_context()  # type: ignore[attr-defined]
    return {
        "id": f"cross/django/{case_id}",
        "key_ref": KEY_REF,
        "context": {
            "table_uuid": ctx.table_uuid.hex(),
            "column_uuid": ctx.column_uuid.hex(),
            "tenant_id": None if tenant is None else tenant.hex(),
            "row_id": None,  # L3-row is not in v0 (docs/12 §4)
            "purpose": "encrypt",
        },
        "plaintext": plaintext.hex(),
        "envelope": envelope.hex(),
    }


def produce() -> dict:
    keys = json.loads(
        (VECTORS / "keys" / "test-keys.json").read_text("utf-8"))["keys"]
    key = keys[KEY_REF]
    _configure(key)

    from fieldseal_django import tenant_scope
    from tests.models import Patient, Person, TenantDoc  # noqa: PLC0415

    cases: list[dict] = []

    # Ordinary text through an EmailField.
    row = Patient.objects.create(email="ada@example.com", note="a note",
                                 age=36)
    cases.append(_case("text-email", Patient, "email", row.pk,
                       b"ada@example.com", None))

    # Text that is not ASCII: the codec's UTF-8 encoding has to be what the
    # consumer decodes, and a mis-set encoding survives an ASCII-only test.
    row = Patient.objects.create(email="renee@example.com",
                                 note="日本語とEmoji 🔐", age=41)
    cases.append(_case("text-non-ascii", Patient, "note", row.pk,
                       "日本語とEmoji 🔐".encode(), None))

    # An IntegerField. **The adapter decides this is `b"45"`** -- a core round
    # trip never sees the decision, and a consumer that expected an integer
    # encoding would decrypt successfully and read the wrong value.
    row = Patient.objects.create(email="grace@example.com", note="g", age=45)
    cases.append(_case("non-text-integer", Patient, "age", row.pk, b"45",
                       None))

    # The empty string, which is a value rather than an absence.
    row = Patient.objects.create(email="empty@example.com", note="", age=1)
    cases.append(_case("text-empty", Patient, "note", row.pk, b"", None))

    # A tenant-bound column: the tenant reaches the context through a
    # contextvar (docs/12 §4), so a consumer must be told which one.
    with tenant_scope("tenant-0001"):
        row = TenantDoc.objects.create(body="tenant-scoped body")
        cases.append(_case("tenant-bound", TenantDoc, "body", row.pk,
                           b"tenant-scoped body", b"tenant-0001"))

    # A column whose index is bucketed -- the ciphertext is ordinary, and this
    # asserts that being unindexable changes nothing about the envelope.
    row = Person.objects.create(legal_name="Ada Lovelace")
    cases.append(_case("indexed-column", Person, "legal_name", row.pk,
                       b"Ada Lovelace", None))

    return {
        "schema": "fieldseal-vectors/cross/v1",
        "producer": {
            "implementation": "django",
            "version": "0.1.0.dev0",
            "commit": _commit(),
            "produced_at": datetime.datetime.now(
                datetime.timezone.utc).isoformat(timespec="seconds"),
        },
        "suite_id": key["suite_id"],
        "cases": cases,
    }


def main() -> int:
    ap = argparse.ArgumentParser(prog="cross_produce (django)")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    doc = produce()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=1) + "\n", "utf-8")
    print(f"wrote {args.out} ({len(doc['cases'])} cases, "
          f"producer django@{doc['producer']['commit'][:12]})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
