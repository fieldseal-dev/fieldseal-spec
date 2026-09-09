"""Dump what Django has actually resolved, as JSON, for `check_declarations.py`.

**Resolved, not as-declared.** Everything below comes from the accessors the
adapter itself uses at runtime -- `iter_encrypted_fields()`,
`build_index_registry()`, `field.fieldseal_context()` -- rather than from the
text of `models.py`. That is `checks.py` E006's own stated rationale, and it
applies with more force here: comparing as-declared inputs would let two
declarations that agree textually and differ operationally register as a
match. An `ast` parse of the model file would be exactly that mistake.

Run as a module, from the `django/` directory:

    DJANGO_SETTINGS_MODULE=settings python -m directory.dump_declarations

It writes JSON to stdout and nothing else, so a caller can read it without
filtering. `check_declarations.py` runs it as a subprocess -- the checker
never imports Django, and so cannot accidentally resolve anything itself.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

#: Django's inner field type -> the logical type its bytes represent.
#:
#: The Django adapter has no `as:` declaration: the inner field *is* the
#: logical type, and the codec renders it (`codec.to_bytes`). This table is
#: the mapping made explicit so it can be compared with Prisma's `as:`, which
#: is the same decision written down. The rendering is what a reader in
#: another language decodes, so a wrong row here is a cross-language break.
LOGICAL_TYPES = {
    "CharField": "string",
    "EmailField": "string",
    "SlugField": "string",
    "TextField": "string",
    "URLField": "string",
    "BinaryField": "bytes",
    "BigIntegerField": "int",
    "IntegerField": "int",
    "PositiveBigIntegerField": "int",
    "PositiveIntegerField": "int",
    "PositiveSmallIntegerField": "int",
    "SmallIntegerField": "int",
    "FloatField": "float",
    "BooleanField": "boolean",
    "DateTimeField": "datetime",
}


def _setup() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
    import django

    django.setup()


def dump() -> dict[str, Any]:
    from django.conf import settings
    from fieldseal_django.apps import build_index_registry, iter_encrypted_fields

    # Keyed by (table_uuid, column_uuid): the core's registry identifies an
    # index by the column it belongs to, which is the same identity this
    # whole comparison is joined on.
    indexes = {
        (d.table_uuid.hex(), d.column_uuid.hex()): d for d in build_index_registry()
    }

    columns: dict[str, Any] = {}
    for model, field in iter_encrypted_fields():
        meta = model.fieldseal
        tenant_bound = bool(
            field.tenant_bound if field.tenant_bound is not None else meta.tenant_bound
        )
        try:
            ctx = field.fieldseal_context()
        except Exception as e:  # noqa: BLE001 - re-raised with the actual cause
            raise SystemExit(
                f"{model.__name__}.{field.name}: could not resolve the field "
                f"context ({e}). A tenant-bound column resolves its context "
                f"from the ambient tenant, so a dump of one has to run inside "
                f"a `tenant_scope(...)`."
            ) from e

        entry: dict[str, Any] = {
            "table_uuid": ctx.table_uuid.hex(),
            "model": model.__name__,
            "table": model._meta.db_table,
            "field": field.name,
            "column": field.column,
            "declared_type": type(field.inner).__name__,
            "logical_type": LOGICAL_TYPES.get(field.inner.get_internal_type()),
            "storage": field.storage,
            "tenant_bound": tenant_bound,
            "nullable": bool(field.null),
            "index": None,
        }

        decl = indexes.get((ctx.table_uuid.hex(), ctx.column_uuid.hex()))
        if decl is not None:
            sibling = next(
                (
                    f
                    for f in model._meta.get_fields()
                    if getattr(f, "source", None) == field.name
                ),
                None,
            )
            entry["index"] = {
                "index_id": decl.index_id,
                "idf": decl.idf,
                "normalize": decl.normalize,
                "truncate_bits": decl.truncate_bits,
                "projected_population": decl.projected_population,
                "on_unindexable": decl.on_unindexable,
                "skewed": decl.skewed,
                "argon2": (
                    None
                    if decl.argon2 is None
                    else {
                        "time_cost": decl.argon2.time_cost,
                        "memory_kib": decl.argon2.memory_kib,
                    }
                ),
                "sibling_column": None if sibling is None else sibling.column,
            }
        columns[ctx.column_uuid.hex()] = entry

    return {
        "stack": "django",
        "resolved_by": (
            "fieldseal_django.apps.iter_encrypted_fields / build_index_registry "
            "/ Encrypted.fieldseal_context"
        ),
        "suite_id": f"0x{settings.SUITE_ID:04X}",
        "key_ref": settings.KEY_REF,
        "columns": columns,
    }


def main() -> int:
    _setup()
    json.dump(dump(), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
