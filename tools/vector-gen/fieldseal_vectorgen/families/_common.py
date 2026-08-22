from __future__ import annotations

from ..manifest import SPEC_VERSION, VECTOR_SUITE_VERSION


def wrapper(family: str, vectors: list[dict]) -> dict:
    """The common file wrapper of docs/08 §4."""
    return {
        "schema": f"fieldseal-vectors/{family}/v1",
        "vector_suite_version": VECTOR_SUITE_VERSION,
        "group": family,
        "spec_version": SPEC_VERSION,
        "vectors": vectors,
        "retired": [],
    }


def suite_str(suite_id: int) -> str:
    """docs/08 §3: 0x prefix, four UPPERCASE hex digits, compared as a string."""
    return f"0x{suite_id:04X}"


def ctx_json(ctx) -> dict:
    return {
        "table_uuid": ctx.table_uuid.hex(),
        "column_uuid": ctx.column_uuid.hex(),
        "tenant_id": None if ctx.tenant_id is None else ctx.tenant_id.hex(),
        "row_id": None if ctx.row_id is None else ctx.row_id.hex(),
        "purpose": ctx.purpose,
    }
