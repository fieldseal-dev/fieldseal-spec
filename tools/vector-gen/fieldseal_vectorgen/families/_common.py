from __future__ import annotations

from ..manifest import SPEC_VERSION, VECTOR_SUITE_VERSION


def wrapper(family: str, vectors: list[dict], *,
            held_out_reason: str | None = None) -> dict:
    """The common file wrapper of docs/08 §4.

    `held_out_reason`, when set, marks the file as generated but NOT part of
    the pinned suite. It is carried in the file as well as in MANIFEST.json so
    that a harness reading the file alone still sees it -- a status that lives
    only in the manifest is one a harness can miss by loading the wrong path.
    """
    out = {
        "schema": f"fieldseal-vectors/{family}/v1",
        "vector_suite_version": VECTOR_SUITE_VERSION,
        "group": family,
        "spec_version": SPEC_VERSION,
        "status": "held-out" if held_out_reason else "pinned",
        "vectors": vectors,
        "retired": [],
    }
    if held_out_reason:
        out["held_out_reason"] = held_out_reason
        out["conformance"] = (
            "MUST NOT be counted toward any conformance claim (docs/14 §4)."
        )
    return out


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
