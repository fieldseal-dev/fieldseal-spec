"""Assembling the contexts to prefetch (`docs/12` §7, spec §11.2).

Shared by the `fieldseal_warm` command and the `WARM_ON_READY` hook so that
the two cannot disagree about what a warm cache covers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fieldseal import FieldContext


def warm_contexts(*, tenants: list[str] | None = None,
                  registry: Any = None) -> tuple[list[FieldContext], list[str]]:
    """Return `(contexts, skipped_labels)` for every declared encrypted column.

    One context per column for the data key, plus one per declared blind index
    for the **index key** -- they are siblings rather than one derived from the
    other (spec §5.2), so a cache warmed only for the data key still stalls
    every indexed lookup.

    `skipped_labels` names tenant-bound columns that could not be warmed
    because no tenant was supplied. Returning them rather than raising is
    deliberate: a deployment with no tenants configured yet should still be
    able to warm everything else, and a run that quietly warmed less than it
    claimed is the failure this whole module exists to prevent.
    """
    from .apps import iter_encrypted_fields
    from .context import tenant_scope

    tenants = tenants or []
    contexts: list[FieldContext] = []
    skipped: list[str] = []

    for model, field in iter_encrypted_fields(registry):
        label = f"{model._meta.label}.{field.name}"
        if field._is_tenant_bound() and not tenants:
            skipped.append(label)
            continue
        scopes = tenants if field._is_tenant_bound() else [None]
        for tenant in scopes:
            if tenant is None:
                contexts.extend(_for_column(field))
            else:
                with tenant_scope(tenant):
                    contexts.extend(_for_column(field))
    return contexts, skipped


def _for_column(field: Any) -> list[FieldContext]:
    base = field.fieldseal_context()
    out = [base]
    if field.index is not None:
        # spec §5.2: the index key is a *sibling* of the tenant DEK, not
        # derived from it, so warming the data key does not warm this one.
        out.append(base.for_index(field.index.index_id))
    return out
