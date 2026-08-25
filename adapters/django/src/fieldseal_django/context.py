"""Tenant binding and per-column `FieldContext` assembly (docs/12 §4).

Django field types cannot see the record they belong to. `get_db_prep_value`
receives a value, a connection and a `prepared` flag -- not the instance, not
the row, not the request. Spec §10's L3 row for Django therefore reads
"documented contextvar side channel", and this module is that side channel,
written to fail closed.

**The failure mode this is built around.** A tenant-bound column whose tenant
is unset must not quietly encrypt under a tenantless context: the write would
succeed, the row would be unreadable by every correctly-configured reader,
and nothing would say so until someone tried to read it. `require_tenant()`
raises instead. That is spec §10.2's rule applied to context rather than to
queries.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token

from fieldseal import FieldContext

from .errors import FieldsealConfigurationError

#: Set per request (middleware), per task (Celery), or per command. A
#: ContextVar rather than thread-local so that async views and thread pools
#: inherit it the way Django's own async plumbing expects.
_tenant: ContextVar[bytes | None] = ContextVar(
    "fieldseal_django_tenant", default=None)


def set_tenant(tenant_id: bytes | str | None) -> Token[bytes | None]:
    """Bind the tenant for the current context.

    Returns the `Token` so a caller can restore the previous value; prefer
    `tenant_scope()`, which does it for you.
    """
    if tenant_id is None:
        return _tenant.set(None)
    if isinstance(tenant_id, str):
        tenant_id = tenant_id.encode("utf-8")
    if not isinstance(tenant_id, bytes):
        raise FieldsealConfigurationError(
            f"tenant_id must be bytes or str, got {type(tenant_id).__name__}"
        )
    return _tenant.set(tenant_id)


def get_tenant() -> bytes | None:
    return _tenant.get()


@contextmanager
def tenant_scope(tenant_id: bytes | str | None) -> Iterator[None]:
    """Bind a tenant for the duration of a block, restoring the previous one.

    The shape management commands and Celery tasks should use, because the
    middleware that would otherwise set it never runs there.
    """
    token = set_tenant(tenant_id)
    try:
        yield
    finally:
        _tenant.reset(token)


def require_tenant(model: str, field: str) -> bytes:
    """The tenant for a column declared `tenant_bound`, or a refusal.

    Failing closed here is the whole point. The alternative -- treating an
    unset tenant as "no tenant" -- writes a row under a context no configured
    reader will reconstruct, and the error surfaces later as
    `COMMITMENT_INVALID` on a read, which names neither the column nor the
    missing binding.
    """
    tenant = _tenant.get()
    if tenant is None:
        raise FieldsealConfigurationError(
            f"{model}.{field} is declared tenant_bound and no tenant is set "
            "in this context. Set one with "
            "`fieldseal_django.context.set_tenant(...)` or the "
            "`tenant_scope(...)` context manager -- the shipped middleware "
            "covers requests, but management commands, Celery tasks and "
            "shell sessions run outside it and must set it themselves. "
            "Encrypting without it would store a row that no correctly "
            "configured reader can decrypt."
        )
    return tenant


def build_context(
    *,
    table_uuid: bytes,
    column_uuid: bytes,
    tenant_bound: bool,
    model: str,
    field: str,
    purpose: str = "encrypt",
) -> FieldContext:
    """Assemble the per-operation `FieldContext` for a column.

    `row_id` is always `None` in v0 (`docs/12` §4, §9): Django cannot see the
    primary key at INSERT time for identity keys, so L3-row is deferred
    rather than half-implemented. The coverage matrix records it as ❌ with
    that reason rather than leaving it unmentioned.
    """
    return FieldContext(
        table_uuid=table_uuid,
        column_uuid=column_uuid,
        purpose=purpose,
        tenant_id=require_tenant(model, field) if tenant_bound else None,
        row_id=None,
    )
