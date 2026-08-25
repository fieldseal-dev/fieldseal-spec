"""fieldseal-django -- transparent field-level encryption at rest for Django.

Design: `docs/12-adapter-django.md`. Conformance target (spec §10.1):
L0 ✅ · L1 ✅ · L2(a)+(b) ✅ · L3 via a documented contextvar side channel ⚠️ ·
L3-row ❌ (v0) · L4 ❌.

**AD-1 (spec §11.3): this package contains no cryptography.** It calls the
core's five sync operations plus `warm`, and nothing else. If a change here
would need a cipher, a KDF, or a random number, it belongs in the core.

**Import path.** The distribution is `fieldseal-django` and the import path
is `fieldseal_django`. `docs/12` §1's example wrote `from fieldseal.django
import ...`; that is not achievable without turning the core into a namespace
package or shipping adapter code inside the core distribution, and the second
would break the layout rule that adapters carry no cryptographic code by
putting them in the same package as all of it.
"""

from __future__ import annotations

from .context import get_tenant, set_tenant, tenant_scope
from .declarations import BlindIndex, FieldsealMeta, Override
from .errors import (
    FieldsealAdapterError,
    FieldsealConfigurationError,
    FieldsealNotSupported,
)

__all__ = [
    "BlindIndex",
    "FieldsealMeta",
    "Override",
    "FieldsealAdapterError",
    "FieldsealConfigurationError",
    "FieldsealNotSupported",
    "set_tenant",
    "get_tenant",
    "tenant_scope",
    "Encrypted",
    "index_column",
]
__version__ = "0.1.0.dev0"

default_app_config = "fieldseal_django.apps.FieldsealConfig"


def __getattr__(name: str) -> object:
    # `Encrypted` imports `django.db.models`, which requires settings to be
    # configured. Deferring keeps `import fieldseal_django` usable from
    # tooling that has not set DJANGO_SETTINGS_MODULE.
    if name in ("Encrypted", "index_column"):
        from . import fields

        return getattr(fields, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
