"""AppConfig, the settings surface, and client construction (docs/12 §7).

**The adapter constructs the client, and that is a normative choice.** The
core's construction-time validation -- the spec §7.4 truncation band and the
§7.6 cardinality gate -- runs over the `IndexDeclaration`s handed to
`Fieldseal(...)`. If a deployment built its own client, those gates would run
against whatever list it passed, which is not necessarily the set of indexes
declared on models. Assembling the registry here, in `ready()`, after model
loading, is the only arrangement in which the gates see the columns that
actually exist.

The escape hatch for deployments that must own provider wiring is
`FIELDSEAL["CLIENT"]`, and it is gated by system check E006: its index
registry must match the model declarations exactly, or startup fails.
"""

from __future__ import annotations

import threading
from typing import Any

from django.apps import AppConfig
from django.conf import settings
from django.core.signals import setting_changed
from django.db.models.signals import class_prepared
from django.dispatch import receiver
from fieldseal import Argon2Params, CardinalityOverride, Fieldseal, IndexDeclaration

from .errors import FieldsealConfigurationError

_client: Fieldseal | None = None
# Two threads racing the first value-path call would otherwise each
# build a client. Harmless -- the client is immutable after
# construction (docs/09 §2) and one wins the assignment -- but it also
# means running every construction-time gate twice and, with a real
# provider, whatever work the provider does on init.
_client_lock = threading.Lock()

#: Only these keys are read. An unknown key is a typo that would otherwise
#: change nothing and be discovered in production.
_SETTING_KEYS = {
    "KEY_PROVIDER", "CLIENT", "READ_MODE", "ALLOWED_SUITES", "WRITE_SUITE",
    "ARM_PROVISIONAL_SUITES",
}


def get_settings() -> dict[str, Any]:
    cfg = dict(getattr(settings, "FIELDSEAL", {}) or {})
    unknown = set(cfg) - _SETTING_KEYS
    if unknown:
        raise FieldsealConfigurationError(
            f"unknown FIELDSEAL settings: {sorted(unknown)}. Known keys are "
            f"{sorted(_SETTING_KEYS)}."
        )
    return cfg


def iter_encrypted_fields(registry: Any = None) -> list[tuple[Any, Any]]:
    """Every `(model, Encrypted field)` pair across installed apps.

    `registry` exists so the system checks can be run against an isolated
    app registry in tests. A check that can only be exercised against the
    real registry can only be tested by breaking the project's own models,
    which is how check suites end up asserting nothing.
    """
    from django.apps import apps as django_apps

    from .fields import Encrypted

    out = []
    for model in (registry or django_apps).get_models():
        for field in model._meta.get_fields():
            if isinstance(field, Encrypted):
                out.append((model, field))
    return out


def build_index_registry(registry: Any = None) -> list[IndexDeclaration]:
    """The core's index registry, assembled from model declarations.

    Translation only -- every constraint on these values is the core's to
    enforce, and it does, at construction. `docs/12` §5's E003 exists to turn
    that refusal into a startup check rather than to duplicate the rule.
    """
    from .declarations import Override

    decls: list[IndexDeclaration] = []
    for model, field in iter_encrypted_fields(registry):
        idx = field.index
        if idx is None:
            continue
        if idx.projected_population is None:
            raise FieldsealConfigurationError(
                f"{model.__name__}.{field.name} declares a BlindIndex with no "
                "projected_population. Spec §7.4 sizes the truncation band "
                "from the number of DISTINCT values the column will hold, so "
                "there is no defensible default (system check fieldseal.E003)."
            )

        def _override(o: Override | None) -> CardinalityOverride | None:
            if o is None:
                return None
            return CardinalityOverride(
                reason=o.reason, approved_by=o.approved_by, date=o.date)

        argon2 = None
        if idx.time_cost is not None or idx.memory_kib is not None:
            if idx.time_cost is None or idx.memory_kib is None:
                raise FieldsealConfigurationError(
                    f"{model.__name__}.{field.name}: time_cost and memory_kib "
                    "must be given together when raising the §7.3 Argon2id "
                    "cost above the minimum"
                )
            argon2 = Argon2Params(
                time_cost=idx.time_cost, memory_kib=idx.memory_kib)

        meta = getattr(model, "fieldseal", None)
        if meta is None:
            raise FieldsealConfigurationError(
                f"{model.__name__} carries an Encrypted field but no "
                "`fieldseal = FieldsealMeta(table_uuid=...)` "
                "(system check fieldseal.E004)"
            )
        decls.append(IndexDeclaration(
            table_uuid=meta.table_uuid_bytes,
            column_uuid=field.column_uuid,
            index_id=idx.index_id,
            idf=idx.idf,
            normalize=idx.normalize,
            truncate_bits=idx.truncate_bits,
            projected_population=idx.projected_population,
            argon2=argon2,
            cardinality_override=_override(idx.cardinality_override),
            skewed=idx.skewed,
            on_unindexable=idx.on_unindexable,
            unindexable_override=_override(idx.unindexable_override),
        ))
    return decls


def build_client(registry: Any = None) -> Fieldseal:
    cfg = get_settings()
    if "CLIENT" in cfg:
        client = cfg["CLIENT"]() if callable(cfg["CLIENT"]) else cfg["CLIENT"]
        if not isinstance(client, Fieldseal):
            raise FieldsealConfigurationError(
                "FIELDSEAL['CLIENT'] must be a Fieldseal instance or a "
                f"callable returning one; got {type(client).__name__}"
            )
        return client

    provider = cfg.get("KEY_PROVIDER")
    if provider is None:
        raise FieldsealConfigurationError(
            "FIELDSEAL['KEY_PROVIDER'] is required: it is a callable "
            "returning a fieldseal KeyProvider. There is no default, because "
            "a default would mean shipping a key."
        )
    if callable(provider):
        provider = provider()

    allowed = cfg.get("ALLOWED_SUITES")
    write = cfg.get("WRITE_SUITE")
    if allowed is None or write is None:
        raise FieldsealConfigurationError(
            "FIELDSEAL['ALLOWED_SUITES'] and FIELDSEAL['WRITE_SUITE'] are "
            "required. Spec §4.3 gives allowed_suites no default on purpose: "
            "writing the list out is the suite-retirement mechanism working."
        )
    return Fieldseal(
        key_provider=provider,
        allowed_suites=set(allowed),
        write_suite=write,
        read_mode=cfg.get("READ_MODE", "strict"),
        indexes=build_index_registry(registry),
        arm_provisional_suites=bool(cfg.get("ARM_PROVISIONAL_SUITES", False)),
    )


def get_client() -> Fieldseal:
    """The process-wide client.

    Built lazily on first use rather than only in `ready()`, so that a field
    reached before app population -- in a data migration, say -- gets a
    working client instead of a confusing `None`.
    """
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = build_client()
    return _client


def reset_client() -> None:
    """Drop the cached client. For tests and `setting_changed`."""
    global _client
    _client = None


@receiver(class_prepared)
def _install_manager(sender: Any, **kwargs: Any) -> None:
    """Give a model with an indexed encrypted column the verifying manager.

    **Only when the model declared no manager of its own.** Django adds
    `objects = Manager()` itself when none is declared and marks it
    `auto_created` (`ModelBase._prepare`, before this signal fires), so that
    flag is an exact test for "the user did not choose a manager". Replacing
    one somebody wrote on purpose would be the adapter silently changing
    behaviour the model author specified; system check **E008** reports that
    case instead.

    Why auto-install at all: decision C (`docs/12` §3.2) puts §7.5
    re-verification on the *default* path precisely so that nothing has to be
    remembered. A `FieldsealManager` the user must add by hand would reinstate
    the failure mode that decision rejected -- one forgotten line and
    `filter()` returns collision rows.
    """
    from .fields import Encrypted
    from .query import FieldsealManager

    if not any(isinstance(f, Encrypted) and f.index is not None
               for f in sender._meta.fields):
        return
    managers = sender._meta.local_managers
    if len(managers) != 1 or not getattr(managers[0], "auto_created", False):
        return  # E008's business, not ours.
    sender._meta.local_managers = []
    manager = FieldsealManager()
    manager.auto_created = True
    sender.add_to_class("objects", manager)
    sender._meta._expire_cache()


@receiver(setting_changed)
def _on_setting_changed(sender: Any, setting: str, **kwargs: Any) -> None:
    if setting == "FIELDSEAL":
        reset_client()


class FieldsealConfig(AppConfig):
    name = "fieldseal_django"
    label = "fieldseal"
    verbose_name = "fieldseal"

    def ready(self) -> None:
        from . import checks  # noqa: F401  (registers the system checks)
