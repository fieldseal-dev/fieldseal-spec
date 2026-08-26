"""System checks (docs/12 §5) -- correctness enforced at startup.

Every check here catches something that would otherwise be found at runtime,
in production, on a write. E003 exists because the failure it catches is
*silent*: an out-of-band truncation length degrades the column's privacy
without any operation failing.

**E001's rationale was wrong until 2026-08-25 and is corrected here.** Both
this module and `docs/12` §1.2 claimed that an index sibling declared before
its source derives "a stale or empty index", because `SQLInsertCompiler`
iterates fields in declaration order. Measured: it does not. `pre_save` reads
the *instance attribute*, which Python has set long before any field hook
runs, so a reversed declaration produces the byte-identical index value. The
check is kept for the reasons that are true -- deterministic column order in
migrations and DDL, readability, and the fact that L3-row binding would make
the source's `pre_save` mutate the instance and turn order into a real
dependency -- and its message no longer claims a failure that cannot happen.

The checks do not re-implement the core's gates. E003 surfaces the core's
construction-time refusal at startup; the core stays the enforcing layer, so
there is exactly one place that decides whether a column is acceptable.
"""

from __future__ import annotations

from typing import Any

from django.core.checks import Error, Warning, register

from .errors import FieldsealAdapterError


@register("fieldseal")
def check_fieldseal(app_configs: Any = None, apps: Any = None,
                    admin_registry: Any = None,
                    **kwargs: Any) -> list[Any]:
    from .apps import build_client, get_settings, iter_encrypted_fields
    from .fields import Encrypted, EncryptedIndex

    issues: list[Any] = []
    pairs = iter_encrypted_fields(apps)

    for model, field in pairs:
        label = f"{model._meta.label}.{field.name}"

        # E004 -- the surrogate identifiers (spec §6.1).
        if getattr(model, "fieldseal", None) is None:
            issues.append(Error(
                f"{model._meta.label} has encrypted fields but no "
                "`fieldseal = FieldsealMeta(table_uuid=...)`.",
                hint="Run `manage.py fieldseal_gen_uuids` for a value. The "
                     "UUID must be immutable and must not be derived from "
                     "the model name (spec §6.1) -- a rename would make "
                     "every existing row undecryptable.",
                obj=model, id="fieldseal.E004"))

        # E002 -- uniqueness over ciphertext, and why moving it does not help.
        if field.unique:
            issues.append(Error(
                f"{label} is encrypted and declares unique=True.",
                hint="A randomized suite writes different ciphertext for the "
                     "same plaintext, so the constraint never fires. Moving "
                     "it to the index column is also forbidden: spec §7.4 "
                     "mandates collisions in a truncated index, so UNIQUE "
                     "there would reject legitimate distinct values (§7.10). "
                     "Use the application-level fallback in §7.10 and read "
                     "its race note.",
                obj=field, id="fieldseal.E002"))

        # W002 -- an index on ciphertext buys nothing.
        if field.db_index:
            issues.append(Warning(
                f"{label} declares db_index=True on a ciphertext column.",
                hint="Randomized ciphertext is not usefully indexable; this "
                     "is index bloat on every write. Equality lookups go "
                     "through the blind-index sibling column instead.",
                obj=field, id="fieldseal.W002"))

        # W003 -- base64 storage overhead (spec §3.3).
        if field.storage == "base64":
            issues.append(Warning(
                f"{label} uses base64 storage (~33% larger than binary).",
                hint="Binary storage is the default and the spec §3.3 "
                     "recommendation. base64 is for text-only stores.",
                obj=field, id="fieldseal.W003"))

        # E005 -- named in a UniqueConstraint or a composite index. All four
        # places Django lets you say it, not just `Meta.constraints` with a
        # `fields` list: the narrow version passed models E005 exists to
        # reject.
        for where in _constraint_sites(model, field.name):
            issues.append(Error(
                f"{label} is named in {where}.",
                hint="Uniqueness over ciphertext is meaningless -- a "
                     "randomized suite writes different bytes for the same "
                     "plaintext, so the constraint never fires. Uniqueness "
                     "over a truncated index is worse than meaningless: spec "
                     "§7.4 mandates collisions, so it would reject "
                     "legitimate distinct values (§7.10, G12). A composite "
                     "index over ciphertext is index bloat with no lookup it "
                     "can serve.",
                obj=field, id="fieldseal.E005"))

    # E001 -- declaration order. `SQLInsertCompiler.as_sql` iterates fields in
    # declaration order, so an index sibling declared before its source reads
    # a plaintext attribute that has not been set yet.
    for model in {m for m, _ in pairs}:
        order = {f.name: i for i, f in enumerate(model._meta.fields)}
        for f in model._meta.fields:
            if not isinstance(f, EncryptedIndex):
                continue
            if f.source not in order:
                issues.append(Error(
                    f"{model._meta.label}.{f.name} indexes {f.source!r}, "
                    "which is not a field on this model.",
                    obj=f, id="fieldseal.E001"))
                continue
            if order[f.name] < order[f.source]:
                issues.append(Error(
                    f"{model._meta.label}.{f.name} is declared before the "
                    f"field it indexes ({f.source!r}).",
                    hint="This does not corrupt the index today -- pre_save "
                         "reads the instance attribute, which is set before "
                         "any field hook runs, so the value is identical "
                         "either way (measured). It is an error because "
                         "column order in migrations and DDL should follow "
                         "the source, and because L3-row binding would make "
                         "the source's pre_save mutate the instance, at "
                         "which point the order becomes load-bearing and the "
                         "failure would be silent. Establishing it now is "
                         "free. Move the index column below its source.",
                    obj=f, id="fieldseal.E001"))
            source = model._meta.get_field(f.source)
            if isinstance(source, Encrypted) and source.index is None:
                issues.append(Error(
                    f"{model._meta.label}.{f.name} indexes {f.source!r}, "
                    "which declares no BlindIndex(...).",
                    obj=f, id="fieldseal.E001"))

    # An Encrypted field declaring an index with no sibling column is the
    # mirror failure: the declaration promises L2 and nothing stores it.
    for model, field in pairs:
        if field.index is None:
            continue
        siblings = [f for f in model._meta.fields
                    if isinstance(f, EncryptedIndex) and f.source == field.name]
        if not siblings:
            issues.append(Error(
                f"{model._meta.label}.{field.name} declares a BlindIndex but "
                "no index column stores it.",
                hint=f'Add `{field.name}_bidx = '
                     f'Encrypted.index_column("{field.name}")` below it.',
                obj=field, id="fieldseal.E001"))

    # W001 -- an encrypted field in ModelAdmin.search_fields compiles to
    # `icontains`, which `Encrypted.get_lookup` refuses at runtime. `docs/12`
    # §9 makes admin search a non-goal; this is the warning that tells people
    # so at startup rather than on the first search.
    issues.extend(_check_admin_search_fields(pairs, admin_registry))

    # E003 -- surface the core's construction-time gates at startup.
    #
    # This must *build the client*, not merely assemble the declarations. The
    # §7.4 band and the §7.6 cardinality gate run inside `Fieldseal.__init__`,
    # so a check that stopped at `build_index_registry` would report a clean
    # startup for a column the core is about to refuse -- which is worse than
    # no check, because it moves the failure from `manage.py check` to the
    # first request.
    if pairs:
        try:
            # A missing or malformed FIELDSEAL setting is E007, not E003.
            # Reporting "the core refused an index declaration" to a project
            # that has simply not configured the adapter yet sends them to
            # look at their models, which are fine.
            get_settings()
        except FieldsealAdapterError as e:
            issues.append(Error(
                str(e), obj=None, id="fieldseal.E007"))
            return issues
        missing = _missing_required_settings()
        if missing:
            issues.append(Error(
                f"FIELDSEAL is missing required keys: {sorted(missing)}.",
                hint="This project declares encrypted fields, so the adapter "
                     "needs a key provider and an explicit suite policy. "
                     "spec §4.3 gives allowed_suites no default on purpose: "
                     "writing the list out is the suite-retirement mechanism "
                     "working. There is no default KEY_PROVIDER because a "
                     "default would mean shipping a key.",
                obj=None, id="fieldseal.E007"))
            return issues
        try:
            build_client(apps)
        except FieldsealAdapterError as e:
            issues.append(Error(str(e), obj=None, id="fieldseal.E003"))
        except Exception as e:  # noqa: BLE001 - the core's ConfigurationError
            issues.append(Error(
                f"the core refused an index declaration: {e}",
                hint="This is the core's own §7.4 band / §7.6 cardinality "
                     "gate, running where it always runs -- at client "
                     "construction. The adapter does not duplicate the rule; "
                     "fix the declaration named above.",
                obj=None, id="fieldseal.E003"))

        # E006 -- a hand-built client must match the model declarations.
        cfg = get_settings()
        if "CLIENT" in cfg:
            issues.extend(_check_client_registry(apps))

    return issues


def _check_client_registry(registry: Any = None) -> list[Any]:
    """E006: a hand-supplied client's registry must match the models exactly.

    This shipped as a `W004` warning until G18 ([#75]), because the core kept
    its validated registry private and exposed no accessor: the only way to
    compare was to read `Fieldseal._indexes`, and a check written against
    another package's internals fails silently the moment they move -- worse
    than the gap it closes. `docs/09` §2's reflection clause closed that, and
    this is the check it was blocking.

    **Both directions matter, and only one of them is loud.** A client missing
    a declared index fails every lookup on that column at runtime, visibly. A
    client carrying an *extra* index derives and stores values for a column
    under rules no model states, and nothing ever raises -- so an exact match
    is the requirement, not a subset one.

    The comparison is against the *validated* form on both sides: the client
    reports resolved declarations, and the model side is resolved through the
    core's own `validate_index_declaration`. Comparing as-declared inputs
    would let two declarations that agree textually and differ operationally
    register as a match, which is what [#62] was.
    """
    from fieldseal import validate_index_declaration

    from .apps import build_client, build_index_registry

    try:
        client = build_client(registry)
        declared = {
            v.key: v
            for v in (validate_index_declaration(d)
                      for d in build_index_registry(registry))
        }
    except FieldsealAdapterError:
        # A malformed CLIENT or an unbuildable declaration set is E003/E007's
        # to report; this check has nothing to say about it and must not
        # report the same fault twice under a second id.
        return []
    except Exception:  # noqa: BLE001 - the core's ConfigurationError
        return []

    actual = dict(client.indexes)
    missing = sorted(set(declared) - set(actual))
    extra = sorted(set(actual) - set(declared))
    differing = sorted(k for k in set(declared) & set(actual)
                       if declared[k] != actual[k])
    if not (missing or extra or differing):
        return []

    parts = []
    if missing:
        parts.append(
            f"declared on models but absent from the client: {missing}")
    if extra:
        parts.append(f"present in the client but declared on no model: "
                     f"{extra}")
    if differing:
        parts.append(f"declared in both with different resolved parameters: "
                     f"{differing}")
    return [Error(
        "FIELDSEAL['CLIENT']'s index registry does not match the model "
        "declarations -- " + "; ".join(parts) + ".",
        hint="An index the client does not carry fails every lookup on that "
             "column at runtime. An index the models do not declare is worse: "
             "the client derives and stores values for that column under "
             "rules no model states, and nothing raises. Resolved parameters "
             "are compared, not as-written ones, so a difference here is a "
             "difference in what gets stored. Add the missing declarations to "
             "the client, or drop FIELDSEAL['CLIENT'] and let the adapter "
             "build the client from the models.",
        obj=None, id="fieldseal.E006")]


def _missing_required_settings() -> set[str]:
    """Required keys, unless the deployment supplies a whole client."""
    from .apps import get_settings

    cfg = get_settings()
    if "CLIENT" in cfg:
        return set()
    return {k for k in ("KEY_PROVIDER", "ALLOWED_SUITES", "WRITE_SUITE")
            if cfg.get(k) is None}


def _constraint_sites(model: Any, name: str) -> list[str]:
    """Every place `name` is bound into a uniqueness or index declaration.

    `Meta.constraints` with a `fields` list is only one of four. The others
    are `unique_together`, `Meta.indexes`, and expression-based constraints
    and indexes, where the field appears inside an `F()` rather than in a
    plain list of names.
    """
    sites: list[str] = []

    for constraint in getattr(model._meta, "constraints", ()) or ():
        if name in set(getattr(constraint, "fields", ()) or ()):
            sites.append(f"constraint {constraint.name!r}")
        elif _names_in_expressions(getattr(constraint, "expressions", ()), name):
            sites.append(f"expression constraint {constraint.name!r}")

    for group in getattr(model._meta, "unique_together", ()) or ():
        if name in set(group):
            sites.append(f"Meta.unique_together {tuple(group)!r}")

    for index in getattr(model._meta, "indexes", ()) or ():
        if name in set(getattr(index, "fields", ()) or ()):
            sites.append(f"Meta.indexes entry {index.name!r}")
        elif _names_in_expressions(getattr(index, "expressions", ()), name):
            sites.append(f"expression index {index.name!r}")

    return sites


def _names_in_expressions(expressions: Any, name: str) -> bool:
    """Whether `name` appears as an `F()` anywhere in an expression tree."""
    from django.db.models import F

    for expr in expressions or ():
        stack = [expr]
        while stack:
            node = stack.pop()
            if isinstance(node, F) and node.name == name:
                return True
            try:
                stack.extend(node.get_source_expressions())
            except AttributeError:
                continue
    return False


def _check_admin_search_fields(pairs: list[Any],
                               admin_registry: Any = None) -> list[Any]:
    """W001: an encrypted field in `ModelAdmin.search_fields`.

    Admin search compiles to `icontains`, which `Encrypted.get_lookup`
    refuses -- so the failure is loud rather than wrong, but it arrives on
    the first search a person types into the admin instead of at startup.
    `docs/12` §9 lists admin search integration as a non-goal; this is the
    warning that says so where someone will read it.
    """
    if admin_registry is None:
        # `django.contrib.admin` is optional, and merely importing it is not
        # enough to touch its registry: reading `site._registry` calls
        # `apps.get_app_config("admin")`, which raises `LookupError` when the
        # app is not installed. Ask the app registry first.
        from django.apps import apps as django_apps

        if not django_apps.is_installed("django.contrib.admin"):
            return []
        try:
            from django.contrib import admin

            admin_registry = admin.sites.site._registry
        except Exception:  # noqa: BLE001 - admin present but not ready
            return []
    if not admin_registry:
        return []

    encrypted = {(model, f.name) for model, f in pairs}
    issues: list[Any] = []
    for model, model_admin in admin_registry.items():
        for entry in getattr(model_admin, "search_fields", ()) or ():
            base = entry.lstrip("^=@$").split("__")[0]
            if (model, base) in encrypted:
                issues.append(Warning(
                    f"{model._meta.label}.{base} is encrypted and appears in "
                    f"{type(model_admin).__name__}.search_fields.",
                    hint="Admin search compiles to `icontains`, which an "
                         "encrypted column refuses at runtime -- the search "
                         "box will raise rather than return wrong rows. "
                         "Admin search over encrypted fields is a non-goal "
                         "(docs/12 §9); search a plaintext column, or expose "
                         "the value through a blind-index lookup once L2 "
                         "ships.",
                    obj=model_admin, id="fieldseal.W001"))
    return issues
