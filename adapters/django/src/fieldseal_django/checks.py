"""System checks (docs/12 §5) -- correctness enforced at startup.

Every check here catches something that would otherwise be found at runtime,
in production, on a write. Two of them (E001, E003) exist because the failure
they catch is *silent*: a mis-ordered index sibling writes a stale index
value and the row simply stops being findable, and an out-of-band truncation
length degrades the column's privacy without any operation failing.

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

        # E005 -- named in a UniqueConstraint or a composite index.
        for constraint in model._meta.constraints:
            names = set(getattr(constraint, "fields", ()) or ())
            if field.name in names:
                issues.append(Error(
                    f"{label} is named in constraint "
                    f"{constraint.name!r}.",
                    hint="Uniqueness over ciphertext is meaningless and "
                         "uniqueness over a truncated index is forbidden by "
                         "spec §7.10 (G12).",
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
                    hint="The insert compiler iterates fields in declaration "
                         "order, so the index would be derived before the "
                         "plaintext is available -- writing a stale or empty "
                         "index and making the row unfindable, with no error. "
                         "Move the index column below its source.",
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
        try:
            cfg = get_settings()
        except FieldsealAdapterError as e:
            issues.append(Error(str(e), obj=None, id="fieldseal.E006"))
            cfg = {}
        if "CLIENT" in cfg:
            issues.extend(_check_client_registry())

    return issues


def _check_client_registry() -> list[Any]:
    """E006/W004: a hand-built client cannot currently be verified.

    `docs/12` §5 specifies E006 as an *Error* when `FIELDSEAL['CLIENT']`'s
    index registry does not exactly match the model declarations. That check
    cannot be implemented against the core's public API: `Fieldseal` keeps its
    validated registry in a private attribute and exposes no accessor, so the
    only way to compare would be to reach into `_indexes`, and a check that
    depends on another package's internals fails silently the moment they
    change -- which is worse than the gap it closes.

    Rather than ship a check that looks authoritative and is not, this reports
    the gap. The operator learns that the escape hatch bypasses a guarantee,
    which is the actionable half; the missing accessor is recorded as a
    follow-up against `docs/09` §8.
    """
    return [Warning(
        "FIELDSEAL['CLIENT'] is set, so the client's index registry is NOT "
        "verified against the model declarations.",
        hint="docs/12 §5 specifies this as error fieldseal.E006, and it is "
             "downgraded here because the core exposes no public accessor "
             "for a client's validated index registry -- implementing it "
             "would mean reading a private attribute. Keep the two in sync "
             "by hand: a client missing a declared index fails every lookup "
             "on that column at runtime, and one carrying an extra index is "
             "indexing a column under rules no model states. Dropping "
             "FIELDSEAL['CLIENT'] and letting the adapter build the client "
             "restores the guarantee.",
        obj=None, id="fieldseal.W004")]
