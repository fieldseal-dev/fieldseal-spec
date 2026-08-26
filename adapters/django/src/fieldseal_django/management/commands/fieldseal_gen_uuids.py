"""`manage.py fieldseal_gen_uuids` -- the command E004's hint names.

Spec §6.1 requires `table_uuid`/`column_uuid` to be **immutable surrogates**,
not SQL names, and forbids deriving them from `app_label.ModelName.field`.
That prohibition is the whole reason this command exists: the obvious
alternative to typing a UUID is generating one from the model's name, and a
rename would then make every existing row undecryptable. So the values have
to come from somewhere, and asking a person to find a UUID generator is how
they end up pasting the same one into two columns.

**It prints; it never edits.** The values belong in the model source, in a
diff a human reviews, because a `column_uuid` that changes is a data-loss
event and a `column_uuid` that repeats silently binds two columns to one key
derivation. Neither is a thing to let a command do unattended.
"""

from __future__ import annotations

import uuid
from typing import Any

from django.core.management.base import BaseCommand


def missing_table_uuids(registry: Any = None) -> list[str]:
    """Models with an encrypted column and no `FieldsealMeta`.

    `registry` exists for the same reason `apps.iter_encrypted_fields` takes
    one: a function that can only be exercised against the real app registry
    can only be tested by breaking the project's own models.
    """
    from ...apps import iter_encrypted_fields

    seen: list[str] = []
    for model, _field in iter_encrypted_fields(registry):
        label = model._meta.label
        if getattr(model, "fieldseal", None) is None and label not in seen:
            seen.append(label)
    return seen


class Command(BaseCommand):  # type: ignore[misc]
    help = ("Print ready-to-paste table_uuid/column_uuid values for "
            "fieldseal-encrypted models (spec §6.1).")

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--count", type=int, default=1, metavar="N",
            help="How many column_uuid values to print (default 1).")
        parser.add_argument(
            "--missing", action="store_true",
            help="Print a table_uuid for each model that declares an "
                 "encrypted column but no FieldsealMeta -- the models system "
                 "check E004 rejects.")

    def handle(self, *args: Any, **options: Any) -> None:
        if options["missing"]:
            self._missing()
            return
        count = options["count"]
        if count < 1:
            self.stderr.write("--count must be at least 1")
            return
        self.stdout.write(self.style.MIGRATE_HEADING(
            "Paste these into your model source (spec §6.1):"))
        self.stdout.write("")
        for _ in range(count):
            self.stdout.write(f'    "{uuid.uuid4()}"')
        self.stdout.write("")
        self._footer()

    def _missing(self) -> None:
        """Label each value with the declaration it is for.

        A bare list of UUIDs is where the copy-paste mistakes come from -- two
        columns getting the same one binds them to the same key derivation,
        and nothing raises.

        **Only `table_uuid` can be missing.** `column_uuid` is a required
        keyword argument of `Encrypted(...)`, so a column without one does not
        construct; an earlier version of this command also looked for those
        and would have reported nothing forever.
        """
        rows = missing_table_uuids()
        if not rows:
            self.stdout.write(self.style.SUCCESS(
                "Every model with an encrypted column already declares a "
                "table_uuid. Nothing to generate."))
            return

        self.stdout.write(self.style.MIGRATE_HEADING(
            "Surrogates still needed (spec §6.1, system check E004):"))
        self.stdout.write("")
        for label in rows:
            self.stdout.write(f"  {label}")
            self.stdout.write(
                f'      fieldseal = FieldsealMeta(table_uuid="{uuid.uuid4()}")')
        self.stdout.write("")
        self._footer()

    def _footer(self) -> None:
        self.stdout.write(self.style.WARNING(
            "These must never change once a row has been written: the key "
            "derivation binds to them (spec §6.1), so editing one makes every "
            "existing row in that column undecryptable. That is also why they "
            "are printed rather than written for you -- they belong in a diff "
            "someone reads. Do not derive them from model or column names; a "
            "rename would then be the same data-loss event."))
