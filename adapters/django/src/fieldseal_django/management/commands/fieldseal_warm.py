"""`manage.py fieldseal_warm` -- pre-deploy cache priming (`docs/12` §7).

**Why this is not optional for one provider.** `docs/09` §8.2 confines KMS
unwrapping to `warm`/background refresh and forbids `encryption_key` and
`decryption_keys` from blocking on network, because every Django field hook is
synchronous (`docs/04` §1) and a value path that waited on a KMS would block a
worker thread per row. The consequence is exact: an `EnvelopeKeyProvider`
deployment whose cache is cold serves `KEY_UNAVAILABLE` for **every** read
until something warms it. That something is this command, or the
`WARM_ON_READY` setting.

`StaticKeyProvider` and `DerivedKeyProvider` need none of it -- they hold or
derive their keys with no I/O -- so warming is a no-op there rather than an
error, and this command is safe to run in any deployment.

**Tenant-bound columns need their tenants named.** A context for a
tenant-bound column carries a `tenant_id` (spec §6.2), and the adapter cannot
enumerate a deployment's tenants -- they live in the application's own data,
under a schema this package knows nothing about. So they are passed in with
`--tenant`, and a run that omits them says which columns it skipped rather
than reporting a warm cache it did not warm.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand


class Command(BaseCommand):  # type: ignore[misc]
    help = ("Prime the DEK cache for every encrypted column (spec §11.2). "
            "Required before serving reads under an EnvelopeKeyProvider.")

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--tenant", action="append", default=[], metavar="TENANT_ID",
            help="A tenant to warm tenant-bound columns for. Repeatable. "
                 "Without it, tenant-bound columns are skipped and named.")

    def handle(self, *args: Any, **options: Any) -> None:
        from ...apps import get_client
        from ...warm import warm_contexts

        contexts, skipped = warm_contexts(tenants=options["tenant"])
        if not contexts and not skipped:
            self.stdout.write(self.style.SUCCESS(
                "No encrypted columns declared. Nothing to warm."))
            return

        if contexts:
            get_client().warm_blocking(contexts)
            self.stdout.write(self.style.SUCCESS(
                f"Warmed {len(contexts)} context(s) across "
                f"{len({c.table_uuid for c in contexts})} table(s)."))

        for label in skipped:
            # Named individually rather than counted: "3 columns skipped" is
            # not something an operator can act on at 3am.
            self.stdout.write(self.style.WARNING(
                f"skipped {label} -- tenant-bound, and no --tenant given"))
        if skipped:
            self.stdout.write(self.style.WARNING(
                "Reads on the columns above will raise KEY_UNAVAILABLE under "
                "an EnvelopeKeyProvider until they are warmed. Re-run with "
                "--tenant for each tenant this process serves."))
