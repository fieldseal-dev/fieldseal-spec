"""`manage.py fieldseal_backfill` -- the backfill frontend (`docs/12` §7).

The procedure is `tools/backfill/PROCEDURE.md`, version 1, and this command
implements it unchanged. Built so far: `init`, `encrypt`, `resume` and
`abandon`. `rotate` waits on a header accessor no core exports yet
(PROCEDURE §11, D-1), and `verify` is not built.

**What it does not do for you.** Encrypting a table that already held
plaintext does nothing about the copies that already exist, which is why a
new run on a populated table prints PROCEDURE §9's text and refuses to
proceed without `--acknowledge-preexisting-backups`. The command runs inside
an application process that holds the keys, and protects nothing against
that process (spec §2.2).
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):  # type: ignore[misc]
    help = ("Encrypt a table's legacy plaintext through the adapter, "
            "resumably and rate-limited (tools/backfill/PROCEDURE.md).")

    def add_arguments(self, parser: Any) -> None:
        sub = parser.add_subparsers(dest="subcommand", required=True)

        init = sub.add_parser(
            "init", help="Create the two state tables (PROCEDURE §3).")
        init.add_argument(
            "--database", default="default",
            help="The database to create them in: the table's own.")

        encrypt = sub.add_parser(
            "encrypt", help="Start a new encrypt run over one model.")
        encrypt.add_argument("model", metavar="APP_LABEL.MODEL")
        encrypt.add_argument(
            "--columns", metavar="FIELD[,FIELD...]",
            help="The Encrypted fields to cover. Default: all of them.")
        encrypt.add_argument(
            "--source", action="append", default=[],
            metavar="FIELD=LEGACY_FIELD",
            help="Read FIELD's plaintext from LEGACY_FIELD (the two-column "
                 "shape). Repeatable. Without it, FIELD is encrypted in "
                 "place.")
        encrypt.add_argument(
            "--acknowledge-preexisting-backups", action="store_true",
            help="Required to start a run on a table that holds rows.")
        _add_limits(encrypt)

        resume = sub.add_parser(
            "resume", help="Continue a run from its stored cursor.")
        resume.add_argument("run_id")
        resume.add_argument("--database", default="default")
        _add_limits(resume)

        abandon = sub.add_parser(
            "abandon", help="Mark a running run abandoned, releasing its "
                            "table for a new run.")
        abandon.add_argument("run_id")
        abandon.add_argument("--database", default="default")

    def handle(self, *args: Any, **options: Any) -> None:
        from ...backfill import BackfillError

        try:
            getattr(self, f"_{options['subcommand']}")(options)
        except BackfillError as e:
            raise CommandError(str(e)) from None

    # -- subcommands --------------------------------------------------------

    def _init(self, options: dict[str, Any]) -> None:
        from django.db import connections

        from ...backfill import state

        created = state.init(connections[options["database"]])
        state.require_tables(connections[options["database"]])
        if created:
            self.stdout.write(self.style.SUCCESS(
                f"Created {', '.join(created)}."))
        else:
            self.stdout.write("Both state tables already exist.")

    def _encrypt(self, options: dict[str, Any]) -> None:
        from django.apps import apps as django_apps
        from django.db import connections

        from ...backfill import BackfillError, encrypt, report, state

        try:
            model = django_apps.get_model(options["model"])
        except (LookupError, ValueError):
            raise BackfillError(
                f"{options['model']!r} is not an installed model; name it "
                "as app_label.Model.") from None
        sources = {}
        for item in options["source"]:
            target, sep, legacy = item.partition("=")
            if not sep or not target or not legacy:
                raise BackfillError(
                    f"--source takes FIELD=LEGACY_FIELD, not {item!r}.")
            sources[target] = legacy
        columns = (None if options["columns"] is None
                   else [c for c in options["columns"].split(",") if c])
        limits = _limits(options)

        plan = encrypt.plan(model, columns, sources)
        connection = connections[plan.alias]
        encrypt.check_connection(connection)
        state.require_tables(connection)
        if (encrypt.table_has_rows(plan)
                and not options["acknowledge_preexisting_backups"]):
            self.stdout.write(report.PREEXISTING_BACKUPS)
            raise BackfillError(
                "refused: the table holds rows and "
                "--acknowledge-preexisting-backups was not given. Nothing "
                "was written.")
        run = encrypt.new_run(plan)
        self._run(encrypt.Runner(plan, run, limits), run, limits)

    def _resume(self, options: dict[str, Any]) -> None:
        from django.apps import apps as django_apps
        from django.db import connections

        from ...backfill import BackfillError, encrypt, state

        limits = _limits(options)
        connection = connections[options["database"]]
        encrypt.check_connection(connection)
        state.require_tables(connection)
        run = state.load_run(connection, options["run_id"])
        if run is None:
            raise BackfillError(
                f"no run {options['run_id']} in database "
                f"{options['database']!r}.")
        if run.status != "running":
            raise BackfillError(
                f"run {run.run_id} is `{run.status}`, not `running`. Start "
                "a new run instead.")
        plan = encrypt.plan_for(run, list(django_apps.get_models()))
        if plan.alias != options["database"]:
            raise BackfillError(
                f"run {run.run_id} is recorded in {options['database']!r}, "
                f"and its table is written through {plan.alias!r}. The state "
                "tables belong in the table's own database (PROCEDURE §3).")
        self._run(encrypt.Runner(plan, run, limits, resumed=True),
                  run, limits)

    def _abandon(self, options: dict[str, Any]) -> None:
        from django.db import connections

        from ...backfill import BackfillError, state

        connection = connections[options["database"]]
        state.require_tables(connection)
        if not state.abandon(connection, options["run_id"]):
            raise BackfillError(
                f"no running run {options['run_id']} in database "
                f"{options['database']!r}.")
        self.stdout.write(
            f"run {options['run_id']} is abandoned. The rows it converted "
            "stay converted; a new run skips them.")

    def _run(self, runner: Any, run: Any, limits: Any) -> None:
        from ...backfill import report

        for line in report.start_lines(run, runner.resumed, limits):
            self.stdout.write(line)
        outcome = runner.run()
        for line in report.final_lines(outcome):
            self.stdout.write(line)
        if outcome.stopped_by_max_failures:
            raise CommandError(
                f"run {run.run_id} stopped at --max-failures and is still "
                "`running`.")


def _add_limits(parser: Any) -> None:
    parser.add_argument(
        "--batch-size", type=int, default=200,
        help="Rows per batch. Also the bound on how long a batch holds its "
             "locks; the setting to lower first.")
    parser.add_argument(
        "--rows-per-second", type=float, default=200.0,
        help="The rate limit. There is no unlimited setting.")
    parser.add_argument(
        "--max-failures", type=int, default=100,
        help="Stop, leaving the run running, once this process has recorded "
             "this many value failures.")


def _limits(options: dict[str, Any]) -> Any:
    from ...backfill.encrypt import Limits

    return Limits(batch_size=options["batch_size"],
                  rows_per_second=options["rows_per_second"],
                  max_failures=options["max_failures"])
