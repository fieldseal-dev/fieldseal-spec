"""Fixtures shared across the Django adapter's tests."""

from __future__ import annotations

import contextlib
import sys

import pytest
from django.db import connection
from django.test.utils import override_settings

from .migration_cases import Case, guard_off


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(tmp_path))
    made: list[Case] = []
    stack = contextlib.ExitStack()

    def make(old: str = "", change="", graph=None) -> Case:
        c = Case(tmp_path, old, change, graph)
        made.append(c)
        stack.enter_context(
            override_settings(MIGRATION_MODULES={"app252": c.package}))
        return c

    try:
        yield make
    finally:
        try:
            for c in made:
                # Unapplying may cross a plain AlterField a test applied with
                # the guard off; the guard has been asserted by then.
                with guard_off():
                    c.migrate("zero")
        finally:
            # A squashed migration's own row outlives `migrate zero`.
            with connection.cursor() as cur:
                cur.execute("DELETE FROM django_migrations "
                            "WHERE app = 'app252'")
            stack.close()
            for name in list(sys.modules):
                if name.startswith("m252_"):
                    del sys.modules[name]
