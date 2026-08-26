"""`manage.py fieldseal_gen_uuids` (`docs/12` §1.1).

Two system-check hints and one declaration error name this command. Until it
existed those were instructions to run something that was not there, which is
worse than no hint: it tells the reader the problem is their installation.
"""

from __future__ import annotations

import re
import uuid
from io import StringIO

from django.core.management import call_command

UUID_RE = re.compile(
    r'"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"')


def run(*args):
    out = StringIO()
    call_command("fieldseal_gen_uuids", *args, stdout=out)
    return out.getvalue()


def test_the_command_the_hints_name_actually_exists():
    """`checks.py` E004 and `declarations.py` both tell the reader to run
    this. A hint pointing at a missing command sends them to debug their
    install instead of their model."""
    assert UUID_RE.search(run())


def test_it_prints_a_parseable_surrogate():
    """The printed form has to be one `parse_uuid` accepts, or the paste
    fails at startup and the command has moved the problem rather than
    solved it."""
    from fieldseal_django.declarations import parse_uuid

    (value,) = UUID_RE.findall(run())
    assert len(parse_uuid(value, "column_uuid")) == 16


def test_count_prints_distinct_values():
    """The failure this guards is not "too few" -- it is the same value
    printed twice and pasted into two columns, which binds them to one key
    derivation with nothing raising."""
    values = UUID_RE.findall(run("--count", "5"))
    assert len(values) == 5
    assert len(set(values)) == 5


def test_values_are_random_not_derived():
    """Spec §6.1 forbids deriving a surrogate from `app_label.ModelName.field`
    -- a rename would then make every row undecryptable. Two runs agreeing
    would mean something derived crept in."""
    assert UUID_RE.findall(run("--count", "3")) != UUID_RE.findall(run("--count", "3"))


def test_it_states_the_immutability_consequence():
    """A UUID with no warning attached looks like a config value somebody may
    tidy later."""
    text = run()
    assert "never change" in text
    assert "undecryptable" in text


def test_missing_reports_nothing_when_every_model_declares_one():
    assert "Nothing to generate" in run("--missing")


def test_missing_finds_the_model_E004_would_reject():
    """The two are the same condition seen from either end: E004 fails
    startup, this prints the value that fixes it."""
    from django.db import models
    from django.test.utils import isolate_apps

    from fieldseal_django import Encrypted
    from fieldseal_django.management.commands.fieldseal_gen_uuids import (
        missing_table_uuids,
    )

    with isolate_apps("tests") as apps:
        class NeedsOne(models.Model):
            body = Encrypted(models.TextField(), column_uuid=uuid.uuid4(),
                             null=True)

        assert "tests.NeedsOne" in missing_table_uuids(apps)


def test_only_table_uuid_can_be_missing():
    """`column_uuid` is a required keyword argument, so a column without one
    does not construct. An earlier version of this command looked for those
    too and would have reported nothing forever."""
    import pytest
    from django.db import models

    from fieldseal_django import Encrypted

    with pytest.raises(TypeError):
        Encrypted(models.TextField())  # type: ignore[call-arg]


def test_the_command_never_edits_source():
    """It prints. A `column_uuid` that changes is a data-loss event and one
    that repeats binds two columns to one derivation; neither belongs to a
    command running unattended."""
    from fieldseal_django.management.commands import fieldseal_gen_uuids

    source = fieldseal_gen_uuids.__file__
    with open(source, encoding="utf-8") as fh:
        body = fh.read()
    for writing in ("open(", "Path(", "write_text", "os.replace"):
        assert writing not in body, (
            f"{writing} appeared in a command documented as print-only")
