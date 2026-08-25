"""Adapter-level exceptions.

The core's `fieldseal.errors` taxonomy (spec §9) covers what the *core*
refuses. This module covers what the *adapter* refuses, which is a different
list: paths where Django would otherwise write plaintext, or return a wrong
answer, if the adapter stayed quiet.

Spec §10.2 is the rule these exist to keep: *where a path would silently
return wrong results, the adapter MUST throw, not degrade silently.* Every
raise site in this package points at the row of `docs/12` §6 it implements,
so a refusal can be traced to the decision that made it one.
"""

from __future__ import annotations

from fieldseal.errors import FieldsealError


class FieldsealAdapterError(FieldsealError):
    """Base for every refusal this adapter adds to the core's §9 set.

    It subclasses the core's base deliberately: application code that already
    catches `FieldsealError` around a save should not silently miss an
    adapter refusal, because the two mean the same thing to a caller -- this
    value did not get stored the way you asked.
    """


class FieldsealNotSupported(FieldsealAdapterError):
    """A Django path the adapter cannot serve correctly (spec §10.2).

    Raised rather than degraded. The message MUST name the path and the
    supported alternative: a refusal that does not say what to do instead is
    a dead end, and the caller's next move is usually to reach for raw SQL,
    which is the one path this adapter cannot protect at all.
    """


class FieldsealConfigurationError(FieldsealAdapterError):
    """A model or settings declaration the adapter refuses at import or
    startup, where the system-check framework is not available to report it.

    Most declaration errors should surface as `django.core.checks` messages
    instead (`docs/12` §5), because a check reports *every* problem at once
    and names the model, where an exception stops at the first. This is for
    the cases that must fail before checks run.
    """
