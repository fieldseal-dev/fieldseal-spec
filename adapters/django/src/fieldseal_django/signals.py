"""The plaintext-read signal and its counter (`docs/12` §4, spec §10.3; #246).

Spec §10.3: in `permissive` and `readonly` a read returns non-envelope input
as it is, and implementations SHOULD emit a metric counting those reads. The
core counts them for the whole client (`Fieldseal.plaintext_reads`). That
says *whether* plaintext is still being read, not *where*. This module
carries the where, so that when the switch to `strict` waits on a count of
zero (`tools/backfill/PROCEDURE.md` §8), a count that is not zero names the
column.

**`plaintext_read`** is sent once per value the core passed through, with
`sender` set to the concrete model that owns the `Encrypted` field
(`field.model`) and `field` to the field's name. Never the value: a receiver
is a metrics or logging hook, and handing it the plaintext would copy the
value into whatever it writes to.

**`plaintext_read_counts()`** is the counter metric: one count per
`(model label, field name)`, kept for the client that made the reads. The
counts belong to the client object, as the core's count does: a rebuilt
client (`apps.reset_client`) starts both at zero, and a `FIELDSEAL["CLIENT"]`
instance, which a reset hands back unchanged, keeps both. While the adapter
is that client's only reader, the counts sum to its `plaintext_reads`.

Both fire on exactly the reads the core counts, and at the same point: after
`decrypt` returned the operand as plaintext, and before the codec renders it.
So a value the codec then refuses (`FieldsealNotSupported`) is still counted
and still signalled -- those are the rows an operator still has to deal
with, and a count that dropped them would read lower than the core's (#253).
A read the core refuses (`NOT_CIPHERTEXT` in strict, `UNKNOWN_FORMAT_VERSION`
in any mode) is neither.

**A receiver cannot break a read.** The signal is sent with `send_robust`,
and a receiver's exception is logged on the `fieldseal_django` logger, not
raised. The value path is the application's read and the backfill's
in-place read (`backfill/encrypt.py`); a metrics client that fails there
would otherwise turn every legacy row into an error, or into a backfill
`INTERNAL` that converts nothing. The count is taken before the signal is
sent, so the metric survives a failing receiver either way.

The counts are per process, like the core's: each worker of a multi-process
server holds its own. A count over a deployment is the signal exported to a
shared metrics backend.
"""

from __future__ import annotations

import logging
import threading
import weakref
from collections import Counter
from typing import Any

from django.dispatch import Signal

#: Sent with `sender=<model class>, field=<field name>` per plaintext read.
plaintext_read = Signal()

logger = logging.getLogger("fieldseal_django")

# Keyed by the client object, so a count can never outlive, or be wiped
# under, the client whose reads it counts -- whatever `reset_client` races
# with. Weak, so a dropped client takes its counts with it.
_counts: weakref.WeakKeyDictionary[Any, Counter[tuple[str, str]]] = (
    weakref.WeakKeyDictionary())
# The value path runs on whatever threads serve requests; `Counter` updates
# are not atomic.
_lock = threading.Lock()


def plaintext_read_counts() -> dict[tuple[str, str], int]:
    """A snapshot for the current client: `{(model label, field name): n}`.

    The model label is `Model._meta.label` (`"app_label.ModelName"`). A
    field with no plaintext read through the current client is absent, not
    zero, and with no client built yet the snapshot is empty. The snapshot is
    a copy; later reads do not change it.
    """
    from .apps import current_client

    client = current_client()
    with _lock:
        counts = _counts.get(client) if client is not None else None
        return dict(counts) if counts else {}


def record_plaintext_read(client: Any, model: Any, field_name: str) -> None:
    """Count one plaintext read made through `client`, then send
    `plaintext_read`.

    Called by `Encrypted.from_db_value` only; not part of the public
    surface.
    """
    with _lock:
        counts = _counts.get(client)
        if counts is None:
            counts = _counts[client] = Counter()
        counts[(model._meta.label, field_name)] += 1
    for receiver, result in plaintext_read.send_robust(
            sender=model, field=field_name):
        if isinstance(result, Exception):
            logger.error(
                "fieldseal_django.signals.plaintext_read receiver %r raised "
                "for %s.%s; the read went on and was counted",
                receiver, model._meta.label, field_name, exc_info=result)
