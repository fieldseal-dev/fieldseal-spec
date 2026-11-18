"""The plaintext-read signal and its counter (`docs/12` §4, spec §10.3; #246).

Spec §10.3: in `permissive` and `readonly` a read returns non-envelope input
as it is, and implementations SHOULD emit a metric counting those reads. The
core counts them for the whole client (`Fieldseal.plaintext_reads`). That
says *whether* plaintext is still being read, not *where*, and
`tools/backfill/PROCEDURE.md` §8 gates the switch to `strict` on the count
being zero, per model and field. This module carries the where.

**`plaintext_read`** is sent once per value the core passed through, with
`sender` set to the model class the `Encrypted` field is declared on and
`field` to the field's name. Never the value: a receiver is a metrics or
logging hook, and handing it the plaintext would copy the value into
whatever it writes to.

**`plaintext_read_counts()`** is the counter metric: one count per
`(model label, field name)`, kept since the adapter's client was last built.
It resets with the client (`apps.reset_client`), so while the adapter's own
client is the only reader, the counts sum to the core's
`client.plaintext_reads`.

Both fire on exactly the reads the core counts, and at the same point: after
`decrypt` returned the operand as plaintext, and before the codec renders it.
So a value the codec then refuses (`FieldsealNotSupported`) is still counted
and still signalled -- those are the rows an operator still has to deal
with, and a count that dropped them would read lower than the core's (#253).
A read the core refuses (`NOT_CIPHERTEXT` in strict, `UNKNOWN_FORMAT_VERSION`
in any mode) is neither. The count is taken before the signal is sent, so a
receiver that raises does not lose it; the receiver's exception then
propagates out of the read, as Django's own `send` propagates it.
"""

from __future__ import annotations

import threading
from collections import Counter
from typing import Any

from django.dispatch import Signal

#: Sent with `sender=<model class>, field=<field name>` per plaintext read.
plaintext_read = Signal()

_counts: Counter[tuple[str, str]] = Counter()
# The value path runs on whatever threads serve requests; `Counter` updates
# are not atomic.
_lock = threading.Lock()


def plaintext_read_counts() -> dict[tuple[str, str], int]:
    """A snapshot: `{(model label, field name): plaintext reads}`.

    The model label is `Model._meta.label` (`"app_label.ModelName"`). A
    field with no plaintext read since the client was built is absent, not
    zero. The snapshot is a copy; later reads do not change it.
    """
    with _lock:
        return dict(_counts)


def record_plaintext_read(model: Any, field_name: str) -> None:
    """Count one plaintext read, then send `plaintext_read`.

    Called by `Encrypted.from_db_value` only; not part of the public
    surface.
    """
    with _lock:
        _counts[(model._meta.label, field_name)] += 1
    plaintext_read.send(sender=model, field=field_name)


def reset_counts() -> None:
    """Drop every count. Called with `apps.reset_client`."""
    with _lock:
        _counts.clear()
