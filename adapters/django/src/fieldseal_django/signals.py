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
and a receiver's exception is not raised, even for a receiver with no
`__qualname__`. The value path is the
application's read and the backfill's in-place read
(`backfill/encrypt.py`); a metrics client that fails there would otherwise
turn every legacy row into an error, or into a backfill `INTERNAL` that
converts nothing. The count is taken before the signal is sent, so the
metric survives a failing receiver either way.

**A failing receiver is logged once, then counted (#295).** A receiver that
is down fails on every read, and a traceback per read is unbounded. So the
first failure of each receiver, for the client that made the read, is logged
on the `fieldseal_django` logger at ERROR with its traceback, and later
failures of that receiver are counted, not logged. Django's own per-failure
log on `django.dispatch` is switched off for this signal (`_PlaintextReadSignal`,
private `Signal._log_robust_failure`; a test fails if Django renames it).
"First" is per receiver object while it lives (held weakly, so a freed
receiver is forgotten), so two instances of one class are each logged once.
**`plaintext_read_receiver_failures()`** is that count: receiver name to
failures, the logged first one included; receivers that share a dotted name
are summed under it. It is kept per client object, as the
plaintext-read counts are, so a rebuilt client logs a failing receiver again
and a `FIELDSEAL["CLIENT"]` instance keeps its state across `reset_client`.
Never the value, in the log or the count. The name is the receiver's
function (a `functools.partial`'s wrapped function) or its type, never its
`repr`, which can carry a secret or raise.

"A receiver cannot break a read" holds for synchronous receivers and for `async
def` receivers called outside a running event loop: from a thread with a
running loop, an `async def` receiver makes Django's own `send_robust` raise
`RuntimeError` (AsyncToSync; reproduced on Django 6.1.3), which this adapter
does not catch.

The counts are per process, like the core's: each worker of a multi-process
server holds its own. A count over a deployment is the signal exported to a
shared metrics backend.
"""

from __future__ import annotations

import functools
import inspect
import logging
import threading
import weakref
from collections import Counter
from typing import Any

from django.dispatch import Signal

logger = logging.getLogger("fieldseal_django")


class _PlaintextReadSignal(Signal):  # type: ignore[misc,unused-ignore]
    """A `Signal` whose `send_robust` does not log a receiver's failure.

    Django's `Signal.send_robust` calls `self._log_robust_failure(receiver,
    err)` for every receiver exception (Django 5.2.19 and 6.1.3), which logs
    an ERROR with a traceback on the `django.dispatch` logger: one more
    traceback per read, whatever `record_plaintext_read` does. It also reads
    `receiver.__qualname__`, so a receiver without one (a `functools.partial`,
    a callable instance) would raise `AttributeError` out of `send_robust` and
    fail the read. This adapter logs the first failure of each receiver
    itself, and counts the rest, so the hook is silenced here.

    `_log_robust_failure` is private Django API; `test_plaintext_read_signal.py`
    fails if `Signal` stops having it, so a rename is a red build rather than
    a silent return of the traceback per read.
    """

    def _log_robust_failure(self, receiver: Any, err: Exception) -> None:
        pass


#: Sent with `sender=<model class>, field=<field name>` per plaintext read.
plaintext_read = _PlaintextReadSignal()

# Keyed by the client object, so a count can never outlive, or be wiped
# under, the client whose reads it counts -- whatever `reset_client` races
# with. Weak, so a dropped client takes its counts with it.
_counts: weakref.WeakKeyDictionary[Any, Counter[tuple[str, str]]] = (
    weakref.WeakKeyDictionary())
# The value path runs on whatever threads serve requests; `Counter` updates
# are not atomic.
_lock = threading.Lock()
# Receiver failures, with the same keying and the same lock as `_counts`.
_failures: weakref.WeakKeyDictionary[Any, Counter[str]] = (
    weakref.WeakKeyDictionary())
class _Seen:
    """The receivers of one client whose first failure has been logged.

    Held weakly, so a receiver that is disconnected and freed leaves nothing
    behind, and a new object that lands on its address is not mistaken for it
    (CPython reuses ids). A bound method is keyed on its `__self__`, which
    Django resolves afresh on each send, with the ids of the class functions
    that have failed on it; any other receiver is keyed on itself. A receiver
    that cannot be weakly referenced falls back to its `id()`, which can be
    reused after the receiver is freed: a receiver that lands on it would not
    be logged.
    """

    def __init__(self) -> None:
        self.refs: dict[int, weakref.ref[Any]] = {}
        self.funcs: dict[int, set[int]] = {}
        self.fallback: set[tuple[int, int]] = set()

    def first(self, receiver: Any) -> bool:
        """Record `receiver`'s failure; True if it is its first. Called with
        `_lock` held."""
        func = getattr(receiver, "__func__", None)
        owner = getattr(receiver, "__self__", None)
        bound = func is not None and owner is not None
        target = owner if bound else receiver
        sub = id(func) if bound else 0
        key = id(target)
        try:
            if key not in self.refs:
                self.refs[key] = weakref.ref(
                    target, functools.partial(self._gone, key))
        except TypeError:
            if (key, sub) in self.fallback:
                return False
            self.fallback.add((key, sub))
            return True
        done = self.funcs.setdefault(key, set())
        if sub in done:
            return False
        done.add(sub)
        return True

    def _gone(self, key: int, ref: Any) -> None:
        # A weakref callback can run anywhere, with `_lock` held: no locking.
        if self.refs.get(key) is ref:
            self.refs.pop(key, None)
            self.funcs.pop(key, None)


_logged: weakref.WeakKeyDictionary[Any, _Seen] = weakref.WeakKeyDictionary()


def _receiver_name(receiver: Any) -> str:
    """A name for a receiver, stable per receiver function or type, never its
    `repr` (which carries an address, can carry a secret, and can raise).

    A `functools.partial` is named after the function it wraps; a function or
    method is `module.qualname`; anything else, such as a callable instance,
    is its type's `module.qualname`. Receivers that share a name are summed.
    """
    while isinstance(receiver, functools.partial):
        receiver = receiver.func
    module = getattr(receiver, "__module__", None)
    qualname = getattr(receiver, "__qualname__", None)
    if isinstance(module, str) and isinstance(qualname, str) and (
            inspect.isroutine(receiver) or inspect.isclass(receiver)):
        return f"{module}.{qualname}"
    cls = type(receiver)
    return f"{cls.__module__}.{cls.__qualname__}"


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


def plaintext_read_receiver_failures() -> dict[str, int]:
    """A snapshot for the current client: `{receiver name: failures}`.

    The name is `f"{module}.{qualname}"` of the receiver function (of the
    function a `functools.partial` wraps), or of the receiver's type for a
    callable instance; never its `repr`. Receivers that share a name are
    summed. The count includes the first failure, the one that
    was logged; the later ones were not (#295). A receiver that has not failed
    through the current client is absent, not zero, and with no client built
    yet the snapshot is empty. The snapshot is a copy.
    """
    from .apps import current_client

    client = current_client()
    with _lock:
        failures = _failures.get(client) if client is not None else None
        return dict(failures) if failures else {}


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
        if not isinstance(result, Exception):
            continue
        name = _receiver_name(receiver)
        with _lock:
            failed = _failures.get(client)
            if failed is None:
                failed = _failures[client] = Counter()
            failed[name] += 1
            logged = _logged.get(client)
            if logged is None:
                logged = _logged[client] = _Seen()
            first = logged.first(receiver)
        if first:
            logger.error(
                "fieldseal_django.signals.plaintext_read receiver %s raised "
                "for %s.%s; the read went on and was counted. This is the "
                "first failure of this receiver for this client; later ones "
                "are counted, not logged "
                "(fieldseal_django.signals.plaintext_read_receiver_failures)",
                name, model._meta.label, field_name, exc_info=result)
