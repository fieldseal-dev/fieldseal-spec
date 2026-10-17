"""The Django backfill frontend (`tools/backfill/PROCEDURE.md`, version 1).

A frontend is a thin program over one adapter. Everything that decides what a
run stores is the procedure's; what is here is the Django spelling of it: the
state tables through a raw cursor, the batch as one `atomic()` block, the
legacy value read through `Encrypted.from_db_value` or the ORM, and every
write through `FieldsealQuerySet.bulk_update`.

Built so far: the `encrypt` job. `rotate` and the census by key wait on a
header accessor no core exports yet (PROCEDURE §11, D-1); `verify` is not
built.
"""

from __future__ import annotations

#: The `procedure_version` this frontend implements and writes.
PROCEDURE_VERSION = 1


class BackfillError(Exception):
    """A refusal or a stop the operator has to act on.

    The message is this package's own text. It never carries a database or
    core error message, because either can quote a value (PROCEDURE §9
    item 5).
    """
