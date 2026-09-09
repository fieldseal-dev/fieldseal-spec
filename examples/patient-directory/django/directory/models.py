"""The demo's one table, as Django declares it.

The same table is declared a second time in `../../prisma/schema.prisma`, and
`check_declarations.py` compares the two. **Prisma's names are canonical and
Django wears the mapping** (`db_table`, `db_column`), because the Prisma field
map carries no representation of `@map`/`@@map` -- so a mapping on that side
would be invisible to the checker, while Django exposes `db_table` and
`column` on every field. Put the mapping where a program can read it.

**Django owns the DDL.** `manage.py migrate` creates this table and Prisma
only ever runs `prisma generate`. Three reasons, strongest first: the
migration carries `column_uuid` into a committed file, which is the identity
key derivation binds to (spec §6.1) and the thing a rename must not move;
`prisma db push` reaches a target state by dropping and recreating columns,
which against a database Django believes it owns is a data-loss path behind a
friendly prompt; and the asymmetry is real -- Django must believe it owns the
table, Prisma is perfectly happy not to.

**The UUID prefix is `018f5a10-`, deliberately unlike either adapter
fixture's `018f3c2e-`.** The two existing fixtures assign `…000000000001` to
different things -- the Django one to a table, the Prisma one to a column --
so a copy-paste from the wrong fixture would type-check, pass the checker, and
be wrong.

**Three logical types only: string, int and bytes.** The others do **not**
survive a trip between these two adapters today, in three different ways: a
`date` written here is read by Prisma as an instant and comes back in a form
this stack can no longer read at all; a `Decimal` has no declaration on the
Prisma side and becomes a double, losing digits silently; a `boolean` is
`b"True"` here and `b"true"` there, and each side refuses the other. That is
an interoperability gap in the adapters, not in this demo, and it is a
specification gap underneath -- nothing normative pins what bytes a logical
type becomes, or even what the logical types are. `check_declarations.py`
refuses any inner type outside the three and states the measurements, so the
constraint is a tripwire rather than a comment.
"""

from __future__ import annotations

import uuid

from django.db import models
from fieldseal_django import BlindIndex, Encrypted, FieldsealMeta

TABLE_PATIENT = "018f5a10-0000-7000-8000-000000000001"
COL_EMAIL = "018f5a10-0000-7000-8000-000000000002"
COL_NOTE = "018f5a10-0000-7000-8000-000000000003"


class Patient(models.Model):
    """One patient. Two of its four columns hold envelopes."""

    #: Client-generated, and passed explicitly by both stacks in the scenario.
    #: Prisma's `uuid()` is a client-side default that emits no DB default,
    #: which is true and is the one assumption `check_schema_shape.py` would
    #: have to make. Passing the id removes the assumption.
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    #: Plaintext, on purpose. A table where *everything* is encrypted hides
    #: the thing the demo is about: the encrypted columns look different from
    #: the ordinary ones in the raw-SQL act, and there has to be an ordinary
    #: one to look different from.
    mrn = models.TextField()

    #: The committed migration serializes only the *non-default* arguments of
    #: this `BlindIndex` -- `idf` and `projected_population` -- because
    #: `BlindIndex.deconstruct()` emits only what differs from the adapter's
    #: defaults, deliberately, so a later default change shows up as a diff
    #: rather than being baked in. The consequence is worth knowing: a reader
    #: of `0001_initial.py` alone sees a thinner declaration than
    #: `check_declarations.py` compares, and the two agree only while
    #: `index_id`, `normalize` and `truncate_bits` still equal the adapter
    #: defaults. This note lives here rather than in the migration because
    #: `makemigrations` rewrites that file and would drop it.
    email = Encrypted(
        models.EmailField(),
        column_uuid=COL_EMAIL,
        db_column="email",
        index=BlindIndex(
            index_id="exact",
            idf="hmac-sha512",
            normalize="nfc-casefold-v1",
            truncate_bits=15,
            projected_population=100_000,
        ),
    )
    email_bidx = Encrypted.index_column("email", db_column="emailBidx")

    note = Encrypted(
        models.TextField(),
        column_uuid=COL_NOTE,
        null=True,
        db_column="note",
    )

    fieldseal = FieldsealMeta(table_uuid=TABLE_PATIENT)

    class Meta:
        db_table = "Patient"
        indexes = [
            models.Index(fields=["email_bidx"], name="Patient_emailBidx_idx"),
        ]

    def __str__(self) -> str:
        return f"Patient({self.mrn})"
