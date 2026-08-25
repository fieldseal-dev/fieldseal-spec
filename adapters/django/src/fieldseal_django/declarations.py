"""What a model author writes: `BlindIndex` and `FieldsealMeta` (docs/12 §1).

These are declarations, not behaviour. They carry exactly enough to build the
core's `IndexDeclaration` in `AppConfig.ready()` (`docs/12` §7), because the
core's construction-time gates -- the §7.4 truncation band and the §7.6
cardinality gate -- are properties of a column and must run against the
indexes actually declared on models, not against a hand-maintained second
list that can drift.

**Validation lives in the core, not here.** This module deliberately does not
re-check `truncate_bits` against `projected_population`. Duplicating the gate
would give the project two answers to the same question and a way for them to
disagree; `docs/12` §5's E003 surfaces the core's refusal as a startup check
rather than replacing it.
"""

from __future__ import annotations

import uuid as _uuid
from dataclasses import dataclass
from dataclasses import field as _dc_field
from typing import Any

from .errors import FieldsealConfigurationError


def parse_uuid(value: str | bytes | _uuid.UUID, what: str) -> bytes:
    """A 16-byte surrogate from whatever the model author wrote.

    Spec §6.1 requires an immutable surrogate rather than a SQL name, and
    requires 16 bytes. Accepting the hyphenated string form is the ergonomic
    part; refusing anything that is not 16 bytes is the normative part.
    """
    if isinstance(value, _uuid.UUID):
        return value.bytes
    if isinstance(value, bytes):
        if len(value) != 16:
            raise FieldsealConfigurationError(
                f"{what} must be exactly 16 bytes (spec §6.1), got {len(value)}"
            )
        return value
    if isinstance(value, str):
        try:
            return _uuid.UUID(value).bytes
        except ValueError as e:
            raise FieldsealConfigurationError(
                f"{what} is not a UUID: {value!r}. Run "
                "`manage.py fieldseal_gen_uuids` for ready-to-paste values. "
                "Deriving it from the app/model/field name is forbidden "
                "(spec §6.1): a rename would then make every existing row "
                "undecryptable."
            ) from e
    raise FieldsealConfigurationError(
        f"{what} must be a UUID, its string form, or 16 bytes; got "
        f"{type(value).__name__}"
    )


@dataclass(frozen=True)
class Override:
    """The `{reason, approved_by, date}` shape spec §7.6 requires.

    Deliberately the same ceremony for the cardinality gate and for
    `on_unindexable="bucket"`, and for the same reason: each is a per-column
    relaxation of a default-deny rule, so it should be a recorded act rather
    than a setting that gets copied between columns.
    """

    reason: str
    approved_by: str
    date: str


@dataclass(frozen=True)
class BlindIndex:
    """Declares L2 for the column it is attached to (`docs/12` §1).

    Presence is the declaration: a field carrying a `BlindIndex` gets an
    index sibling column and answers `exact`/`in`; a field without one
    refuses those lookups rather than scanning or returning nothing.
    """

    index_id: str = "exact"
    idf: str = "argon2id"
    normalize: str = "nfc-casefold-v1"
    truncate_bits: int = 15
    #: DISTINCT values expected in this column (spec §7.4). Required: there is
    #: no defensible default, and E003 fails startup without it.
    projected_population: int | None = None
    #: Argon2id cost, when raising it above the spec §7.3 minimum. Per column
    #: because §7.3 states the cost as a minimum a deployment MAY raise.
    time_cost: int | None = None
    memory_kib: int | None = None
    cardinality_override: Override | None = None
    skewed: bool = False
    #: docs/09 §7.2 / docs/12 §10. `refuse` fails the write with a field-level
    #: ValidationError; `bucket` stores the column's reserved marker so the
    #: row stays findable. `bucket` requires `unindexable_override`.
    on_unindexable: str = "refuse"
    unindexable_override: Override | None = None

    def __post_init__(self) -> None:
        if self.on_unindexable not in ("refuse", "bucket"):
            raise FieldsealConfigurationError(
                f"on_unindexable must be 'refuse' or 'bucket', got "
                f"{self.on_unindexable!r} (docs/09 §7.2)"
            )


@dataclass
class FieldsealMeta:
    """Per-model declaration: `fieldseal = FieldsealMeta(table_uuid=...)`.

    Required on any model carrying an `Encrypted` field; E004 fails startup
    without it.
    """

    table_uuid: str | bytes | _uuid.UUID
    #: Bind every encrypted column on this model to the ambient tenant
    #: (`docs/12` §4). Per-field `tenant_bound` overrides it.
    tenant_bound: bool = False
    _resolved: bytes = _dc_field(init=False, repr=False, default=b"")

    def __post_init__(self) -> None:
        self._resolved = parse_uuid(self.table_uuid, "table_uuid")

    @property
    def table_uuid_bytes(self) -> bytes:
        return self._resolved

    def contribute_to_class(self, cls: type, name: str, **kwargs: Any) -> None:
        """Django calls this for any class attribute that defines it.

        Implemented so `fieldseal = FieldsealMeta(...)` can sit in the model
        body beside the fields without Django trying to treat it as one.
        """
        setattr(cls, name, self)
