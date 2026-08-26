"""The `refuse` message for an unindexable value (`docs/12` §10.2).

`encrypt` does not normalize and `blind_index` does, so a value containing a
code point the pinned Unicode version does not define **stores perfectly well
and cannot be fingerprinted** (docs/09 §7.2). Under `on_unindexable="refuse"`
the write is rejected, and §10.2 makes three normative demands of how that
rejection reads. The core's own message meets none of them, and correctly so
-- it is addressed to whoever wired the column:

    value contains U+0378, which is not assigned in Unicode 17.0.0;
    `nfc-casefold-v1` is pinned to that version and cannot index a character
    it does not define

That is the right message for a log and the wrong one for a person typing
their own name into a form. §10.2 requires the message to:

1. **name the character and where it is** -- "somewhere in this field" is not
   something anyone can act on;
2. **put the fault on the system** -- the value is not invalid, it is a name,
   and the pinned tables are behind. Wording that implies a user mistake is
   wrong on the facts;
3. **offer a route that ends with the real value stored** -- which is why
   `refuse` and `bucket` are specified as a pair. `bucket` is the
   operator-applied escape hatch, not a rival philosophy, and "contact
   support" is only honest because an operator can actually move the column.

**Finding the offending character uses the core as the oracle.** The adapter
must not carry its own copy of the Unicode assignment table -- that table
decides index values, so a second copy that drifts is a silent lookup miss
(docs/09 §7.1). Instead each code point is offered to the core's own
normalizer until one is refused. Refusal under `nfc-casefold-v1` is a per
-code-point property (unassigned, or an unpaired surrogate), so probing one
character at a time gives the same answer as probing the whole string.
"""

from __future__ import annotations

from typing import Any

#: Kept short deliberately. A message that scrolls is a message nobody reads,
#: and the actionable part is the character and the route.
_TEMPLATE = (
    "We can't save this {noun} yet. Our systems don't recognise the "
    "character {char} ({ordinal} character). This is a gap on our side, not "
    "a problem with your {noun} -- it's a character we haven't added support "
    "for yet. You can save with a different spelling, or contact support and "
    "we can enter it manually."
)


def locate_unindexable(normalizer: str, value: str) -> tuple[int, str] | None:
    """Return `(index, character)` of the first code point the normalizer
    refuses, or `None` if it refuses none.

    `None` is a real outcome rather than an error path: a normalizer can
    refuse a *string* for a reason no single character carries, and in that
    case the caller falls back to a message that names no position rather
    than inventing one.
    """
    from fieldseal import normalize
    from fieldseal.errors import InvalidArgument

    for i, ch in enumerate(value):
        try:
            normalize(normalizer, ch)
        except InvalidArgument:
            return i, ch
    return None


def _ordinal(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def user_message(normalizer: str, value: Any, noun: str = "value") -> str:
    """The §10.2-shaped message for a refused value.

    `noun` lets a deployment say "name" where the column holds one; §10.2's
    worked example is a name, and "we can't save this value" is measurably
    colder than "we can't save this name" for the person reading it.
    """
    if not isinstance(value, str):
        # A non-text column cannot reach the Unicode pin at all; if some
        # future normalizer refuses bytes, say so without guessing a position.
        return (
            f"We can't save this {noun} yet -- our systems don't recognise "
            "part of it. This is a gap on our side, not a problem with your "
            f"{noun}. Contact support and we can enter it manually."
        )
    found = locate_unindexable(normalizer, value)
    if found is None:
        return (
            f"We can't save this {noun} yet -- our systems don't recognise "
            "part of it. This is a gap on our side, not a problem with your "
            f"{noun}. Contact support and we can enter it manually."
        )
    index, char = found
    return _TEMPLATE.format(noun=noun, char=char, ordinal=_ordinal(index + 1))


def operator_detail(normalizer: str, value: Any) -> str:
    """The engineer-facing half, for logs and `ValidationError.params`.

    Kept separate from `user_message` on purpose: §10.2's requirement 2 is
    about what the person who typed the value reads, and a code point and a
    Unicode version in the same sentence undo it.
    """
    if not isinstance(value, str):
        return f"normalizer {normalizer!r} refused a non-text value"
    found = locate_unindexable(normalizer, value)
    if found is None:
        return f"normalizer {normalizer!r} refused the value"
    index, char = found
    return (f"normalizer {normalizer!r} refused U+{ord(char):04X} at index "
            f"{index}")


def validation_error(normalizer: str, value: Any, noun: str = "value") -> Any:
    """The `ValidationError` both refusal sites raise.

    Built here rather than at each site because `ValidationError` **drops
    `code` and `params` when its message is a dict** -- so the inner error has
    to carry them, and a caller that builds the dict itself loses the
    machine-readable half without any warning that it did.
    """
    from django.core.exceptions import ValidationError

    return ValidationError(
        user_message(normalizer, value, noun=noun),
        code="fieldseal_unindexable",
        params={"detail": operator_detail(normalizer, value)},
    )
