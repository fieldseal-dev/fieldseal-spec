"""Envelope parsing, recognition and serialization (spec §3.1, §3.2, §3.4, §3.5).

Recognition (spec §3.4) is the first step of the decrypt path (docs/09 §3.2
step 2) and is deliberately total: for any operand it either returns a parsed
header, returns None ("not one of ours"), or raises `UnknownFormatVersion` --
never anything else. What "not one of ours" becomes -- `NOT_CIPHERTEXT` in
`strict`, pass-through in `permissive` and `readonly` -- is the client's
decision (spec §10.3), not this module's.

Nothing here copies the operand. `decrypt` must refuse an over-bound envelope
*before* allocating for it (spec §3.5), and a recognizer that copied the input
to look at three bytes would have allocated already.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import UnknownFormatVersion
from .registry import SUITES, Suite

FMT_VER = 0x01
HEADER_LEN = 51  # 1 + 2 + 16 + 32
MAX_PLAINTEXT = (1 << 31) - 1  # spec §3.5

# Pinned (docs/09 §3.2 footnote; docs/08 §4.6): the set of "reserved,
# known-future" version bytes for which `UNKNOWN_FORMAT_VERSION` -- "data
# written by a newer implementation" (spec §9) -- is a true statement. No
# document defines this set, so it is declared in the conformance report
# (`pinned_decisions.unknown-format-version-set`). Every other non-0x01 first
# byte is non-ciphertext under §3.4, because a version this implementation has
# never heard of is structurally indistinguishable from plaintext.
RESERVED_FUTURE_FMT_VERS = frozenset({0x02})


def fixed_overhead(suite: Suite) -> int:
    """Bytes an envelope under `suite` carries besides its ciphertext."""
    return HEADER_LEN + suite.nonce_len + suite.tag_len + suite.commit_len


# The smallest envelope any registered suite can produce. A future fmt_ver
# carries an unknown layout, so this global minimum -- not any one suite's --
# is the only defensible "plausible length" for raising UNKNOWN_FORMAT_VERSION.
MIN_ENVELOPE_LEN = min(fixed_overhead(s) for s in SUITES.values())


@dataclass(frozen=True, slots=True)
class EnvelopeHeader:
    fmt_ver: int
    suite_id: int
    key_id: bytes
    msg_seed: bytes


def serialize_header(suite_id: int, key_id: bytes, msg_seed: bytes) -> bytes:
    return (bytes([FMT_VER]) + suite_id.to_bytes(2, "big") + key_id + msg_seed)


def _view(blob: object) -> memoryview | None:
    """A byte view over any contiguous bytes-like operand, or None."""
    if isinstance(blob, memoryview):
        mv = blob
    elif isinstance(blob, (bytes, bytearray)):
        mv = memoryview(blob)
    else:
        return None
    try:
        return mv.cast("B") if mv.format != "B" or mv.ndim != 1 else mv
    except TypeError:
        return None


def recognize(blob: object) -> EnvelopeHeader | None:
    """Spec §3.4 recognition, in docs/09 §3.2's order, and total.

    Returns the parsed header when the operand is an envelope of a registered
    suite at a length that suite can have produced (per-suite minimum, not the
    global one: a 115-byte 0xFF02-tagged blob cannot be an envelope). Returns
    None for anything else, with one exception: a reserved-known-future
    version byte at a plausible length raises `UnknownFormatVersion`, in every
    read mode, because that operand is best explained as ciphertext from a
    newer implementation and silently handing it back as plaintext would be the
    §3.4 double-encryption accident.
    """
    mv = _view(blob)
    if mv is None or len(mv) == 0:
        return None
    fmt_ver = mv[0]
    if fmt_ver != FMT_VER:
        if fmt_ver in RESERVED_FUTURE_FMT_VERS and len(mv) >= MIN_ENVELOPE_LEN:
            raise UnknownFormatVersion(
                f"fmt_ver {fmt_ver:#04x} is reserved for a future format "
                "version; this implementation cannot read it")
        return None
    if len(mv) < HEADER_LEN:
        return None
    suite = SUITES.get(int.from_bytes(mv[1:3], "big"))
    if suite is None:
        return None
    if len(mv) < fixed_overhead(suite):
        return None
    return EnvelopeHeader(
        fmt_ver=fmt_ver,
        suite_id=suite.suite_id,
        key_id=bytes(mv[3:19]),
        msg_seed=bytes(mv[19:51]),
    )


def implied_plaintext_len(blob: object, suite: Suite) -> int:
    """Spec §3.5, decrypt side: a function of the byte count alone."""
    return len(blob) - fixed_overhead(suite)  # type: ignore[arg-type]


def split(blob: object, suite: Suite) -> tuple[bytes, bytes, bytes, bytes]:
    """nonce, ciphertext, tag, commitment of a *recognized* envelope. Callers
    run `recognize` and the §3.5 bound first; this never sees a short blob."""
    mv = _view(blob)
    assert mv is not None and len(mv) >= fixed_overhead(suite)
    i = HEADER_LEN
    nonce = bytes(mv[i:i + suite.nonce_len])
    i += suite.nonce_len
    end = len(mv) - suite.commit_len
    commit = bytes(mv[end:])
    tag = bytes(mv[end - suite.tag_len:end])
    ct = bytes(mv[i:end - suite.tag_len])
    return nonce, ct, tag, commit


def is_ciphertext(blob: object) -> bool:
    """Spec §3.4. Total on arbitrary input: never raises, for any value.

    A cheap structural check only -- it says "this looks like one of ours",
    not "this is authentic". Authenticity is decrypt's job. A reserved future
    version is *not* ciphertext here (§3.4: the version must be recognized),
    even though `decrypt` names it; that tension is D-03 in docs/18.
    """
    try:
        return recognize(blob) is not None
    except UnknownFormatVersion:
        return False
