"""The Django half of the scenario. One act per process invocation.

    DJANGO_SETTINGS_MODULE=settings python -m directory.scenario <step>

**The database is the only channel between the two stacks.** Nothing here
passes a value in memory to the Prisma half, and nothing reads a file it
wrote: every claim is made about bytes that went through Postgres. That is
what makes the demo an assertion rather than a picture of one, and it is why
each step is its own process rather than a function call in a driver.

**Nothing asserts an exact ciphertext.** Every envelope carries a fresh nonce
and `msg_seed` (spec §3.1, §4.4), and the fixed-nonce affordance that would
make one reproducible is a test-mode-only facility an implementation must
never accept outside it (`vectors/README.md`). So the assertions here are
structural: envelope *length*, the 19-byte header the two writers must share,
the inequality of two envelopes over the same plaintext, the byte-equality of
the two blind indexes, and the absence of the plaintext as a substring.
Randomness appears as lengths and inequalities, never compared to a literal.
"""

from __future__ import annotations

import json
import pathlib
import sys
import uuid
from typing import Any

DEMO = pathlib.Path(__file__).resolve().parents[2]
TRANSCRIPT = DEMO / "transcript"

#: Both stacks pass ids explicitly, so the narration is the same on every run
#: and a row can be named across a process boundary without a lookup.
ADA = uuid.UUID("018f5a10-0001-7000-8000-000000000001")
GRACE = uuid.UUID("018f5a10-0001-7000-8000-000000000002")
SHARED_DJANGO = uuid.UUID("018f5a10-0001-7000-8000-000000000005")
SHARED_PRISMA = uuid.UUID("018f5a10-0001-7000-8000-000000000006")

#: Spec §3.1: the fixed overhead of suite 0xFF01 is
#: 1 + 2 + 16 + 32 + 12 + 16 + 32 = 111 bytes, so an envelope's length is a
#: function of its plaintext's length and nothing else.
ENVELOPE_OVERHEAD = 111
#: `fmt_ver` (1) + `suite_id` (2) + `key_id` (16). Deterministic, and the only
#: part of an envelope two independent writers must agree on byte for byte.
HEADER_LEN = 19


class Failed(Exception):
    """An assertion did not hold. Recorded, then re-raised."""


class Act:
    """One act: its narration, its assertions, and its transcript entry."""

    def __init__(self, order: int, step: str, act: int, title: str,
                 proves: str) -> None:
        self.order, self.step, self.act = order, step, act
        self.title, self.proves = title, proves
        self.assertions: list[dict[str, Any]] = []

    def say(self, line: str = "") -> None:
        print(line)

    def head(self) -> None:
        print(f"--- Act {self.act} * {self.title} "
              + "-" * max(0, 62 - len(self.title)))
        print(f"    {self.proves}")
        print()

    def check(self, claim: str, ok: bool, detail: str = "") -> None:
        self.assertions.append(
            {"claim": claim, "ok": bool(ok), "detail": detail})
        if not ok:
            raise Failed(f"{claim} -- {detail}")

    def write(self) -> None:
        TRANSCRIPT.mkdir(parents=True, exist_ok=True)
        path = TRANSCRIPT / f"{self.order:02d}-django-{self.step}.json"
        path.write_text(
            json.dumps(
                {
                    "act": self.act,
                    "step": self.step,
                    "stack": "django",
                    "title": self.title,
                    "proves": self.proves,
                    "assertions": self.assertions,
                    "warnings": [],
                },
                indent=1,
            )
            + "\n",
            "utf-8",
        )


# -- helpers ---------------------------------------------------------------


def raw(column: str, pk: uuid.UUID) -> bytes | None:
    """A column as the database holds it, read through a cursor.

    Through a cursor and not the ORM on purpose: `from_db_value` would
    decrypt, and what the other stack receives is the stored column, not this
    adapter's view of it.
    """
    from django.db import connection

    with connection.cursor() as cur:
        cur.execute(f'SELECT "{column}" FROM "Patient" WHERE id = %s', [str(pk)])
        row = cur.fetchone()
    if row is None:
        return None
    value = row[0]
    return None if value is None else bytes(value)


def header() -> bytes:
    from django.conf import settings

    return b"\x01" + settings.SUITE_ID.to_bytes(2, "big") + settings.KEY_ID


def show_envelope(a: Act, label: str, envelope: bytes, plaintext: str) -> None:
    a.say(f"    {label}")
    a.say(f"      envelope     {len(envelope)} bytes "
          f"= {ENVELOPE_OVERHEAD} fixed + {len(plaintext.encode())} plaintext "
          f"(spec §3.1)")
    a.say(f"      header       {envelope[:HEADER_LEN].hex()}")
    a.say("                   fmt_ver 0x01 | suite 0xFF01 | key_id "
          f"{envelope[3:HEADER_LEN].hex()}")


# -- the acts --------------------------------------------------------------


def reset() -> int:
    """Not an act: empty the table so the narration is the same every run."""
    from directory.models import Patient

    deleted, _ = Patient.objects.all().delete()
    print(f"--- Setup * cleared {deleted} row(s) from \"Patient\" "
          + "-" * 24)
    print()
    return 0


def act1_write(a: Act) -> None:
    from directory.models import Patient

    email, note = "ada@example.com", "peanut allergy"
    a.say(f'    Patient.objects.create(id={ADA}, mrn="MRN-0001",')
    a.say(f'                           email="{email}", note="{note}")')
    a.say()
    Patient.objects.create(id=ADA, mrn="MRN-0001", email=email, note=note)

    envelope = raw("email", ADA)
    bidx = raw("emailBidx", ADA)
    assert envelope is not None and bidx is not None
    show_envelope(a, '"Patient"."email" now holds:', envelope, email)
    a.say(f"      plaintext    {email!r} does not appear in the column")
    a.say()
    a.say('    "Patient"."emailBidx" now holds:')
    a.say(f"      blind index  {len(bidx)} bytes = {bidx.hex()}  "
          f"(15 bits, spec §7.4)")
    a.say()

    a.check("the value path encrypted: the column is an envelope of the "
            "right length",
            len(envelope) == ENVELOPE_OVERHEAD + len(email.encode()),
            f"{len(envelope)} bytes")
    a.check("the plaintext is not a substring of the stored column",
            email.encode() not in envelope, "")
    a.check("the envelope header is fmt_ver 0x01, suite 0xFF01, the "
            "configured key_id",
            envelope[:HEADER_LEN] == header(), envelope[:HEADER_LEN].hex())
    a.check("the blind index is ceil(15/8) = 2 bytes (spec §7.11)",
            len(bidx) == 2, bidx.hex())


def act4_read_search(a: Act) -> None:
    """The claim in the Prisma -> Django direction, both halves."""
    from directory.models import Patient

    a.say(f"    Patient.objects.get(id={GRACE})   # written by Prisma")
    row = Patient.objects.get(id=GRACE)
    a.say(f"      mrn          {row.mrn!r}   (plaintext column)")
    a.say(f"      email        {row.email!r}   (decrypted from the envelope)")
    a.say(f"      note         {row.note!r}")
    a.say()
    a.check("Django decrypts a row Prisma wrote -- the central claim, in "
            "this direction",
            row.email == "Grace@Example.COM", repr(row.email))
    a.check("the plaintext column is untouched by either stack",
            row.mrn == "MRN-0002", repr(row.mrn))

    a.say('    Patient.objects.get(email="grace@example.com")')
    a.say("      # lower case: `nfc-casefold-v1` is the column's one equality")
    found = Patient.objects.get(email="grace@example.com")
    a.say(f"      found        {found.id}  mrn={found.mrn!r}")
    a.say()
    a.check("a lookup Python derived finds a row TypeScript indexed -- the "
            "failure with no error message",
            found.id == GRACE, str(found.id))
    a.check("equality is the normalizer's equality (spec §7.5, G19): "
            "'grace@…' matched a row stored as 'Grace@Example.COM'",
            found.email == "Grace@Example.COM", repr(found.email))


def act5_write_shared(a: Act) -> None:
    from directory.models import Patient

    email = "mallory@example.com"
    a.say(f'    Patient.objects.create(id={SHARED_DJANGO}, mrn="MRN-0005-DJ",')
    a.say(f'                           email="{email}")')
    a.say("      # Prisma writes the same address to a different row next.")
    a.say()
    Patient.objects.create(id=SHARED_DJANGO, mrn="MRN-0005-DJ", email=email)
    envelope = raw("email", SHARED_DJANGO)
    assert envelope is not None
    show_envelope(a, "written:", envelope, email)
    a.say()
    a.check("Django wrote the shared-plaintext row",
            len(envelope) == ENVELOPE_OVERHEAD + len(email.encode()),
            f"{len(envelope)} bytes")


def act5_compare(a: Act) -> None:
    """The act no CI job covers: two independent writers, one plaintext."""
    dj_env, dj_idx = raw("email", SHARED_DJANGO), raw("emailBidx", SHARED_DJANGO)
    pr_env, pr_idx = raw("email", SHARED_PRISMA), raw("emailBidx", SHARED_PRISMA)
    assert dj_env and dj_idx and pr_env and pr_idx

    a.say("    Two rows, one plaintext, written by two languages:")
    a.say()
    a.say(f"      Django   envelope {len(dj_env)} bytes, "
          f"header {dj_env[:HEADER_LEN].hex()}")
    a.say(f"               index    {dj_idx.hex()}")
    a.say(f"      Prisma   envelope {len(pr_env)} bytes, "
          f"header {pr_env[:HEADER_LEN].hex()}")
    a.say(f"               index    {pr_idx.hex()}")
    a.say()
    a.say("      headers  identical -- same format, same suite, same key")
    a.say("      bodies   different -- a fresh nonce and msg_seed per write")
    a.say("      indexes  identical -- which is what makes either stack's")
    a.say("               lookup find the other stack's row")
    a.say()

    a.check("the two writers produced the same 19-byte header "
            "(fmt_ver, suite_id, key_id)",
            dj_env[:HEADER_LEN] == pr_env[:HEADER_LEN],
            dj_env[:HEADER_LEN].hex())
    a.check("the two envelopes differ: a fresh nonce and msg_seed on every "
            "write, including this one (spec §4.4)",
            dj_env != pr_env, "")
    a.check("the two envelopes are the same length: the difference is "
            "randomness, not encoding",
            len(dj_env) == len(pr_env), f"{len(dj_env)} bytes")
    a.check("the two blind indexes are byte-equal -- derived independently, "
            "in two languages, from one declaration",
            dj_idx == pr_idx, dj_idx.hex())


def act6_refusals(a: Act) -> None:
    """Django serves what it can materialize, and refuses the rest."""
    from fieldseal_django import FieldsealNotSupported

    from directory.models import Patient

    a.say('    Patient.objects.filter(email="ada@example.com").count()')
    served = Patient.objects.filter(email="ada@example.com").count()
    a.say(f"      -> {served}")
    a.say("      Served. Django materializes the §7.4 candidate bucket and")
    a.say("      re-verifies it (spec §7.5) before counting. The Prisma")
    a.say("      adapter refuses the same call -- see act 6's other half.")
    a.say()
    a.check("Django serves count() over an indexed encrypted column by "
            "materializing and re-verifying the bucket",
            served == 1, str(served))

    a.say('    Patient.objects.exclude(email="ada@example.com")')
    try:
        list(Patient.objects.exclude(email="ada@example.com"))
    except FieldsealNotSupported as e:
        a.say(f"      -> {type(e).__name__}:")
        for line in _wrap(str(e)):
            a.say(f"         {line}")
        a.say()
        a.check("an exclusion over an encrypted column is refused, not "
                "approximated (spec §10.2, G24)", True, type(e).__name__)
    else:
        a.check("an exclusion over an encrypted column is refused", False,
                "the queryset was served")


def act7_raw_sql(a: Act) -> None:
    """What the DBA sees."""
    from django.db import connection

    sql = ('SELECT "mrn", "email", "emailBidx", "note" '
           'FROM "Patient" ORDER BY "mrn"')
    a.say(f"    {sql}")
    a.say("      # through psycopg, with no adapter in the path")
    a.say()
    with connection.cursor() as cur:
        cur.execute(sql)
        rows = [tuple(r) for r in cur.fetchall()]

    a.say("      mrn          email                    emailBidx  note")
    a.say("      -----------  -----------------------  ---------  ----------")
    for mrn, email, bidx, note in rows:
        email_b = bytes(email)
        note_s = "NULL" if note is None else f"<{len(bytes(note))} bytes>"
        a.say(f"      {mrn:<11}  <{len(email_b)} bytes of envelope>   "
              f"{bytes(bidx).hex():<9}  {note_s}")
    a.say()
    a.say("      The mrn is readable because it is not encrypted. Nothing")
    a.say("      else is, and no key is reachable from this connection.")
    a.say()

    plaintexts = [b"ada@example.com", b"Grace@Example.COM",
                  b"mallory@example.com", b"peanut allergy"]
    blob = b"".join(bytes(r[1]) + (b"" if r[3] is None else bytes(r[3]))
                    for r in rows)
    a.check("no plaintext this scenario wrote appears anywhere in the "
            "encrypted columns",
            not any(p in blob for p in plaintexts), f"{len(blob)} bytes scanned")
    a.check("every blind index is 2 bytes -- 15 bits, spec §7.4's band at "
            "P=100,000",
            all(len(bytes(r[2])) == 2 for r in rows), f"{len(rows)} rows")
    a.check("the scenario left exactly the four rows it wrote",
            len(rows) == 4, f"{len(rows)} rows")


def _wrap(text: str, width: int = 68) -> list[str]:
    """Deterministic wrapping, so a refusal message is one shape every run."""
    out: list[str] = []
    line = ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


STEPS = {
    "write": (1, 1, "Django writes a patient",
              "the value path encrypts, and the plaintext is not in the column"),
    "read-search": (5, 4, "Django reads and searches a row Prisma wrote",
                    "the central claim in the other direction, both halves"),
    "write-shared": (6, 5, "Django writes the shared plaintext",
                     "half of the act that compares two writers"),
    "compare-writers": (8, 5, "Two languages, one plaintext",
                        "headers identical, ciphertexts different, indexes "
                        "equal"),
    "refusals": (9, 6, "Django serves what it can, and refuses the rest",
                 "adapters throw rather than degrade"),
    "raw-sql": (11, 7, "What the DBA sees",
                "no plaintext anywhere; the index is two bytes"),
}

RUNNERS = {
    "write": act1_write,
    "read-search": act4_read_search,
    "write-shared": act5_write_shared,
    "compare-writers": act5_compare,
    "refusals": act6_refusals,
    "raw-sql": act7_raw_sql,
}


def main(argv: list[str]) -> int:
    import os

    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
    import django

    django.setup()

    if len(argv) != 2 or (argv[1] not in STEPS and argv[1] != "reset"):
        print(f"usage: python -m directory.scenario "
              f"{{reset,{','.join(STEPS)}}}", file=sys.stderr)
        return 2
    step = argv[1]
    if step == "reset":
        return reset()

    order, act_no, title, proves = STEPS[step]
    a = Act(order, step, act_no, title, proves)
    a.head()
    try:
        RUNNERS[step](a)
    except Failed as e:
        a.write()
        print(f"    FAILED: {e}", file=sys.stderr)
        return 1
    a.write()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
