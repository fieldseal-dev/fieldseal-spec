#!/usr/bin/env python3
"""Assert the shape of a whole scenario run.

    python check_transcript.py transcript/

**Why this is separate from the acts.** Each act asserts its own claims and
exits non-zero if one fails, so a green run already means every assertion
held. What an act cannot check is whether it *ran*: a step that is skipped,
renamed, or quietly dropped from the runner leaves no failure behind, and a
scenario that silently shrinks to three acts still exits 0. This reads the
whole directory and refuses a run that is missing a step, out of order, or
carrying fewer assertions than the act is supposed to make.

It also asserts the two facts no single act is the right place for:

- **Both directions are covered.** Act 2 is Prisma reading Django's row and
  act 4 is Django reading Prisma's. A demo that lost one of them would still
  look like a cross-language proof.
- **Every Prisma act recorded the development-only key-provider warning.**
  The core emits it because `StaticKeyProvider` is a test facility (spec §8),
  and this turns "the demo is not a production configuration" into a checked
  fact rather than a sentence in a README that can be deleted.
"""

from __future__ import annotations

import json
import pathlib
import sys

#: file stem -> (act, stack, minimum assertions, claim substrings that must
#: appear in that step). The substrings are load-bearing rather than
#: decorative: each names the specific thing the act exists to prove, so an
#: act rewritten into a weaker one fails here instead of passing quietly.
EXPECTED: dict[str, tuple[int, str, int, tuple[str, ...]]] = {
    "01-django-write": (
        1, "django", 4,
        ("the plaintext is not a substring of the stored column",
         "the blind index is ceil(15/8) = 2 bytes"),
    ),
    "02-prisma-read": (
        2, "prisma", 4,
        ("Prisma decrypts a row Django wrote",),
    ),
    "03-prisma-search": (
        3, "prisma", 1,
        ("the blind index Python derived is derivable by TypeScript",),
    ),
    "04-prisma-write": (
        4, "prisma", 3,
        ("the plaintext is not a substring of the stored column",),
    ),
    "05-django-read-search": (
        4, "django", 4,
        ("Django decrypts a row Prisma wrote",
         "a lookup Python derived finds a row TypeScript indexed"),
    ),
    "06-django-write-shared": (5, "django", 1, ()),
    "07-prisma-write-shared": (5, "prisma", 1, ()),
    "08-django-compare-writers": (
        5, "django", 4,
        ("the two writers produced the same 19-byte header",
         "the two envelopes differ",
         "the two blind indexes are byte-equal"),
    ),
    "09-django-refusals": (
        6, "django", 2,
        ("Django serves count() over an indexed encrypted column",
         "an exclusion over an encrypted column is refused"),
    ),
    "10-prisma-refusals": (
        6, "prisma", 2,
        ("count() over an encrypted column is refused",
         "negation over an encrypted column is refused"),
    ),
    "11-django-raw-sql": (
        7, "django", 3,
        ("no plaintext this scenario wrote appears anywhere",),
    ),
}

#: Spec §8: `StaticKeyProvider` is a development facility, and the core says
#: so through `onWarning` on every client it builds.
DEV_WARNING = "static-key-provider"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python check_transcript.py <transcript-dir>",
              file=sys.stderr)
        return 2
    root = pathlib.Path(argv[1])
    if not root.is_dir():
        print(f"check_transcript: {root} is not a directory. Run "
              f"`python run_scenario.py` first.", file=sys.stderr)
        return 1

    found = sorted(p.stem for p in root.glob("*.json"))
    problems: list[str] = []

    missing = [s for s in EXPECTED if s not in found]
    extra = [s for s in found if s not in EXPECTED]
    if missing:
        problems.append(
            "steps that did not run: " + ", ".join(sorted(missing))
            + ". Every act reads what the last one wrote, so a missing step "
            "means the acts after it proved less than they claim."
        )
    if extra:
        problems.append(
            "transcript files this checker does not know: "
            + ", ".join(extra)
            + ". A new act needs a row in EXPECTED, or it is asserting "
            "nothing that survives review."
        )

    acts_seen: set[int] = set()
    assertions = 0
    for stem in sorted(set(found) & set(EXPECTED)):
        act, stack, minimum, required = EXPECTED[stem]
        # Guarded: this file promises a FAILED diagnostic, and a truncated or
        # hand-edited transcript would otherwise hand back a traceback
        # instead -- which is the shape of failure it exists to replace.
        try:
            rec = json.loads((root / f"{stem}.json").read_text("utf-8"))
            act_no, stack_name = rec["act"], rec["stack"]
            assertions_in = rec["assertions"]
            warnings_in = rec["warnings"]
        except (OSError, ValueError, KeyError, TypeError) as e:
            problems.append(
                f"{stem}: could not be read as a transcript entry "
                f"({type(e).__name__}: {e}). An act writes this file as its "
                f"last action, so a malformed one means the act died "
                f"mid-write or the file was edited."
            )
            continue
        rec = {"act": act_no, "stack": stack_name,
               "assertions": assertions_in, "warnings": warnings_in}
        acts_seen.add(rec["act"])

        if rec["act"] != act or rec["stack"] != stack:
            problems.append(
                f"{stem}: recorded as act {rec['act']} on {rec['stack']}, "
                f"expected act {act} on {stack}"
            )
        claims = [a["claim"] for a in rec["assertions"]]
        assertions += len(claims)
        for a in rec["assertions"]:
            if not a["ok"]:
                problems.append(f"{stem}: assertion failed -- {a['claim']} "
                                f"({a['detail']})")
        if len(claims) < minimum:
            problems.append(
                f"{stem}: {len(claims)} assertion(s), expected at least "
                f"{minimum}. An act that stops asserting still prints."
            )
        for needle in required:
            if not any(needle in c for c in claims):
                problems.append(
                    f"{stem}: no assertion covering {needle!r}. That is the "
                    f"claim this act exists to make."
                )
        if stack == "prisma" and not any(
            w["kind"] == DEV_WARNING for w in rec["warnings"]
        ):
            problems.append(
                f"{stem}: the core's `{DEV_WARNING}` warning was not "
                f"recorded. Either the demo stopped using StaticKeyProvider "
                f"-- which would mean it is carrying a real key -- or the "
                f"warning stopped being emitted."
            )

    for act in range(1, 8):
        if act not in acts_seen:
            problems.append(f"act {act} is absent from the run")

    if problems:
        print("check_transcript: FAILED\n", file=sys.stderr)
        for p in problems:
            print(f"- {p}\n", file=sys.stderr)
        return 1

    print(f"check_transcript: {len(EXPECTED)} step(s), acts 1-7 all present, "
          f"{assertions} assertions, all holding.")
    print("  Both directions covered: act 2 is Prisma reading Django's row, "
          "act 4 is\n  Django reading Prisma's.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
