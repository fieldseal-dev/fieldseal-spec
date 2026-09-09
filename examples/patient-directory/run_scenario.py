#!/usr/bin/env python3
"""Run the seven acts, each as its own process, and print the narration.

    python run_scenario.py                # run, print, write transcript/
    python run_scenario.py --check        # ... and diff against the golden file
    python run_scenario.py --write-expected

**Why a runner and not one program.** The demo's claim is about bytes in a
shared database, so the database has to be the only channel between the two
stacks. A single process holding both an ORM session and a Prisma client
could pass a value from one to the other without either of them noticing,
and the demo would then be asserting something about its own memory. Each
step below is a separate invocation of a separate runtime; the only thing
they share is Postgres.

The order matters and is not a preference: act 2 reads what act 1 wrote.

**`--check` compares the whole narration against `expected-narration.txt`,**
in the shape of `vectors-reproducible` and `tools/ucd-gen/generate.py
--check`. That is only meaningful because the narration is deterministic --
row ids are passed explicitly, envelope *lengths* are a function of plaintext
length, blind index values are a function of the key and the value, and the
19-byte envelope header is fixed by the suite and the key id. Nothing random
is printed. If a change makes the narration legitimately different, run
`--write-expected` and commit the diff; the diff is the review artifact.
"""

from __future__ import annotations

import argparse
import difflib
import os
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
DJANGO_DIR = HERE / "django"
PRISMA_DIR = HERE / "prisma"
TRANSCRIPT = HERE / "transcript"
EXPECTED = HERE / "expected-narration.txt"

#: (stack, step). `reset` empties the table; every other entry is an act or
#: half of one, and each writes one transcript file.
STEPS: list[tuple[str, str]] = [
    ("django", "reset"),
    ("django", "write"),           # act 1
    ("prisma", "read"),            # act 2
    ("prisma", "search"),          # act 3
    ("prisma", "write"),           # act 4
    ("django", "read-search"),     # act 4
    ("django", "write-shared"),    # act 5
    ("prisma", "write-shared"),    # act 5
    ("django", "compare-writers"),  # act 5
    ("django", "refusals"),        # act 6
    ("prisma", "refusals"),        # act 6
    ("django", "raw-sql"),         # act 7
]


def command(stack: str, step: str) -> tuple[list[str], pathlib.Path, dict[str, str]]:
    env = dict(os.environ)
    env.setdefault(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/fieldseal_demo"
    )
    if stack == "django":
        env["DJANGO_SETTINGS_MODULE"] = "settings"
        # The refusal messages this narrates contain '§'. On a console whose
        # default encoding is not UTF-8 they would raise UnicodeEncodeError
        # in the child rather than print, so the encoding is stated rather
        # than inherited.
        env["PYTHONIOENCODING"] = "utf-8"
        return [sys.executable, "-m", "directory.scenario", step], DJANGO_DIR, env
    node = shutil.which("node") or "node"
    return (
        [node, "--no-warnings=ExperimentalWarning", "scenario.ts", step],
        PRISMA_DIR,
        env,
    )


#: Seconds any one step may take. The whole run is about ten on a laptop, and
#: CI's slowest step is under a minute, so this is not a performance budget --
#: it is the local counterpart of the job's `timeout-minutes`. Without it a
#: step wedged on a database lock hangs an interactive run with no output at
#: all, because stdout is captured rather than streamed.
STEP_TIMEOUT = 300


def run() -> tuple[str, int]:
    if TRANSCRIPT.exists():
        shutil.rmtree(TRANSCRIPT)
    TRANSCRIPT.mkdir(parents=True)

    out: list[str] = []
    for stack, step in STEPS:
        argv, cwd, env = command(stack, step)
        try:
            proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                                  timeout=STEP_TIMEOUT)
        except subprocess.TimeoutExpired:
            sys.stderr.write(
                f"\nrun_scenario: {stack} {step} did not finish within "
                f"{STEP_TIMEOUT}s and was killed. The likeliest cause is a "
                f"database lock held by an earlier step, or a Node process "
                f"holding pg sockets open after its work is done.\n"
            )
            return "".join(out), 1
        # Captured as bytes and normalized here rather than read as text: a
        # Python child on Windows writes CRLF, a Node child and every Linux
        # child write LF, and `expected-narration.txt` is one file compared on
        # both. The repository's .gitattributes keeps it LF on disk; this
        # keeps the run that is compared against it LF too.
        text = proc.stdout.decode("utf-8").replace("\r\n", "\n")
        sys.stdout.write(text)
        sys.stdout.flush()
        out.append(text)
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr.decode("utf-8"))
            sys.stderr.write(
                f"\nrun_scenario: {stack} {step} exited {proc.returncode}. The "
                f"acts are ordered and each one reads what the last one wrote, "
                f"so the run stops here.\n"
            )
            return "".join(out), proc.returncode
    return "".join(out), 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="run_scenario.py")
    ap.add_argument(
        "--check",
        action="store_true",
        help="diff the narration against expected-narration.txt",
    )
    ap.add_argument(
        "--write-expected",
        action="store_true",
        help="rewrite expected-narration.txt from this run",
    )
    args = ap.parse_args()

    narration, code = run()
    if code != 0:
        return code

    if args.write_expected:
        EXPECTED.write_text(narration, "utf-8", newline="\n")
        print(f"run_scenario: wrote {EXPECTED.name} "
              f"({len(narration.splitlines())} lines)")
        return 0

    if args.check:
        if not EXPECTED.exists():
            print(f"run_scenario: {EXPECTED.name} does not exist; run "
                  f"--write-expected first", file=sys.stderr)
            return 1
        want = EXPECTED.read_text("utf-8")
        if want != narration:
            diff = difflib.unified_diff(
                want.splitlines(True),
                narration.splitlines(True),
                fromfile=EXPECTED.name,
                tofile="this run",
            )
            sys.stderr.write("\nrun_scenario: the narration changed.\n\n")
            sys.stderr.writelines(diff)
            sys.stderr.write(
                "\nIf the change is intended, `--write-expected` and commit "
                "the diff.\nIf it is not, something in the two stacks stopped "
                "agreeing.\n"
            )
            return 1
        print(f"run_scenario: narration matches {EXPECTED.name} "
              f"({len(narration.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
