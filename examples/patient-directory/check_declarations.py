#!/usr/bin/env python3
"""The identifier tripwire: do the two stacks declare the same column?

    python check_declarations.py

**Why this exists.** The failure it prevents has no error message worth
reading. A `column_uuid` that differs between the two declarations produces
`COMMITMENT_INVALID` on read -- a decrypt-side error for a write-side
configuration mistake, raised arbitrarily far from the cause. An *index*
declaration that differs is worse: it raises nothing at all. The row is
stored, it is decryptable, and it simply stops being findable by the other
stack. Spec §7.8 calls a changed `idf`, `normalize` or `truncate_bits` a NEW
index requiring a backfill; two stacks that never agreed on one are that
situation from the first row.

**Joined on `column_uuid`, because spec §6.1 makes it the column's immutable
identity.** The join key is the identity; everything else is a comparison.

| Divergence | What it would cause |
|---|---|
| same `column_uuid`, different `table_uuid` | undecryptable rows |
| same `column_uuid`, different index declaration | silent lookup miss |
| `column_uuid` on one side only | one stack cannot see a column the other writes |
| same `column_uuid`, different `(table, column)` | two stacks at different columns |

That last row is why the Prisma schema declares no `@map`/`@@map`: with no
mapping there, `(model, field)` **is** `(table, column)`, so the physical-name
half is closed by the same comparison, without parsing the `.prisma` file.

**Both sides are resolved rather than as-written.** Prisma's side is the field
map its generator emitted at `prisma generate`; Django's is a runtime dump
through the adapter's own accessors (`directory/dump_declarations.py`). An
`ast` parse of `models.py` would be the mistake `checks.py` E006 names:
comparing as-declared inputs lets two declarations that agree textually and
differ operationally register as a match.

**What this is not.** It is a *diagnostic*, not the proof. Declaring the same
UUID does not prove either stack uses it -- the scenario proves that, by
moving bytes through the database. This exists so that a drift fails with a
message naming the drifted parameter, instead of surfacing as
`COMMITMENT_INVALID` forty lines into the narration.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
DJANGO_DIR = HERE / "django"
FIELD_MAP = HERE / "prisma" / "generated" / "fieldseal-map.ts"

#: The generator version this checker understands. Bumping the field map is a
#: change in what a declaration *means*, so it is refused rather than read
#: optimistically -- a half-understood map is a column quietly treated as
#: plaintext.
EXPECTED_MAP_VERSION = 2

#: The logical types this demo's shared model is allowed to use.
#:
#: The others are excluded because they do not survive a trip between these
#: two adapters. Measured 2026-09-08 and 2026-09-09 through each adapter's
#: real codec, and the three failures are in three different classes:
#:
#:  - **`date` is silent going in and fatal coming back.** Django writes
#:    `b"2026-09-08"`; Prisma reads it *successfully*, as an instant at UTC
#:    midnight (there is no `as: "date"`, only `datetime`), and re-writing
#:    that value -- an ordinary read-modify-write -- stores
#:    `b"2026-09-08T00:00:00.000Z"`, which Django then refuses. One write
#:    through the other stack makes the row permanently unreadable here, with
#:    nothing raised when the damage is done. Rendered in local time west of
#:    UTC, that instant is also the previous day.
#:  - **`Decimal` has no declaration to reach for**, so it becomes
#:    `as: "float"`, an IEEE-754 double: `b"12345678901234567.89"` comes back
#:    as `12345678901234568` and re-writes as that. Silent, both directions.
#:  - **`boolean` is the loud one.** `b"True"` against `b"true"`, each side
#:    refusing the other rather than coercing -- which is correct behaviour,
#:    and why this is the least dangerous of the three.
#:
#: `datetime` proper does round-trip, but only because V8 accepts Django's
#: `"2026-09-08 12:00:00+00:00"`, and a non-ISO-8601 string is
#: implementation-defined in ECMA-262 §21.4.3.2 -- so that direction rests on
#: a behaviour no standard requires.
#:
#: The root cause is a specification gap, not an adapter bug: spec §3 pins the
#: byte layer -- envelope, AAD, commitment -- and nothing anywhere pins the
#: logical-type-to-bytes rendering, nor even the vocabulary of logical types,
#: which has no entry for a decimal. Both adapters are conformant and they
#: disagree. Which rendering is correct is a normative question (G25), so it
#: is not settled here; this demo stays inside the types where the two agree,
#: and fails the build rather than leaving that as a comment somebody deletes.
PORTABLE_LOGICAL_TYPES = ("string", "int", "bytes")


def _fail(message: str) -> None:
    sys.stdout.flush()
    print(f"\ncheck_declarations: FAILED\n\n{message}", file=sys.stderr)
    raise SystemExit(1)


def _uuid_key(value: str) -> str:
    """A UUID's identity, however it was written."""
    return value.replace("-", "").lower()


def _hyphenate(key: str) -> str:
    return "-".join([key[:8], key[8:12], key[12:16], key[16:20], key[20:]])


# -- the two sides ---------------------------------------------------------


def load_prisma() -> dict[str, Any]:
    """The generated field map, as JSON.

    `renderModule()` quotes every key and value with `JSON.stringify`, so the
    object literal in that TypeScript file is valid JSON and needs no parser
    of its own. Nothing here evaluates the file.
    """
    if not FIELD_MAP.exists():
        _fail(
            f"{FIELD_MAP} does not exist. Run `npx prisma generate` in "
            f"`prisma/` first -- the field map is the Prisma side of this "
            f"comparison, and it is a build product, not a committed file."
        )
    text = FIELD_MAP.read_text("utf-8")
    marker = "export const fieldsealFieldMap"
    try:
        start = text.index("{", text.index(marker))
        end = text.rindex("}") + 1
    except ValueError:
        _fail(
            f"{FIELD_MAP} does not contain a `{marker}` object literal. The "
            f"generator's output shape changed; this checker reads it as JSON."
        )
    raw = json.loads(text[start:end])
    if raw.get("version") != EXPECTED_MAP_VERSION:
        _fail(
            f"field map version is {raw.get('version')!r}, and this checker "
            f"understands {EXPECTED_MAP_VERSION}. A map emitted by a "
            f"different generator version says something different about what "
            f"a declaration means; reading it optimistically is how a column "
            f"gets quietly treated as plaintext."
        )

    columns: dict[str, Any] = {}
    for model in raw["models"]:
        indexes = {i["source"]: i for i in model["indexes"]}
        for enc in model["encrypted"]:
            idx = indexes.get(enc["field"])
            columns[_uuid_key(enc["columnUuid"])] = {
                "table_uuid": _uuid_key(model["tableUuid"] or ""),
                "model": model["model"],
                # No `@map`/`@@map` in this schema, so the model and field
                # names ARE the physical names. That is a property of the
                # schema, asserted below rather than assumed here.
                "table": model["model"],
                "field": enc["field"],
                "column": enc["field"],
                "logical_type": enc["valueType"],
                "storage": enc["storage"],
                "tenant_bound": enc["tenantBound"],
                "index": None
                if idx is None
                else {
                    "index_id": idx["indexId"],
                    "idf": idx["idf"],
                    "normalize": idx["normalize"],
                    "truncate_bits": idx["truncateBits"],
                    "projected_population": idx["projectedPopulation"],
                    "on_unindexable": idx["onUnindexable"],
                    "skewed": idx["skewed"],
                    "argon2": idx.get("argon2"),
                    "sibling_column": idx["field"],
                },
            }
    return {"generator": raw["generator"], "columns": columns}


def load_django() -> dict[str, Any]:
    """Django's resolved view, dumped by a Django process.

    A subprocess rather than an import: this checker never sets up Django, so
    it cannot accidentally resolve anything itself, and the dump is produced
    by the same runtime accessors the adapter uses to encrypt.
    """
    env = dict(os.environ)
    env.setdefault("DJANGO_SETTINGS_MODULE", "settings")
    proc = subprocess.run(
        [sys.executable, "-m", "directory.dump_declarations"],
        cwd=DJANGO_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        _fail(
            "the Django declaration dump failed:\n\n"
            + (proc.stderr.strip() or "(no output)")
        )
    raw = json.loads(proc.stdout)
    return {
        "resolved_by": raw["resolved_by"],
        "columns": {_uuid_key(k): v for k, v in raw["columns"].items()},
    }


# -- the comparison --------------------------------------------------------

#: Compared field by field, with what a divergence would cause. The message is
#: the point: a mismatch has to name the parameter and its consequence, not
#: report that two dictionaries differ.
COMPARED = {
    "table_uuid": (
        "the two stacks would derive different record keys for this column, "
        "so rows written by one are undecryptable by the other "
        "(COMMITMENT_INVALID, spec §6.3)"
    ),
    "table": (
        "the two stacks are pointed at different tables while claiming one "
        "column identity"
    ),
    "column": (
        "the two stacks are pointed at different columns while claiming one "
        "column identity"
    ),
    "logical_type": (
        "the two stacks would encrypt different bytes for the same value, so "
        "a read from the other side decrypts successfully and returns the "
        "wrong thing -- or refuses"
    ),
    "storage": (
        "one stack writes raw envelope bytes and the other base64 ASCII into "
        "the same column; the reader fails at the length gate, pointing at "
        "the envelope rather than at the column"
    ),
    "tenant_bound": (
        "one stack binds the tenant into the derived key and the other does "
        "not, so every row one writes is undecryptable by the other"
    ),
}

#: Deliberately NOT compared, each for a reason worth stating.
#:
#: - `noun` (Prisma) / `unindexable_noun` (Django): what to call the value in
#:   a user-facing refusal (docs/12 §10.2). It shapes a sentence, not a byte.
#: - nullability: a property of the physical column, which the two stacks
#:   share by construction. `check_schema_shape.py` compares it against the
#:   database, where there is one answer rather than two declarations.
#: - `prismaType`: the storage type, already implied by `storage`.
NOT_COMPARED = ("noun", "nullable", "prismaType")

INDEX_CONSEQUENCE = (
    "the blind indexes derived by the two stacks differ, so a lookup written "
    "by one silently misses rows written by the other. Nothing raises: the "
    "row is stored, it is decryptable, and it is simply not found. Spec §7.8 "
    "makes a changed `{param}` a NEW index requiring a full backfill."
)


def compare(django: dict[str, Any], prisma: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    dj, pr = django["columns"], prisma["columns"]

    for key in sorted(set(dj) - set(pr)):
        c = dj[key]
        problems.append(
            f"{_hyphenate(key)}: declared by Django only "
            f"({c['model']}.{c['field']}). Prisma cannot see a column Django "
            f"writes: a read through it returns the raw envelope bytes and a "
            f"filter on it goes unexamined."
        )
    for key in sorted(set(pr) - set(dj)):
        c = pr[key]
        problems.append(
            f"{_hyphenate(key)}: declared by Prisma only "
            f"({c['model']}.{c['field']}). Django cannot see a column Prisma "
            f"writes: it is not an `Encrypted` field, so nothing decrypts it."
        )

    for key in sorted(set(dj) & set(pr)):
        d, p = dj[key], pr[key]
        label = f"{_hyphenate(key)} ({d['model']}.{d['field']})"

        if d["logical_type"] not in PORTABLE_LOGICAL_TYPES:
            problems.append(
                f"{label}: Django declares an inner type whose logical type is "
                f"{d['logical_type']!r} ({d['declared_type']}). This demo's "
                f"model is restricted to {', '.join(PORTABLE_LOGICAL_TYPES)}, "
                f"because the two adapters render the others differently -- "
                f"`boolean` is `b\"True\"` on one side and `b\"true\"` on the "
                f"other, and each refuses the other's -- and nothing normative "
                f"pins which is right. See this file's PORTABLE_LOGICAL_TYPES."
            )
        if p["logical_type"] not in PORTABLE_LOGICAL_TYPES:
            problems.append(
                f"{label}: Prisma declares `as: \"{p['logical_type']}\"`, which "
                f"is outside {', '.join(PORTABLE_LOGICAL_TYPES)} for the same "
                f"reason."
            )

        for what, consequence in COMPARED.items():
            if d[what] != p[what]:
                problems.append(
                    f"{label}: {what} differs -- Django {d[what]!r}, Prisma "
                    f"{p[what]!r}. Consequence: {consequence}."
                )

        di, pi = d["index"], p["index"]
        if (di is None) != (pi is None):
            has, lacks = ("Django", "Prisma") if pi is None else ("Prisma", "Django")
            problems.append(
                f"{label}: {has} declares a blind index and {lacks} does not. "
                f"{lacks} cannot serve an equality on this column at all, and "
                f"if it writes rows they carry no index value -- so they are "
                f"invisible to the other stack's lookups while being perfectly "
                f"readable. Nothing raises."
            )
        elif di is not None and pi is not None:
            for param in sorted(set(di) | set(pi)):
                if di.get(param) != pi.get(param):
                    problems.append(
                        f"{label}: index {param} differs -- Django "
                        f"{di.get(param)!r}, Prisma {pi.get(param)!r}. "
                        f"Consequence: "
                        + INDEX_CONSEQUENCE.format(param=param)
                    )
    return problems


def report(django: dict[str, Any], prisma: dict[str, Any]) -> None:
    print("fieldseal patient-directory demo -- declaration check")
    print()
    print(f"  Prisma  {FIELD_MAP.relative_to(HERE).as_posix()}")
    print(f"          emitted by {prisma['generator']}")
    print("  Django  directory.models, resolved through")
    print(f"          {django['resolved_by']}")
    print()
    for key in sorted(django["columns"]):
        d = django["columns"][key]
        print(f"  {_hyphenate(key)}")
        print(
            f"      {d['model']}.{d['field']}  ->  "
            f"\"{d['table']}\".\"{d['column']}\"   "
            f"{d['logical_type']}, {d['storage']}"
        )
        idx = d["index"]
        if idx is None:
            print("      no blind index: equality on this column is refused")
        else:
            print(
                f"      index {idx['index_id']}: {idx['idf']} / "
                f"{idx['normalize']} / {idx['truncate_bits']} bits / "
                f"P={idx['projected_population']}  ->  "
                f"\"{idx['sibling_column']}\""
            )
    print()


def main() -> int:
    prisma = load_prisma()
    django = load_django()
    problems = compare(django, prisma)
    report(django, prisma)

    if problems:
        _fail("\n\n".join(f"- {p}" for p in problems))

    columns = len(django["columns"])
    indexes = sum(1 for c in django["columns"].values() if c["index"] is not None)
    print(
        f"  {columns} encrypted column(s), {indexes} blind index(es): the two "
        f"stacks agree on every compared field."
    )
    print(
        "  Not compared, deliberately: "
        + ", ".join(NOT_COMPARED)
        + " -- see NOT_COMPARED."
    )
    print()
    print(
        "  This is a diagnostic, not the proof. Declaring the same UUID does "
        "not\n  prove either stack uses it -- run the scenario for that."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
