#!/usr/bin/env python3
"""
Copy ../docs/*.md into www/content/docs/ with Hugo front matter derived from
each file's H1 and numeric prefix.

The files in docs/ are the canonical source and are never modified. Everything
under www/content/docs/ is generated and git-ignored -- do not hand-edit it.

Usage:  python www/scripts/sync-docs.py
"""
import pathlib, re, shutil, sys

HERE = pathlib.Path(__file__).resolve().parent
WWW = HERE.parent
REPO = WWW.parent
SRC = REPO / "docs"
DEST = WWW / "content" / "docs"

SECTION_INDEX = """---
title: "Documents"
description: "The working drafts behind the Fieldseal specification."
---

These are the working documents. They are drafts: they change, and they are
numbered in reading order rather than importance.
"""


def main() -> int:
    if not SRC.is_dir():
        print(f"error: {SRC} not found", file=sys.stderr)
        return 1

    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True)
    (DEST / "_index.md").write_text(SECTION_INDEX, encoding="utf-8")

    count = 0
    for src in sorted(SRC.glob("*.md")):
        text = src.read_text(encoding="utf-8")
        lines = text.splitlines()

        # Title = first H1; fall back to the filename.
        title, body_start = src.stem, 0
        for i, line in enumerate(lines):
            if line.startswith("# "):
                title = line[2:].strip()
                body_start = i + 1
                break

        stem = src.stem                       # e.g. "02-spec-v0.1"
        prefix, _, rest = stem.partition("-")  # "02", "spec-v0.1"
        weight = int(prefix) + 1 if prefix.isdigit() else 999
        slug = rest or stem

        front = (
            "---\n"
            f'title: "{title.replace(chr(34), chr(92) + chr(34))}"\n'
            f"weight: {weight}\n"
            f'slug: "{slug}"\n'
            f'sourceFile: "docs/{src.name}"\n'
            "---\n\n"
        )
        body = "\n".join(lines[body_start:]).lstrip("\n")
        (DEST / src.name).write_text(front + body + "\n", encoding="utf-8")
        print(f"  {src.name}  ->  content/docs/{src.name}  ({title})")
        count += 1

    print(f"synced {count} document(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
