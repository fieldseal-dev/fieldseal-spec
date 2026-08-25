#!/usr/bin/env python3
"""
Copy the canonical documents into www/content/docs/ with Hugo front matter, and
rewrite their relative links into site URLs.

Three trees are published:

    docs/*.md              ->  /docs/<slug>/
    docs/adr/*.md          ->  /docs/adr/<slug>/       (README.md -> /docs/adr/)
    docs/issues/*.md       ->  /docs/issues/<slug>/    (README.md -> /docs/issues/)

The files in docs/ are the canonical source and are never modified. Everything
under www/content/docs/ is generated and git-ignored -- do not hand-edit it.

Why the link rewrite exists. The sources are read in two places, and a link that
is correct in one is wrong in the other. On GitHub, `16-reviewer-brief.md#q2`
resolves next to the file it sits in and works. On the site that document is
served at /docs/reviewer-brief/, so a browser resolves the same href against the
*current page* -- /docs/spec-v0.1/16-reviewer-brief.md -- and 404s. Rather than
bend the sources toward the site (and break GitHub), the translation happens
here, once, at sync time. A relative link whose target cannot be resolved is a
hard error: this script is also the build's guard against a link that points at
nothing. Targets inside the repository but outside the published trees resolve
to GitHub, which is the only place they exist.

Usage:  python www/scripts/sync-docs.py
"""
import pathlib, re, shutil, sys

HERE = pathlib.Path(__file__).resolve().parent
WWW = HERE.parent
REPO = WWW.parent
SRC = REPO / "docs"
DEST = WWW / "content" / "docs"

REPO_URL = "https://github.com/fieldseal-dev/fieldseal-spec"
BRANCH = "main"

# Sub-sections of docs/ that are published, in nav order after the numbered
# documents. The weight is the base; pages inside get base + 1, base + 2, ...
SUBSECTIONS = {
    "adr": 100,
    "issues": 200,
}

SECTION_INDEX = """---
title: "Documents"
description: "The working drafts behind the Fieldseal specification."
---

These are the working documents. They are drafts: they change, and they are
numbered in reading order rather than importance.
"""

# [text](target) and [text](target "title"), including the ![image] form. The
# text may contain one level of nested brackets, which several tables do.
LINK = re.compile(r'(\[(?:[^\]\[]|\[[^\]]*\])*\]\()([^)\s]+)((?:\s+"[^"]*")?\))')
FENCE = re.compile(r"^\s*(```|~~~)")


def adr_order(stem: str) -> tuple:
    """0001 before its Appendix A, template last."""
    num = stem.split("-")[0]
    if num == "0000":
        return ("9999", "0", stem)
    return (num, "1" if "appendix" in stem else "0", stem)


def title_of(text: str) -> tuple:
    """First H1 and the offset just past it."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("# "):
            return line[2:].strip(), i + 1
    return None, 0


def nav_title(title: str) -> str:
    """A sidebar-length name for an ADR or gap draft.

    Their H1s are full sentences -- "G2 - §7.3: The Argon2id index-derivation
    invocation is incompletely specified" -- which is right on the page and far
    too long in a nav column. Take the identifier off the front: everything
    before the first em dash, widened to the first colon when that leaves only
    a bare "G2".
    """
    dash = title.find("—")
    colon = title.find(":")
    head = title[:dash].strip() if dash > 0 else title
    if len(head) <= 4 and 0 < colon:
        head = title[:colon].strip()
    elif dash <= 0 and 0 < colon:
        head = title[:colon].strip()
    return head or title


def build_plan():
    """Every published file, in one pass, so links can be resolved against it.

    Returns (pages, urls): pages is the work list, urls maps a repo-relative
    POSIX path to the site URL it will be served at.
    """
    pages, urls = [], {}

    for src in sorted(SRC.glob("*.md")):
        prefix, _, rest = src.stem.partition("-")
        slug = rest or src.stem
        pages.append({
            "src": src,
            "out": DEST / src.name,
            "url": f"/docs/{slug}/",
            "slug": slug,
            "weight": int(prefix) + 1 if prefix.isdigit() else 999,
        })

    for name, base in SUBSECTIONS.items():
        d = SRC / name
        if not d.is_dir():
            print(f"error: {d} not found", file=sys.stderr)
            raise SystemExit(1)
        readme = d / "README.md"
        if not readme.is_file():
            print(f"error: {readme} not found", file=sys.stderr)
            raise SystemExit(1)
        pages.append({
            "src": readme,
            "out": DEST / name / "_index.md",
            "url": f"/docs/{name}/",
            "slug": None,                    # a section index has no slug
            "weight": base,
            "shorten": False,
        })
        others = sorted((p for p in d.glob("*.md") if p.name != "README.md"),
                        key=lambda p: adr_order(p.stem) if name == "adr" else p.stem)
        for i, src in enumerate(others, start=1):
            slug = src.stem.lower()
            pages.append({
                "src": src,
                "out": DEST / name / src.name,
                "url": f"/docs/{name}/{slug}/",
                "slug": slug,
                "weight": base + i,
                "shorten": True,
            })

    for p in pages:
        urls[p["src"].relative_to(REPO).as_posix()] = p["url"]
    return pages, urls


def rewrite_links(text: str, src: pathlib.Path, urls: dict, errors: list) -> str:
    """Translate relative link targets into site URLs, skipping code fences."""
    out, in_fence, fence_marker = [], False, ""

    for lineno, line in enumerate(text.splitlines(), start=1):
        m = FENCE.match(line)
        if m:
            if not in_fence:
                in_fence, fence_marker = True, m.group(1)
            elif line.strip().startswith(fence_marker):
                in_fence, fence_marker = False, ""
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue

        def repl(m):
            head, target, tail = m.group(1), m.group(2), m.group(3)
            if target.startswith(("http://", "https://", "mailto:", "#", "/")):
                return m.group(0)
            path, sep, frag = target.partition("#")
            if not path:
                return m.group(0)
            resolved = (src.parent / path).resolve()
            try:
                rel = resolved.relative_to(REPO).as_posix()
            except ValueError:
                errors.append(f"{src.relative_to(REPO)}:{lineno}: link escapes "
                              f"the repository: {target}")
                return m.group(0)
            if rel in urls:
                return head + urls[rel] + sep + frag + tail
            if resolved.is_dir():
                return f"{head}{REPO_URL}/tree/{BRANCH}/{rel}{tail}"
            if resolved.is_file():
                return f"{head}{REPO_URL}/blob/{BRANCH}/{rel}{sep}{frag}{tail}"
            errors.append(f"{src.relative_to(REPO)}:{lineno}: link target does "
                          f"not exist: {target}")
            return m.group(0)

        out.append(LINK.sub(repl, line))

    return "\n".join(out)


def main() -> int:
    if not SRC.is_dir():
        print(f"error: {SRC} not found", file=sys.stderr)
        return 1

    pages, urls = build_plan()

    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True)
    (DEST / "_index.md").write_text(SECTION_INDEX, encoding="utf-8")

    errors = []
    for page in pages:
        src = page["src"]
        text = src.read_text(encoding="utf-8")
        title, body_start = title_of(text)
        if title is None:
            errors.append(f"{src.relative_to(REPO)}: no H1 to use as a title")
            title = src.stem

        def yaml(s):
            return s.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))

        front = ["---", f'title: "{yaml(title)}"', f"weight: {page['weight']}"]
        if page.get("shorten"):
            front.append(f'linkTitle: "{yaml(nav_title(title))}"')
        if page["slug"]:
            front.append(f'slug: "{page["slug"]}"')
        front += [f'sourceFile: "{src.relative_to(REPO).as_posix()}"', "---", "", ""]

        body = "\n".join(text.splitlines()[body_start:]).lstrip("\n")
        body = rewrite_links(body, src, urls, errors)

        page["out"].parent.mkdir(parents=True, exist_ok=True)
        page["out"].write_text("\n".join(front) + body + "\n", encoding="utf-8")
        rel_out = page["out"].relative_to(WWW).as_posix()
        print(f"  {src.relative_to(REPO).as_posix()}  ->  {rel_out}  ({page['url']})")

    if errors:
        print(f"\n{len(errors)} unresolvable link(s):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    print(f"synced {len(pages)} document(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
