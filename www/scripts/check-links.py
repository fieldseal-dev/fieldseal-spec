#!/usr/bin/env python3
"""
Check every internal link in the built site, and fail the build on a broken one.

This runs against www/public after `hugo`, so it sees what a reader sees: the
resolved href, the page it lands on, and the anchors that page actually has.
That is the only place the two failure modes are both visible --

  * a link to a page that is not built (a relative `.md` href that reached the
    HTML unrewritten, or a document that was never synced), and
  * a link to a real page with an anchor that does not exist on it (a heading
    renamed, or an id assumed rather than checked).

Only same-site links are checked. Third parties are deliberately out of scope:
they 403 CI runners on bot suspicion (dfs.ny.gov, media.defense.gov) and go
down for reasons that have nothing to do with this repository, and a deploy
that fails for either is a deploy that gets ignored. Check those by hand.

Usage:  python www/scripts/check-links.py [public_dir]
"""
import html, pathlib, re, sys, urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_PUBLIC = HERE.parent / "public"

SITE_HOSTS = {"fieldseal.dev", "www.fieldseal.dev"}
SKIP_SCHEMES = ("mailto:", "javascript:", "data:", "tel:")

HREF = re.compile(r'href=(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', re.I)
ID = re.compile(r'\bid=(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', re.I)
NAME_ANCHOR = re.compile(r'<a\b[^>]*\bname=(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', re.I)


def group(m):
    return m.group(1) or m.group(2) or m.group(3) or ""


def main(argv) -> int:
    public = pathlib.Path(argv[1]).resolve() if len(argv) > 1 else DEFAULT_PUBLIC
    if not public.is_dir():
        print(f"error: {public} not found -- run hugo first", file=sys.stderr)
        return 1

    # url path -> set of anchor ids, for every built page
    anchors, files = {}, {}
    for f in public.rglob("*"):
        if not f.is_file():
            continue
        rel = f.relative_to(public).as_posix()
        files["/" + rel] = f
        if f.suffix != ".html":
            continue
        body = f.read_text(encoding="utf-8", errors="replace")
        ids = {group(m) for m in ID.finditer(body)}
        ids |= {group(m) for m in NAME_ANCHOR.finditer(body)}
        url = "/" + rel
        anchors[url] = ids
        if rel.endswith("index.html"):                      # /docs/spec-v0.1/
            anchors["/" + rel[: -len("index.html")]] = ids

    failures = []
    for f in sorted(public.rglob("*.html")):
        page = "/" + f.relative_to(public).as_posix()
        page_url = page[: -len("index.html")] if page.endswith("index.html") else page
        body = f.read_text(encoding="utf-8", errors="replace")
        seen = set()
        for m in HREF.finditer(body):
            href = html.unescape(group(m)).strip()
            if not href or href.startswith(SKIP_SCHEMES):
                continue
            parsed = urllib.parse.urlparse(href)
            if parsed.scheme and parsed.scheme not in ("http", "https"):
                continue
            if parsed.netloc and parsed.netloc not in SITE_HOSTS:
                continue                                    # third party
            target = urllib.parse.urljoin(page_url, parsed._replace(
                scheme="", netloc="").geturl())
            if target in seen:
                continue
            seen.add(target)
            t = urllib.parse.urlparse(target)
            path, frag = t.path or page_url, urllib.parse.unquote(t.fragment)

            if path in anchors:
                ids = anchors[path]
            elif path in files:
                if frag:
                    failures.append((page_url, href, "anchor on a non-HTML file"))
                continue
            elif path.endswith("/") and path + "index.html" in files:
                ids = anchors.get(path, set())
            else:
                failures.append((page_url, href, f"no such page: {path}"))
                continue

            if frag and frag not in ids:
                failures.append((page_url, href, f"no such anchor: #{frag}"))

    if failures:
        print(f"{len(failures)} broken internal link(s):\n", file=sys.stderr)
        for page_url, href, why in failures:
            print(f"  {page_url}", file=sys.stderr)
            print(f"      href: {href}", file=sys.stderr)
            print(f"      {why}\n", file=sys.stderr)
        return 1

    pages = sum(1 for _ in public.rglob("*.html"))
    print(f"internal links OK across {pages} page(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
