#!/usr/bin/env python3
"""
Turn an Archify sequence-diagram HTML page into a standalone, script-free SVG
for docs/figures/.

Archify (https://github.com/tt-a1i/archify, MIT) renders a diagram as an HTML
page: an inline SVG plus an interactive viewer -- zoom levels, hover notes,
theme toggle -- written in JavaScript. fieldseal.dev carries no third-party
JavaScript (www/README.md), and GitHub renders an SVG but not a page, so the
figure that is committed is the SVG alone. This script extracts it and makes it
stand on its own:

  * keeps the "context" detail layer (message labels, participant sublabels) and
    drops the "fine" layer, which the viewer only shows when zoomed in -- its
    long notes overlap everything at the default scale;
  * drops the background grid, the per-node <title>s and the viewer's data-*,
    tabindex and ARIA-button attributes;
  * enlarges the 7/9/11px text a step, widening each label's backing mask to
    match, because the figure is read at column width rather than full screen;
  * moves the legend clear of the last time segment and crops the empty bands
    the viewer reserved above the participants and below for its navigation dock;
  * inlines the classic preset's light and dark colours as CSS variables, dark
    under prefers-color-scheme -- the same switch the site uses -- with masks
    and background set to the site's own page colours.

Standard library only. Usage:

    python tools/figures/svg_from_archify.py page.html out.svg --desc "..."
"""
import argparse, re, sys

FONT_STEP = {"7": "8.5", "9": "10.5", "11": "12"}
LEGEND_SHIFT = 16
MARGIN = 18

# Archify's classic preset (light and dark), with --bg and --mask replaced by
# www/static/css/main.css's --bg so label masks disappear into the page.
LIGHT = {
    "bg": "#ffffff", "mask": "#ffffff",
    "backend-fill": "rgba(52, 211, 153, 0.18)", "backend-stroke": "#059669",
    "database-fill": "rgba(167, 139, 250, 0.2)", "database-stroke": "#7c3aed",
    "security-fill": "rgba(251, 113, 133, 0.15)", "security-stroke": "#e11d48",
    "lane-fill": "rgba(248, 250, 252, 0.65)", "lane-stroke": "#cbd5e1",
    "text": "#0f172a", "text-muted": "#64748b", "text-dim": "#94a3b8",
    "arrow": "#94a3b8", "arrow-emphasis": "#059669",
}
DARK = {
    "bg": "#0f1216", "mask": "#0f1216",
    "backend-fill": "rgba(6, 78, 59, 0.4)", "backend-stroke": "#34d399",
    "database-fill": "rgba(76, 29, 149, 0.4)", "database-stroke": "#a78bfa",
    "security-fill": "rgba(136, 19, 55, 0.4)", "security-stroke": "#fb7185",
    "lane-fill": "rgba(15, 23, 42, 0.22)", "lane-stroke": "#334155",
    "text": "#ffffff", "text-muted": "#94a3b8", "text-dim": "#64748b",
    "arrow": "#64748b", "arrow-emphasis": "#34d399",
}

RULES = """
svg { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; }
.bg { fill: var(--bg); }
.c-backend { fill: var(--backend-fill); stroke: var(--backend-stroke); }
.c-database { fill: var(--database-fill); stroke: var(--database-stroke); }
.c-security { fill: var(--security-fill); stroke: var(--security-stroke); }
.c-lane { fill: var(--lane-fill); stroke: var(--lane-stroke); stroke-dasharray: 6,6; }
.c-mask { fill: var(--mask); stroke: none; }
.t-primary { fill: var(--text); }
.t-muted { fill: var(--text-muted); }
.t-dim { fill: var(--text-dim); }
.t-backend { fill: var(--backend-stroke); }
.t-security { fill: var(--security-stroke); }
.t-database { fill: var(--database-stroke); }
.a-default { stroke: var(--arrow); fill: none; }
.a-emphasis { stroke: var(--arrow-emphasis); fill: none; }
.a-security { stroke: var(--security-stroke); fill: none; stroke-dasharray: 5,5; }
.m-default { fill: var(--arrow); }
.m-emphasis { fill: var(--arrow-emphasis); }
.m-security { fill: var(--security-stroke); }
.m-dashed { fill: var(--database-stroke); }
.s-backend { color: var(--backend-stroke); }
.s-database { color: var(--database-stroke); }
.s-security { color: var(--security-stroke); }
.semantic-sigil { fill: none; stroke: currentColor; stroke-width: 1.35; stroke-linecap: round; stroke-linejoin: round; opacity: 0.76; }
.semantic-sigil .sigil-fill { fill: currentColor; stroke: none; }
"""


def tokens(values: dict) -> str:
    return " ".join(f"--{k}: {v};" for k, v in values.items())


def style_block() -> str:
    return (f"<style>\nsvg {{ {tokens(LIGHT)} }}\n"
            f"@media (prefers-color-scheme: dark) {{ svg {{ {tokens(DARK)} }} }}"
            f"{RULES}</style>")


def enlarge_labels(svg: str) -> str:
    """Step the font sizes up, and widen a label's mask by the same ratio.

    Archify sizes each mask from the label's own text, so the ratio of the new
    font size to the old one is the ratio the mask needs, centred on the
    label's anchor.
    """
    def label(m):
        rect, space, text = m.group(1), m.group(2), m.group(3)
        size = re.search(r'font-size="([^"]+)"', text).group(1)
        if size not in FONT_STEP:
            return m.group(0)
        ratio = float(FONT_STEP[size]) / float(size)
        x = float(re.search(r' x="([^"]+)"', rect).group(1))
        w = float(re.search(r' width="([^"]+)"', rect).group(1))
        cx, nw = x + w / 2, w * ratio
        rect = re.sub(r' x="[^"]+"', f' x="{cx - nw / 2:.2f}"', rect, count=1)
        rect = re.sub(r' width="[^"]+"', f' width="{nw:.2f}"', rect, count=1)
        return rect + space + text

    svg = re.sub(r'(<rect [^>]*class="c-mask"/>)(\s*)(<text [^>]*text-anchor="middle"[^>]*>)',
                 label, svg)
    return re.sub(r'font-size="(7|9|11)"',
                  lambda m: f'font-size="{FONT_STEP[m.group(1)]}"', svg)


def content_extent(svg: str) -> tuple:
    """Top of the highest rect and the lowest drawn point (text baselines, rect
    bottoms). Runs before the background rect is added."""
    rects = [(float(y), float(h)) for y, h in
             re.findall(r'<rect [^>]*? y="([\d.]+)"[^>]*? height="([\d.]+)"', svg)]
    texts = [float(y) for y in re.findall(r'<text [^>]*? y="([\d.]+)"', svg)]
    top = min(y for y, _ in rects)
    bottom = max([y + h for y, h in rects] + [y + 6 for y in texts])
    return top, bottom


def convert(page: str, desc: str) -> str:
    start = page.index("<svg")
    svg = page[start:page.index("</svg>", start) + len("</svg>")]

    svg = re.sub(r'\s*<text data-detail="fine"[^>]*>.*?</text>', "", svg, flags=re.S)
    svg = re.sub(r'\s*<pattern id="grid".*?</pattern>', "", svg, flags=re.S)
    svg = re.sub(r'\s*<!-- Background Grid -->\s*<rect [^>]*url\(#grid\)[^>]*/>', "", svg)
    svg = re.sub(r"\s*<!--.*?-->", "", svg, flags=re.S)
    # Node <title>s are hover text for the viewer; an <img> never shows them.
    head_end = svg.index("</desc>") + len("</desc>")
    svg = svg[:head_end] + re.sub(r"\s*<title>.*?</title>", "", svg[head_end:], flags=re.S)
    svg = re.sub(r'\s(?:data-[\w-]+|tabindex|aria-pressed|aria-label)="[^"]*"', "", svg)
    svg = re.sub(r'\s(?:data-[\w-]+)(?=[\s>/])', "", svg)
    svg = re.sub(r'\srole="button"', "", svg)

    svg = enlarge_labels(svg)
    svg, n = re.subn(r'(<g)(>\s*<text [^>]*>Legend</text>)',
                     rf'\1 transform="translate(0 {LEGEND_SHIFT})"\2', svg, count=1)
    if n != 1:
        raise SystemExit("error: legend group not found")

    width = float(re.search(r'viewBox="0 0 ([\d.]+) [\d.]+"', svg).group(1))
    top, bottom = content_extent(svg)
    top = max(0, round(top) - MARGIN)
    height = round(bottom + LEGEND_SHIFT + MARGIN) - top
    svg = re.sub(r'<svg viewBox="[^"]+"',
                 f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:g}" '
                 f'height="{height}" viewBox="0 {top} {width:g} {height}"', svg, count=1)
    svg = re.sub(r"<desc([^>]*)>.*?</desc>", lambda m: f"<desc{m.group(1)}>{desc}</desc>",
                 svg, count=1, flags=re.S)
    svg = svg.replace("<defs>", style_block() + "\n<defs>", 1)
    svg = svg.replace("</defs>", f'</defs>\n<rect class="bg" x="0" y="{top}" '
                      f'width="{width:g}" height="{height}"/>', 1)
    svg = re.sub(r"\n\s*\n", "\n", svg)
    return svg + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("page", help="Archify-rendered HTML")
    ap.add_argument("out", help="SVG to write")
    ap.add_argument("--desc", required=True, help="text for the SVG's <desc>")
    a = ap.parse_args()
    with open(a.page, encoding="utf-8") as f:
        svg = convert(f.read(), a.desc)
    if "<script" in svg:
        print("error: script survived extraction", file=sys.stderr)
        return 1
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(svg)
    print(f"wrote {a.out} ({len(svg.encode())} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
