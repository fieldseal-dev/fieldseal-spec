"""Generate the Fieldseal mark, favicons and touch icon from one geometry.

The mark is a row of three table cells with the middle one sealed: two hollow
cells either side of a solid one. It is drawn on a square grid and rotated 45
degrees, so the row runs from bottom left to top right. Every output file below
is derived from CELLS; none of them is hand-edited.

Standard library only, so it runs anywhere the rest of tools/ does. The PNGs
are rasterised here by supersampling rather than by an SVG renderer, which the
shapes -- axis-aligned rectangles in grid space -- make easy.

    py -3 tools/brand/make_logo.py
"""
import math
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "www" / "static"

LIGHT = "#1f5fa8"  # --accent in www/static/css/main.css
DARK = "#79b0f0"   # --accent under prefers-color-scheme: dark

# Grid units. A cell is 9x9; a hollow cell has a 3x3 hole, so its stroke is 3.
CELL, HOLE, GAP = 9, 3, 2
CELLS = [(0, True), (CELL + GAP, False), (2 * (CELL + GAP), True)]  # (x, hollow)
W, H = 3 * CELL + 2 * GAP, CELL
PAD = 1.2  # around the rotated shape, in grid units
HALF = (W + H) / math.sqrt(2) / 2 + PAD  # half the side of the square viewBox


def path_data():
    d = []
    for x, hollow in CELLS:
        d.append(f"M{x} 0h{CELL}v{CELL}h-{CELL}z")
        if hollow:
            o = (CELL - HOLE) // 2
            d.append(f"M{x + o} {o}v{HOLE}h{HOLE}v-{HOLE}z")
    return "".join(d)


def svg(fill=None, style=None):
    box = f"{-HALF:.2f} {-HALF:.2f} {2 * HALF:.2f} {2 * HALF:.2f}"
    fill_attr = f' fill="{fill}"' if fill else ""
    style_el = f"<style>{style}</style>" if style else ""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{box}">{style_el}'
        f'<path{fill_attr} fill-rule="evenodd" '
        f'transform="rotate(-45) translate({-W / 2} {-H / 2})" d="{path_data()}"/>'
        "</svg>\n"
    )


def inside(x, y):
    """Is viewBox point (x, y) on the mark? Undoes rotate(-45) and the translate."""
    c = math.sqrt(0.5)
    gx = (x * c - y * c) + W / 2
    gy = (x * c + y * c) + H / 2
    if not 0 <= gy < H:
        return False
    for cx, hollow in CELLS:
        if cx <= gx < cx + CELL:
            if not hollow:
                return True
            o = (CELL - HOLE) / 2
            return not (cx + o <= gx < cx + o + HOLE and o <= gy < o + HOLE)
    return False


def raster(size, fg, bg=None, inset=0.0, ss=8):
    """RGBA rows. `inset` shrinks the mark inside the canvas (fraction per side)."""
    fr, fgc, fb = (int(fg[i:i + 2], 16) for i in (1, 3, 5))
    scale = 2 * HALF / (size * (1 - 2 * inset))
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            hits = 0
            for sy in range(ss):
                for sx in range(ss):
                    x = ((px + (sx + 0.5) / ss) - size / 2) * scale
                    y = ((py + (sy + 0.5) / ss) - size / 2) * scale
                    hits += inside(x, y)
            a = hits / (ss * ss)
            if bg is None:
                row += bytes((fr, fgc, fb, round(255 * a)))
            else:
                br, bgc, bb = (int(bg[i:i + 2], 16) for i in (1, 3, 5))
                mix = lambda f, b: round(f * a + b * (1 - a))
                row += bytes((mix(fr, br), mix(fgc, bgc), mix(fb, bb), 255))
        rows.append(bytes(row))
    return rows


def png(rows):
    size = len(rows)

    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data)))

    raw = b"".join(b"\x00" + r for r in rows)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def ico(images):
    """An ICO holding PNG images, which every browser since IE9 reads."""
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = len(head) + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32,
                               len(data), offset)
        blobs += data
        offset += len(data)
    return head + entries + blobs


def main():
    brand = STATIC / "brand"
    brand.mkdir(exist_ok=True)
    (brand / "fieldseal-mark.svg").write_text(svg(fill=LIGHT), newline="\n")
    (brand / "fieldseal-mark-dark.svg").write_text(svg(fill=DARK), newline="\n")
    # One SVG favicon that follows the browser's colour scheme.
    (STATIC / "favicon.svg").write_text(svg(style=(
        f"path{{fill:{LIGHT}}}"
        f"@media (prefers-color-scheme:dark){{path{{fill:{DARK}}}}}")), newline="\n")
    # favicon.ico is for browsers that ignore SVG icons, and for /favicon.ico
    # requests that never read the page's <link> tags.
    (STATIC / "favicon.ico").write_bytes(
        ico([(s, png(raster(s, LIGHT))) for s in (16, 32, 48)]))
    # iOS fills transparency with black and rounds the corners itself, so this
    # one is opaque with room around the mark.
    (STATIC / "apple-touch-icon.png").write_bytes(
        png(raster(180, LIGHT, bg="#ffffff", inset=0.1)))
    for p in sorted([*brand.iterdir(), *STATIC.glob("favicon.*"),
                     STATIC / "apple-touch-icon.png"]):
        print(p.relative_to(ROOT).as_posix(), p.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
