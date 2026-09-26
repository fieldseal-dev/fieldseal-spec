# tools/brand

Builds the Fieldseal mark and the site's icons from one geometry.

The mark is a row of three table cells, drawn on a square grid and turned 45
degrees. The two outer cells are hollow and the middle one is solid: one field
sealed in an ordinary row, which is what field-level encryption does and what
a whole-disk or whole-database scheme does not. It deliberately avoids the
padlock, key and shield every encryption product uses.

| File | What it is | Used by |
|---|---|---|
| `www/static/brand/fieldseal-mark.svg` | the mark in `#1f5fa8`, the site's light `--accent` | this repository's README |
| `www/static/brand/fieldseal-mark-dark.svg` | the mark in `#79b0f0`, the dark `--accent` | the README on a dark GitHub theme |
| `www/static/favicon.svg` | the mark, switching colour with `prefers-color-scheme` | the site's `<head>` |
| `www/static/favicon.ico` | 16, 32 and 48 px PNGs in one ICO | browsers without SVG icons, and bare `/favicon.ico` requests |
| `www/static/apple-touch-icon.png` | 180 px, opaque white, mark inset 10% | iOS home-screen bookmarks |

The site header inlines `fieldseal-mark.svg` at build time
([`www/layouts/partials/header.html`](../../www/layouts/partials/header.html))
and replaces its fill with `currentColor`, so the mark follows `--accent` in both
themes. The replacement matches the literal `fill="#1f5fa8"`: if `LIGHT` in the
script changes, change it there too. The build fails with a message saying so
if you forget.

## Regenerating

```sh
py -3 tools/brand/make_logo.py
```

Standard library only. The PNGs are rasterised by the script itself, by
supersampling the cells, rather than by an SVG renderer, so nothing needs
installing. Every output is overwritten; none of them is hand-edited.

## Using the mark

- **One flat colour.** No gradients, shadows or outlines. It is built to read at
  16 px, and effects are the first thing lost there.
- **Not a seal of approval.** Do not put the mark on a badge, rosette or stamp,
  or next to words like "certified" or "verified". The design has not been
  independently reviewed (see the status note in the top-level
  [README](../../README.md)), and a logo must not imply otherwise.
- **The wordmark is text, not a drawing.** Set "Fieldseal" in the surrounding
  typeface next to the mark, as the site header does.
