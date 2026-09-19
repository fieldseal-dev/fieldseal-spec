# tools/figures

Builds the diagrams in [`docs/figures/`](../../docs/figures/). Each figure has a
JSON source, drawn with [Archify](https://github.com/tt-a1i/archify), and a
committed SVG extracted from Archify's output by `svg_from_archify.py`.

The SVG is what GitHub shows inside a document and what fieldseal.dev serves
(`www/scripts/sync-docs.py` copies `docs/figures/*.svg` to `/figures/`). Archify
itself renders an HTML page whose viewer is JavaScript; the site carries no
third-party JavaScript ([`www/README.md`](../../www/README.md)), so only the
diagram is kept. What the extraction changes, and why, is in the script's
docstring.

| Figure | Source | Used by |
|---|---|---|
| `write-path.svg` | `write-path.sequence.json` | [`docs/21-write-path.md`](../../docs/21-write-path.md) |

## Regenerating a figure

Archify is not vendored and not a dependency of anything in this repository.
The committed figures were drawn with Archify 2.17.0-dev.1.

```sh
ARCHIFY=path/to/archify     # a checkout of github.com/tt-a1i/archify

node "$ARCHIFY/bin/archify.mjs" deliver sequence \
    docs/figures/write-path.sequence.json /tmp/write-path.html --quality showcase

python tools/figures/svg_from_archify.py /tmp/write-path.html docs/figures/write-path.svg \
    --desc "Sequence diagram of one encrypted-field write through the Django adapter: encrypt under a single-use record key, derive the blind index under the separate index key, and store both in one INSERT or UPDATE."
```

`deliver` must exit 0: it validates the layout (label collisions, crossings,
legibility) before it writes the page. Never edit an SVG by hand — the next
regeneration would silently undo it.
