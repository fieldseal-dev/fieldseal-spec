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
| `read-path.svg` | `read-path.workflow.json` | [`docs/22-read-path.md`](../../docs/22-read-path.md) |
| `query-path.svg` | `query-path.sequence.json` | [`docs/23-query-path.md`](../../docs/23-query-path.md) |
| `key-hierarchy.svg` | `key-hierarchy.architecture.json` | [`docs/24-key-lifecycle.md`](../../docs/24-key-lifecycle.md) |
| `key-lifecycle.svg` | `key-lifecycle.lifecycle.json` | [`docs/24-key-lifecycle.md`](../../docs/24-key-lifecycle.md) |

## Regenerating a figure

Archify is not vendored and not a dependency of anything in this repository.
The committed figures were drawn with Archify 2.17.0-dev.1.

```sh
ARCHIFY=path/to/archify     # a checkout of github.com/tt-a1i/archify

# <name> and <type> come from the source's file name: write-path.sequence.json
# is name write-path, type sequence.
node "$ARCHIFY/bin/archify.mjs" deliver <type> \
    docs/figures/<name>.<type>.json /tmp/<name>.html --quality showcase

python tools/figures/svg_from_archify.py /tmp/<name>.html docs/figures/<name>.svg \
    --desc "<the figure's description, below>"
```

The `--desc` text becomes the SVG's `<desc>`, which screen readers announce:

- `write-path`: Sequence diagram of one encrypted-field write through the Django adapter: encrypt under a single-use record key, derive the blind index under the separate index key, and store both in one INSERT or UPDATE.
- `read-path`: Workflow of one encrypted-field read: recognize the envelope, check the decrypt allow-list, take candidate keys from the cache, verify the key commitment, open the AEAD; each gate has its own error.
- `query-path`: Sequence diagram of an equality query through the Django adapter: index the query value, fetch the candidate rows that share its blind index, decrypt and re-verify each, and return only true matches.
- `key-hierarchy`: Key hierarchy: a root KEK in the KMS wraps two sibling tenant keys, the DEK and the index key; the DEK derives a single-use record key per write that seals the envelope, and the index key derives a blind-index key per index that produces the truncated blind index.
- `key-lifecycle`: Lifecycle of one key version: created, active for write, decrypt-only once a newer version is active, re-encrypted away by a sweep, unreferenced, scheduled for destruction with a cancellable delay window, destroyed; destroying a version that envelopes still name loses those rows.

`deliver` must exit 0: it validates the layout (label collisions, crossings,
legibility) before it writes the page. Never edit an SVG by hand — the next
regeneration would silently undo it.
