# fieldseal.dev

The site is [Hugo](https://gohugo.io) with hand-written templates. There is no
theme, no npm dependency tree, and no third-party JavaScript -- deliberately.
The whole build is one static binary plus the files in this directory.

## Local preview

Requires Hugo (extended not needed) and Python 3.

```sh
python www/scripts/sync-docs.py     # docs/*.md  ->  www/content/docs/
hugo server --source www
```

Then open <http://localhost:1313>.

Do **not** map `fieldseal.dev` to localhost for previewing. `.dev` is on the HSTS
preload list, so browsers refuse plain HTTP on it and you would need a locally
trusted certificate. Use the `localhost` URL.

## How content gets here

`docs/*.md` in the repository root are the canonical documents. They are never
edited by the build. `scripts/sync-docs.py` copies them into
`content/docs/` and prepends Hugo front matter derived from each file's `H1`
and numeric prefix:

| Source | Becomes |
| --- | --- |
| `docs/02-spec-v0.1.md` | `/docs/spec-v0.1/`, weight 3, title from the `H1` |

`content/docs/` is git-ignored. If you find yourself editing a file in there,
you are editing a build artifact -- change `docs/` instead.

This one-directional flow is the point: there is exactly one copy of the
specification text, so the published site cannot drift from the repository.

## Syntax highlighting

`static/css/chroma.css` is generated, not hand-written:

```sh
hugo gen chromastyles --style=github        >  www/static/css/chroma.css
# dark half appended inside a prefers-color-scheme media query
hugo gen chromastyles --style=github-dark   >> /tmp/dark.css
```

Regenerate only if you change the highlight style.

## Deployment

`.github/workflows/pages.yml` builds on every push to `main` that touches
`www/` or `docs/`, and publishes to GitHub Pages.

The site is live at <https://fieldseal.dev>. The two one-time repository
settings it needed are done:

1. **Settings -> Pages -> Source: GitHub Actions.**
2. **Settings -> Pages -> Custom domain: `fieldseal.dev`**, with **Enforce
   HTTPS** ticked — plain HTTP now redirects to HTTPS.

One item may still be outstanding, at the account/organisation level: **verify
the domain** (Settings -> Pages -> Add a domain) so that no other repository can
publish to `fieldseal.dev`. This is what prevents a domain takeover if Pages is
ever unlinked, and it is not observable from outside — check it in settings
rather than assuming it from the site being up.

Note that the workflow deploys from `main` only. Work merged to `dev` does not
reach the site until `dev` merges to `main`.

`static/CNAME` is committed as a belt-and-braces measure; the custom domain
configured in repository settings is what actually takes effect.
