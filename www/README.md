# fieldseal.dev

The site is [Hugo](https://gohugo.io) with hand-written templates. There is no
theme, no npm dependency tree, and no third-party JavaScript -- deliberately.
The whole build is one static binary plus the files in this directory.

## Local preview

Requires Hugo (extended not needed) and Python 3.

```sh
python www/scripts/sync-docs.py     # docs/  ->  www/content/docs/
hugo server --source www
```

Then open <http://localhost:1313>.

Before pushing, build and run the link check the way CI does:

```sh
hugo --source www --minify --gc
python www/scripts/check-links.py www/public
```

Do **not** map `fieldseal.dev` to localhost for previewing. `.dev` is on the HSTS
preload list, so browsers refuse plain HTTP on it and you would need a locally
trusted certificate. Use the `localhost` URL.

## How content gets here

The files under `docs/` in the repository root are the canonical documents. They
are never edited by the build. `scripts/sync-docs.py` copies three trees into
`content/docs/` and prepends Hugo front matter derived from each file's `H1` and
filename:

| Source | Becomes |
| --- | --- |
| `docs/02-spec-v0.1.md` | `/docs/spec-v0.1/`, weight 3, title from the `H1` |
| `docs/adr/README.md` | `/docs/adr/` — the section index |
| `docs/adr/0002-suite-0x0001-aead.md` | `/docs/adr/0002-suite-0x0001-aead/` |
| `docs/issues/README.md` | `/docs/issues/` — the section index |
| `docs/issues/G02-argon2id-parameters.md` | `/docs/issues/g02-argon2id-parameters/` |

The ADRs and gap drafts are published because the specification cites them as
the source of its provisional decisions: §4.6 sends a reviewer to ADR-0002 and
§7.3 to G2, and a reviewer reading the spec on the web should be able to follow
those without leaving the site.

`content/docs/` is git-ignored. If you find yourself editing a file in there,
you are editing a build artifact -- change `docs/` instead.

This one-directional flow is the point: there is exactly one copy of the
specification text, so the published site cannot drift from the repository.

### Links are rewritten on the way in

A relative link is read in two places and cannot be correct in both.
`[Q2](16-reviewer-brief.md#q2)` in `docs/02-spec-v0.1.md` resolves next to its
file on GitHub and works. On the site that document is served at
`/docs/reviewer-brief/`, so a browser resolves the same href against the *current
page* — `/docs/spec-v0.1/16-reviewer-brief.md` — and 404s.

Rather than bend the sources toward the site and break GitHub, `sync-docs.py`
translates them once, at sync time: a link to a published document becomes its
site URL, and a link to a repository path that is not published (`../README.md`,
`../core/typescript/`) becomes a GitHub URL. Links inside code fences are left
alone. **A relative link whose target does not exist fails the sync**, so a
typo cannot reach the site.

`scripts/check-links.py` is the second half of that guard. It runs against the
built HTML in `public/`, where the resolved href and the anchors each page
actually has are both visible, and fails on a link to a missing page or a
missing anchor. Internal links only: third parties 403 CI runners on bot
suspicion (`dfs.ny.gov`, `media.defense.gov`) and go down for reasons that have
nothing to do with this repository, and a deploy that fails for either is a
deploy that gets ignored. Check those by hand.

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
`www/` or `docs/`, and publishes to GitHub Pages. It also builds and link-checks
pull requests touching the same paths, without deploying — a link that points at
nothing should fail the PR that introduced it, not the deploy after the merge.

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
