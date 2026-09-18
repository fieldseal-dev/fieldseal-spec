# tools/release

Builds, checks and smoke-tests the four packages the project may publish as
**experimental pre-1.0 releases** under PRD §8
([`docs/01-prd.md`](../../docs/01-prd.md) §8): `fieldseal` and
`fieldseal-django` on PyPI, and `@fieldseal/core` and `@fieldseal/prisma` on npm.

Nothing here publishes anything. Publishing is `.github/workflows/release.yml`, described below.

| Script | What it does |
|---|---|
| `build_dists.py` | Builds all six artifacts into `dist-release/`: sdist and wheel for each Python package, one tarball for each npm package. The Prisma tarball is packed from a staging copy whose `package.json` names the core by version (`^<core version>`) rather than `file:../../core/typescript`, which only works inside this repository. The source tree is never modified. |
| `check_release_conditions.py` | Checks the built artifacts against PRD §8's five conditions: version below 1.0; Alpha-or-lower classifier; the warning at the start of every registry description and README; the limitations the spec requires each README to state; no overclaiming phrases. Also checks the LICENSE files, public access for scoped npm packages, and that no `file:` dependency survives. The docstring says which parts are keyword checks and which condition is left to `smoke.py`. |
| `smoke.py` | Installs the artifacts into a fresh virtualenv and a fresh npm project and uses them. Every registered suite must be provisional, and an unarmed client must refuse to write. Each core decrypts the other's envelope. The Django adapter renders a spec §3.6 value, and the Prisma adapter loads with its peer. |

CI runs all three as the `release-readiness` job in `.github/workflows/conformance.yml`.

Locally:

```sh
python tools/release/build_dists.py --out dist-release   # needs `build`, npm, and npm ci in both npm packages
python tools/release/check_release_conditions.py dist-release
python tools/release/smoke.py dist-release                # needs network for cryptography, django, @prisma/client
```

**What these scripts do not cover.** Condition 5 also applies to release notes and announcements, which only a person can read.

## Publishing

Push a `v0.MINOR.PATCH` tag that matches all four package versions.
`.github/workflows/release.yml` then runs three jobs:

1. **`build`** refuses a tag that disagrees with any package version. It then
   runs the three scripts above and uploads the artifacts.
2. **`publish`** waits for the maintainer's approval in the `release`
   environment, which accepts only `v0.*` tags. It re-verifies `SHA256SUMS`,
   then uploads to PyPI and to npm (the core before the adapter). A version
   already on a registry is skipped, so re-running after a partial failure is
   safe.
3. **`draft-release`** creates the GitHub release as a draft, with the
   artifacts and their hashes. Condition 5 covers release notes, so a person
   writes the "what changed" section, reads the note, and publishes it.

**No stored credentials.** Both registries use trusted publishing (OIDC):

- PyPI trusts this repository, `release.yml` and the `release` environment for
  `fieldseal`. It has a *pending* publisher for `fieldseal-django`, whose first
  upload creates the project.
- npm trusts the same three for `@fieldseal/core` and `@fieldseal/prisma`.
  npm configures trust per package, so each package needed an existing version
  first; that is what the two `0.0.0` placeholders are.
- npm provenance is generated at publish time. It requires npm ≥ 11.5.1, which
  the job installs, and a `repository.url` that matches this repository.
- **npm's "Allowed actions" must include `npm publish`.** A trusted publisher
  created after 3 September 2026 allows only `npm stage publish` by default,
  and the registry refuses a direct publish with `403 OIDC permission denied
  for this action`. That, not the job, is why v0.1.2's first attempt failed.
- The publish job must not give npm a token of its own: no `registry-url` on
  `setup-node`, which writes one into `.npmrc`. A guard refuses to publish if
  one is configured.
