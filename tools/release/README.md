# tools/release

Builds, checks and smoke-tests the four packages the project may publish as
**experimental pre-1.0 releases** under PRD §8
([`docs/01-prd.md`](../../docs/01-prd.md) §8): `fieldseal` and
`fieldseal-django` on PyPI, and `@fieldseal/core` and `@fieldseal/prisma` on npm.

Nothing here publishes anything. Publishing is a separate, approval-gated step.

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
