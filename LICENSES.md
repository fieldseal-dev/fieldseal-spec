# Licensing

Fieldseal uses three licenses, chosen so that each part of the repository can be used the way it is meant to be used. This file is the authoritative mapping; the rationale is in [`GOVERNANCE.md`](GOVERNANCE.md).

| What | License | SPDX | File |
|---|---|---|---|
| Specification and documentation | Creative Commons Attribution 4.0 International | `CC-BY-4.0` | [`LICENSE-SPEC`](LICENSE-SPEC) |
| Test vectors | Creative Commons Zero 1.0 Universal (public domain dedication) | `CC0-1.0` | [`LICENSE-VECTORS`](LICENSE-VECTORS) |
| Code and everything else | Apache License 2.0 | `Apache-2.0` | [`LICENSE`](LICENSE) |

## By path

**`CC-BY-4.0`** — `docs/`, `spec/`, and the Markdown documents at the repository root (`README.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CLAUDE.md`, `AGENTS.md`).

**`CC0-1.0`** — `vectors/`, including the JSON vector files, their schemas, and `MANIFEST.json`. `vectors/README.md` is documentation *about* the vectors and is `CC-BY-4.0` like the rest of the docs.

**`Apache-2.0`** — `core/`, `adapters/`, `tools/`, `bench/`, `examples/`, `.github/`, and the site machinery in `www/` (templates, CSS, and `www/scripts/`). Note that `www/content/docs/` is generated from `docs/` at build time and is not committed; the generated copies carry the license of their source, `CC-BY-4.0`.

Where a directory contains both, the more specific rule above wins over the general one.

## Why these three

**The specification is `CC-BY-4.0` because being copied is the point.** A specification that cannot be quoted, profiled, or folded into another standard without a license conversation is a specification that will not be adopted. Attribution is the only condition, which is the condition a standards process would want anyway.

**The vectors are `CC0-1.0` because their value comes from being run, not from being credited.** The project's central claim is that an implementation someone else wrote passes the same vectors (PRD metric M2). Anything that gives a competing implementer a reason to hesitate before running the conformance suite works directly against that, and attribution obligations on a file of hex strings are exactly that kind of friction. This closes the open question `GOVERNANCE.md` recorded.

**The code is `Apache-2.0` for the patent grant.** Permissive licenses without an explicit patent grant leave a real question open for a cryptographic format, and Apache 2.0 is what the OpenSSF ecosystem this project targets expects.

## For contributors

Contributions are accepted under the license governing the path you are contributing to, as mapped above. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## A note on CC0 and patents

`CC0-1.0` is a copyright waiver. It explicitly does **not** waive patent or trademark rights held by the person dedicating the work — that limitation is in the CC0 text itself, and it is not specific to this project. It is called out here so nobody reads the vectors' public-domain dedication as a broader grant than it is. The `Apache-2.0` patent grant covers the code, which is where a patent question would actually arise.
