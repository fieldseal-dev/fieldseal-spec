"""Build the four release artifacts exactly as they would be published.

    python tools/release/build_dists.py --out dist-release

Python: an sdist and a wheel for `fieldseal` and `fieldseal-django`, built by
`python -m build`.

npm: a tarball for `@fieldseal/core` and `@fieldseal/prisma`, packed by
`npm pack` from a **staging copy** of each package. The staging copy exists for
one reason: in this repository the Prisma adapter depends on the core as
`file:../../core/typescript`, so that CI and local development always test the
checkout. A published package cannot point at a path, so the staged
`package.json` names the core by version (`^<core version>`) instead. Nothing
in the working tree is modified.

The release workflow and the CI release-readiness job both call this script,
so what CI checks is what would be uploaded. It prints each artifact's sha256
and writes them to `<out>/SHA256SUMS`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PYTHON = ["core/python", "adapters/django"]
NPM = ["core/typescript", "adapters/prisma"]
NPM_CMD = "npm.cmd" if sys.platform == "win32" else "npm"


def run(cmd: list[str], cwd: Path) -> None:
    print(f"  $ {' '.join(cmd)}  (in {cwd.relative_to(REPO) if cwd.is_relative_to(REPO) else cwd})",
          flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


def build_python(out: Path) -> None:
    for pkg in PYTHON:
        run([sys.executable, "-m", "build", "--outdir", str(out), "."], REPO / pkg)


def stage(pkg: Path, dest: Path, core_version: str) -> None:
    """Copy what `files` publishes, plus package.json with the core by version."""
    meta = json.loads((pkg / "package.json").read_text("utf-8"))
    for name in meta["files"]:
        src = pkg / name
        if not src.exists():
            raise SystemExit(f"{pkg.name}: `files` lists {name}, which does not exist -- build first")
        if src.is_dir():
            shutil.copytree(src, dest / name)
        else:
            shutil.copy2(src, dest / name)
    deps = meta.get("dependencies", {})
    if "@fieldseal/core" in deps:
        deps["@fieldseal/core"] = f"^{core_version}"
    for field in ("dependencies", "peerDependencies", "optionalDependencies"):
        for name, spec in meta.get(field, {}).items():
            if spec.startswith(("file:", "link:", "workspace:")):
                raise SystemExit(f"{pkg.name}: {field}.{name} is still {spec!r} after staging")
    (dest / "package.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", "utf-8")


def build_npm(out: Path) -> None:
    core_version = json.loads((REPO / "core/typescript/package.json").read_text("utf-8"))["version"]
    for rel in NPM:
        pkg = REPO / rel
        run([NPM_CMD, "run", "build"], pkg)
        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp) / "package"
            staged.mkdir()
            stage(pkg, staged, core_version)
            run([NPM_CMD, "pack", "--pack-destination", str(out)], staged)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=REPO / "dist-release")
    ap.add_argument("--only", choices=["python", "npm"])
    args = ap.parse_args(argv)
    out: Path = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    if args.only in (None, "python"):
        build_python(out)
    if args.only in (None, "npm"):
        build_npm(out)
    sums = []
    for f in sorted(out.iterdir()):
        if f.name == "SHA256SUMS":
            continue
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        sums.append(f"{digest}  {f.name}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", "utf-8")
    print("\n".join(sums))
    return 0


if __name__ == "__main__":
    sys.exit(main())
