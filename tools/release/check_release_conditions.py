"""Check built release artifacts against PRD §8's five experimental-release conditions.

    python tools/release/check_release_conditions.py dist-release

It reads the artifacts themselves -- a wheel's METADATA, an npm tarball's
package.json and README -- not the source tree, so what it checks is what would
be uploaded. Stdlib only. Exit status 1 on any failure.

What each condition is checked by, stated so the check does not overclaim:

1. Below 1.0, maturity marker set -- here: every version's major is 0; every
   wheel carries a `Development Status` classifier of 3 or lower.
2. Provisional suites only, arming gate as specified -- NOT checked here. A
   text scan cannot tell a default that arms from an error message explaining
   how to arm, or from an adapter passing the caller's own choice through; the
   first version of this script tried and flagged exactly those. `smoke.py`
   checks it behaviourally against the installed artifacts: every registered
   suite is provisional, and an unarmed client refuses to write.
3. The warning comes first -- here: every registry description starts with the
   warning, and every README carries the warning block before its first
   paragraph of body text.
4. The honest limitations travel with it -- here: each README names the
   limitation topics the spec requires implementations to document. A keyword
   check, not a reading: it catches a limitation deleted, not one reworded
   into something false.
5. No overclaiming -- here: descriptions and READMEs contain none of a short
   list of claims (production-ready, battle-tested, audited, ...). The rest of
   condition 5 -- release notes and announcements -- is a human review.
"""

from __future__ import annotations

import email.parser
import io
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path

WARN = "EXPERIMENTAL, NOT INDEPENDENTLY REVIEWED, NOT FOR PRODUCTION DATA"
README_WARN = "**Experimental release: not independently reviewed, not for production data.**"
README_MUST = ("re-encrypted", "format may change", "arm")

# Spec §2, §2.3, §3.3, §5.5, §7.3, §8.1 for every package; adapters add the
# §7 normalizer-equality and §10.2 raw-SQL and cache items.
LIMITS_ALL = {
    "§2 compromised process": r"compromised|keys are in",
    "§2.3 logs": r"\blogs?\b",
    "§3.3 storage overhead": r"overhead",
    "§5.5 DEK cache exposure": r"memory dump|swap|core file",
    "§7.3 Argon2id cost": r"Argon2id",
    "§8.1 KMS dependency": r"hard dependency|KMS",
}
LIMITS_ADAPTER = {
    "§10.2 raw SQL": r"raw SQL",
    "§10.2 plaintext caches": r"cache",
    "§7 normalizer equality": r"normali[sz]",
}
# Positive claims only: "have not been independently reviewed" is the warning
# itself, so a bare phrase match would flag the text it exists to protect.
OVERCLAIM = [r"production[- ]ready", r"battle[- ]tested", r"military[- ]grade",
             r"bank[- ]grade",
             r"\b(has|have|is|are) been (independently |externally )?(reviewed|audited)\b",
             r"\b(is|are) (independently |externally )?audited\b"]
ADAPTERS = {"fieldseal-django", "@fieldseal/prisma"}

failures: list[str] = []


def fail(pkg: str, msg: str) -> None:
    failures.append(f"{pkg}: {msg}")


def check_version(pkg: str, version: str) -> None:
    if not re.match(r"0\.", version):
        fail(pkg, f"version {version} is not below 1.0 (condition 1)")


def check_description(pkg: str, desc: str) -> None:
    if not desc.startswith(WARN):
        fail(pkg, f"registry description does not open with the warning (condition 3): {desc[:80]!r}")
    check_overclaim(pkg, "description", desc)


def check_readme(pkg: str, text: str) -> None:
    lines = text.splitlines()
    head = "\n".join(lines[:12])
    if README_WARN not in head:
        fail(pkg, "README does not open with the warning block (condition 3)")
    else:
        block = "\n".join(l for l in lines[:12] if l.startswith(">"))
        for word in README_MUST:
            if word not in block:
                fail(pkg, f"README warning block does not say {word!r} (condition 3)")
    limits = dict(LIMITS_ALL)
    if pkg in ADAPTERS:
        limits.update(LIMITS_ADAPTER)
    for name, pattern in limits.items():
        if not re.search(pattern, text, re.I):
            fail(pkg, f"README does not state the {name} limitation (condition 4)")
    if re.search(r"\]\((?!https?:|#|mailto:)", text):
        fail(pkg, "README has a relative link, which the registry cannot resolve")
    check_overclaim(pkg, "README", text)


def check_overclaim(pkg: str, where: str, text: str) -> None:
    for pattern in OVERCLAIM:
        m = re.search(pattern, text, re.I)
        if m:
            fail(pkg, f"{where} contains {m.group(0)!r} (condition 5)")


def wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as z:
        meta_name = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
        meta = email.parser.Parser().parsestr(z.read(meta_name).decode())
        pkg = meta["Name"]
        check_version(pkg, meta["Version"])
        check_description(pkg, meta["Summary"] or "")
        status = [c for c in meta.get_all("Classifier", []) if c.startswith("Development Status")]
        if not status or not re.match(r"Development Status :: [123] ", status[0]):
            fail(pkg, f"Development Status classifier is {status or 'missing'}, needs 3 or lower (condition 1)")
        if not any(n.endswith("licenses/LICENSE") for n in z.namelist()):
            fail(pkg, "wheel carries no LICENSE")
        check_readme(pkg, meta.get_payload() or "")
        for dep in meta.get_all("Requires-Dist", []):
            if dep.startswith("fieldseal") and "<0.2" not in dep.replace(" ", ""):
                fail(pkg, f"{dep!r} does not pin the core to the 0.1 minor")
        print(f"ok  {path.name}: {pkg} {meta['Version']}")


def tarball(path: Path) -> None:
    with tarfile.open(path) as t:
        manifest = json.load(t.extractfile("package/package.json"))
        pkg = manifest["name"]
        check_version(pkg, manifest["version"])
        check_description(pkg, manifest.get("description", ""))
        if manifest.get("private"):
            fail(pkg, "package.json is private")
        if manifest.get("publishConfig", {}).get("access") != "public":
            fail(pkg, "publishConfig.access is not public (a scoped package publishes restricted)")
        names = t.getnames()
        if "package/LICENSE" not in names:
            fail(pkg, "tarball carries no LICENSE")
        for field in ("dependencies", "peerDependencies"):
            for dep, spec in manifest.get(field, {}).items():
                if spec.startswith(("file:", "link:", "workspace:")):
                    fail(pkg, f"{field}.{dep} is {spec!r}: a published package cannot point at a path")
        check_readme(pkg, t.extractfile("package/README.md").read().decode())
        print(f"ok  {path.name}: {pkg} {manifest['version']}")


def main(argv: list[str]) -> int:
    out = Path(argv[1] if len(argv) > 1 else "dist-release")
    wheels = sorted(out.glob("*.whl"))
    tgzs = sorted(out.glob("*.tgz"))
    if len(wheels) != 2 or len(tgzs) != 2:
        print(f"expected 2 wheels and 2 npm tarballs in {out}, found {len(wheels)} and {len(tgzs)}")
        return 1
    for w in wheels:
        wheel(w)
    for t in tgzs:
        tarball(t)
    if failures:
        print("\nPRD §8 release conditions NOT met:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nPRD §8 release conditions: the mechanical checks pass. Condition 5's release notes and "
          "announcements still need a human read.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
