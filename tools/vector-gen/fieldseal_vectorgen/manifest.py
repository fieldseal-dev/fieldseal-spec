from __future__ import annotations

import hashlib
import json
from pathlib import Path

VECTOR_SUITE_VERSION = "0.1.0-provisional"
SPEC_VERSION = "0.1-draft"


def write_json(path: Path, payload: dict) -> None:
    """UTF-8, LF, 2-space indent, trailing newline -- docs/08 §3."""
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def build_manifest(root: Path, files: list[Path]) -> dict:
    entries = []
    for f in sorted(files):
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        entries.append({
            "path": f.relative_to(root).as_posix(),
            "sha256": digest,
            "bytes": f.stat().st_size,
        })
    return {
        "vector_suite_version": VECTOR_SUITE_VERSION,
        "spec_version": SPEC_VERSION,
        "provisional": True,
        "provisional_note": (
            "Every suite identifier here is in the reserved 0xFF00-0xFFFF "
            "provisional range (spec §4.8). These vectors are built against "
            "constructions marked [PROVISIONAL] in the specification and "
            "adopted under Gate 0a; they are not a stable release and the "
            "expected values may change when Gate 0b closes."
        ),
        "files": entries,
    }
