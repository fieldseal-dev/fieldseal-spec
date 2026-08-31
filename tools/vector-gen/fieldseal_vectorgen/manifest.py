from __future__ import annotations

import hashlib
import json
from pathlib import Path

VECTOR_SUITE_VERSION = "0.6.0-provisional"
SPEC_VERSION = "0.1-draft"

# Families generated but deliberately NOT part of the pinned suite. Listed
# rather than omitted: a missing file reads as an oversight, a listed one with
# a reason reads as a decision. A conformance harness MUST iterate `files` and
# MUST NOT iterate `held_out` (docs/14 §4).
HELD_OUT: dict[str, dict[str, str]] = {
    # Empty since suite 0.6.0-provisional. `blind-index/argon2id.json` was the
    # only entry; the project took the decision its `unblocks_when` asked for
    # and pinned the family (docs/07 §7, 2026-08-31). The mechanism stays
    # because the next held-out family should be listed with a reason rather
    # than quietly omitted -- and because promoting this one showed what a
    # hold-out hides: nothing ran those vectors, so eight of them carried no
    # `idf_params` and both cores would have rejected them as malformed.
}


def write_json(path: Path, payload: dict) -> None:
    """UTF-8, LF, 2-space indent, trailing newline -- docs/08 §3."""
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def _entry(root: Path, f: Path) -> dict:
    return {
        "path": f.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
        "bytes": f.stat().st_size,
    }


# Files the suite ships that are not vector families: no expected values, so
# nothing to run. Hashed like everything else; a harness MUST NOT iterate them.
SUPPORT = {"keys/test-keys.json", "cross/corpus.json"}


def build_manifest(root: Path, written: list[Path]) -> dict:
    pinned, held, support = [], [], []
    for f in sorted(written):
        rel = f.relative_to(root).as_posix()
        if rel in HELD_OUT:
            held.append({**_entry(root, f), **HELD_OUT[rel]})
        elif rel in SUPPORT:
            support.append(_entry(root, f))
        else:
            pinned.append(_entry(root, f))
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
        "files": pinned,
        "support": support,
        "held_out": held,
        "held_out_note": (
            "Generated, reviewable, and NOT part of the suite. A conformance "
            "run MUST iterate `files` only. An implementation may exercise a "
            "held-out family for its own development, but MUST NOT count it "
            "toward any conformance claim and MUST NOT report it as passed."
        ),
    }
