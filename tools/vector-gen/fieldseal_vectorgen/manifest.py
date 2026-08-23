from __future__ import annotations

import hashlib
import json
from pathlib import Path

VECTOR_SUITE_VERSION = "0.2.0-provisional"
SPEC_VERSION = "0.1-draft"

# Families generated but deliberately NOT part of the pinned suite. Listed
# rather than omitted: a missing file reads as an oversight, a listed one with
# a reason reads as a decision. A conformance harness MUST iterate `files` and
# MUST NOT iterate `held_out` (docs/14 §4).
HELD_OUT = {
    "blind-index/argon2id.json": {
        "reason": (
            "Held pending a project decision (docs/18 D-15). The original "
            "ground -- that the Argon2id primitive had never been checked "
            "against an external known-answer source -- no longer holds: "
            "since 2026-08-23 the generator checks argon2-cffi against "
            "libsodium's seven published crypto_pwhash answers (empty K and "
            "X, 16-byte salt, p = 1) at every run, and the TypeScript core's "
            "node:crypto backend reproduces RFC 9106 §5.3 and all four "
            "vectors in this file. What remains is the decision to count "
            "the family, which the project makes, not the generator."
        ),
        "unblocks_when": (
            "The project records the decision in docs/07 §7 and moves this "
            "path from held_out to files (tools/vector-gen manifest.HELD_OUT); "
            "both harnesses then run it. No expected value changes."
        ),
        "tracking": "docs/08-test-vector-spec.md §7; gap G2",
    },
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
