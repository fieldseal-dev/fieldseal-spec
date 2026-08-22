"""Generate the vector suite.

Families are grouped by whether they need a third-party dependency, so that
`--stdlib-only` produces a usable partial suite on a bare interpreter.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .families import (blind_index_family, commitment_family, context_family,
                       envelope_family, kdf_family)
from .manifest import HELD_OUT, build_manifest, write_json

STDLIB_FAMILIES = {
    "context/canonical.json": context_family.generate,
    "kdf/record-key.json": kdf_family.generate_record_key,
    "kdf/index-key.json": kdf_family.generate_index_key,
    "commitment/ff01.json": commitment_family.generate,
    "blind-index/hmac-sha512.json": blind_index_family.generate_hmac,
}

DEPENDENT_FAMILIES = {
    "envelope/ff01.json": envelope_family.generate,          # cryptography
    "blind-index/argon2id.json": blind_index_family.generate_argon2id,  # argon2-cffi
}


def selfcheck_roundtrip() -> int:
    """docs/08 §4.1 requires every envelope vector to be exercised in both
    directions. Encrypting and then decrypting here is not a substitute for a
    second implementation -- it catches assembly errors, not spec
    misreadings -- but a generator whose own output will not open is not worth
    reviewing."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from .envelope import SUITES
    checked = 0
    for vec in envelope_family.generate()["vectors"]:
        env = bytes.fromhex(vec["expected"]["envelope"])
        suite = SUITES[0xFF01]
        n, t, c = suite["nonce_len"], suite["tag_len"], suite["commit_len"]
        nonce = env[51:51 + n]
        body = env[51 + n:len(env) - c]
        commit = env[len(env) - c:]
        rk = bytes.fromhex(vec["intermediates"]["record_key"])
        aad = bytes.fromhex(vec["expected"]["aad"])
        pt = AESGCM(rk).decrypt(nonce, body, aad)
        assert pt == bytes.fromhex(vec["plaintext"]), vec["id"]
        assert commit == bytes.fromhex(vec["intermediates"]["commitment"])
        assert len(body) == len(pt) + t
        checked += 1
    return checked


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fieldseal-vector-gen")
    ap.add_argument("--out", type=Path, required=True,
                    help="vectors/ directory to write")
    ap.add_argument("--stdlib-only", action="store_true",
                    help="skip families needing cryptography or argon2-cffi")
    args = ap.parse_args(argv)

    families = dict(STDLIB_FAMILIES)
    if not args.stdlib_only:
        families.update(DEPENDENT_FAMILIES)

    written: list[Path] = []
    for rel, fn in families.items():
        path = args.out / rel
        write_json(path, fn())
        written.append(path)
        print(f"  wrote {rel}")

    if not args.stdlib_only:
        n = selfcheck_roundtrip()
        print(f"  self-check: {n} envelope vectors decrypt back to plaintext")

    manifest = args.out / "MANIFEST.json"
    payload = build_manifest(args.out, written)
    write_json(manifest, payload)
    print(f"  wrote MANIFEST.json ({len(payload['files'])} pinned, "
          f"{len(payload['held_out'])} held out)")
    for h in payload["held_out"]:
        print(f"    HELD OUT: {h['path']} -- not part of the suite, "
              f"MUST NOT be counted toward conformance")

    if args.stdlib_only:
        print("\nPARTIAL SUITE: envelope/ and blind-index/argon2id.json were "
              "skipped.\nMANIFEST.json therefore does not describe a complete "
              "suite -- do not publish it.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
