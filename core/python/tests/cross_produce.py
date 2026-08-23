"""Cross-implementation producer (docs/08 §4.7, docs/14 §3).

Encrypts every case in `vectors/cross/corpus.json` through the REAL
production path -- runtime CSPRNG for `msg_seed` and nonce, no test-mode
injection; `fieldseal.testing` is never imported here -- resolving `key_ref`
against `vectors/keys/test-keys.json`, and writes a cross file whose
envelopes every other implementation must decrypt.

The output differs on every run (that is the point: these envelopes exercise
what a consumer's decrypt path does with values no vector pinned), so the
file is a CI artifact, never committed.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
import warnings
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "vectors"
sys.path.insert(0, str(REPO / "core" / "python" / "src"))

from fieldseal import FieldContext, Fieldseal  # noqa: E402
from fieldseal.errors import FieldsealWarning  # noqa: E402
from fieldseal.keyprovider import StaticKeyProvider  # noqa: E402

H = bytes.fromhex


def _commit() -> str:
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
            text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def client_for(key: dict) -> Fieldseal:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FieldsealWarning)
        return Fieldseal(
            key_provider=StaticKeyProvider(
                H(key["key_id"]), H(key["tenant_dek"]),
                H(key["tenant_index_key"])),
            allowed_suites={int(key["suite_id"], 16)},
            write_suite=int(key["suite_id"], 16),
            # Spec §4.8: writing under a provisional suite is armed
            # deliberately, here as everywhere.
            arm_provisional_suites=True,
        )


def ctx_from(c: dict) -> FieldContext:
    return FieldContext(
        table_uuid=H(c["table_uuid"]), column_uuid=H(c["column_uuid"]),
        purpose=c["purpose"],
        tenant_id=None if c["tenant_id"] is None else H(c["tenant_id"]),
        row_id=None if c["row_id"] is None else H(c["row_id"]),
    )


def produce() -> dict:
    corpus = json.loads((VECTORS / "cross" / "corpus.json").read_text("utf-8"))
    keys = json.loads(
        (VECTORS / "keys" / "test-keys.json").read_text("utf-8"))["keys"]
    clients = {ref: client_for(k) for ref, k in keys.items()}
    cases = []
    for c in corpus["cases"]:
        pt = H(c["plaintext"])
        env = clients[c["key_ref"]].encrypt(pt, ctx_from(c["context"]))
        cases.append({
            "id": f"cross/python/{c['case']}",
            "key_ref": c["key_ref"],
            "context": c["context"],
            "plaintext": c["plaintext"],
            "envelope": env.hex(),
        })
    return {
        "schema": "fieldseal-vectors/cross/v1",
        "producer": {
            "implementation": "python", "version": "0.1.0.dev0",
            "commit": _commit(),
            "produced_at": datetime.datetime.now(
                datetime.timezone.utc).isoformat(timespec="seconds"),
        },
        "suite_id": corpus["suite_id"],
        "cases": cases,
    }


def main() -> int:
    ap = argparse.ArgumentParser(prog="cross_produce")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    doc = produce()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=1) + "\n", "utf-8")
    print(f"wrote {args.out} ({len(doc['cases'])} cases, "
          f"producer python@{doc['producer']['commit'][:12]})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
