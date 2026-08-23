"""Cross-implementation consumer (docs/08 §4.7, docs/14 §3).

Decrypts every case of one or more producer files and compares plaintext
byte-exact. This is the direction that tests the central claim: a value
encrypted by implementation A is decryptable by implementation B with the
same key. Exit status is non-zero on any failed pair, and a verdict file is
written for the CI gate.

The consumer trusts nothing from the producer beyond what a real reader
would have: the envelope bytes, the caller-side context, and the key_ref
into the shared public test-keys file.
"""

from __future__ import annotations

import argparse
import json
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


def client_for(key: dict) -> Fieldseal:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FieldsealWarning)
        return Fieldseal(
            key_provider=StaticKeyProvider(
                H(key["key_id"]), H(key["tenant_dek"]),
                H(key["tenant_index_key"])),
            allowed_suites={int(key["suite_id"], 16)},
            write_suite=int(key["suite_id"], 16),
            # Decrypt needs no §4.8 arming; strict mode so a non-envelope
            # producer value fails loudly instead of passing through.
        )


def ctx_from(c: dict) -> FieldContext:
    return FieldContext(
        table_uuid=H(c["table_uuid"]), column_uuid=H(c["column_uuid"]),
        purpose=c["purpose"],
        tenant_id=None if c["tenant_id"] is None else H(c["tenant_id"]),
        row_id=None if c["row_id"] is None else H(c["row_id"]),
    )


def consume(files: list[Path]) -> dict:
    keys = json.loads(
        (VECTORS / "keys" / "test-keys.json").read_text("utf-8"))["keys"]
    clients = {ref: client_for(k) for ref, k in keys.items()}
    pairs, producers = [], []
    for f in files:
        doc = json.loads(f.read_text("utf-8"))
        producer = doc["producer"]["implementation"]
        producers.append(producer)
        for case in doc["cases"]:
            entry: dict = {"id": case["id"], "producer": producer}
            try:
                got = clients[case["key_ref"]].decrypt(
                    H(case["envelope"]), ctx_from(case["context"]))
                if got.hex() == case["plaintext"]:
                    entry["status"] = "pass"
                else:
                    entry["status"] = "fail"
                    entry["reason"] = "plaintext differs"
            except Exception as exc:  # noqa: BLE001 - a verdict reports, not raises
                entry["status"] = "fail"
                entry["reason"] = repr(exc)
            pairs.append(entry)
    npass = sum(p["status"] == "pass" for p in pairs)
    return {
        "schema": "fieldseal-conformance-cross/v1",
        "consumer": "python",
        "producers": producers,
        "pairs": pairs,
        "summary": {"pass": npass, "fail": len(pairs) - npass, "skipped": 0},
    }


def main() -> int:
    ap = argparse.ArgumentParser(prog="cross_consume")
    ap.add_argument("files", nargs="+", type=Path,
                    help="producer cross files to decrypt")
    ap.add_argument("--verdict", type=Path, required=True)
    args = ap.parse_args()
    doc = consume(args.files)
    args.verdict.parent.mkdir(parents=True, exist_ok=True)
    args.verdict.write_text(json.dumps(doc, indent=1) + "\n", "utf-8")
    for p in doc["pairs"]:
        if p["status"] != "pass":
            print(f"FAIL {p['id']} (producer {p['producer']}): "
                  f"{p.get('reason', '')}", file=sys.stderr)
    print(f"consumer python: {doc['summary']}", file=sys.stderr)
    return 1 if doc["summary"]["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
