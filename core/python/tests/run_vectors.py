"""Vector harness (docs/08 §5, docs/14 §4).

Runnable two ways: directly for a report on stdout, and via pytest through
`test_vectors.py`.

The manifest is the authority on what the suite contains. This harness iterates
`files` and never `held_out`: a held-out family is reported as `not-run` so its
absence is visible rather than silent.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("FIELDSEAL_TEST_MODE", "1")

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "vectors"
sys.path.insert(0, str(REPO / "core" / "python" / "src"))

from fieldseal import Fieldseal, FieldContext                      # noqa: E402
from fieldseal.blindindex import (idf_hmac_sha512,                 # noqa: E402
                                  normalize_nfc_casefold, truncate)
from fieldseal.context import canonical_context                    # noqa: E402
from fieldseal.kdf import commitment, index_key, record_key        # noqa: E402
from fieldseal.keyprovider import StaticKeyProvider                # noqa: E402
from fieldseal.testing import encrypt_with_materials               # noqa: E402

H = bytes.fromhex


def _client(key_id: bytes, dek: bytes, index_key_material: bytes) -> Fieldseal:
    return Fieldseal(
        key_provider=StaticKeyProvider(key_id, dek, index_key_material),
        allowed_suites={0xFF01}, write_suite=0xFF01,
        # Spec §4.8: the suite is provisional, so even a harness must say so
        # explicitly to write. A harness that did not need to would be evidence
        # the gate does not work.
        acknowledge_provisional_suite=True,
    )


def _ctx(v: dict, suite_id: int = 0xFF01) -> FieldContext:
    c = v["context"]
    return FieldContext(
        table_uuid=H(c["table_uuid"]), column_uuid=H(c["column_uuid"]),
        purpose=c["purpose"],
        tenant_id=None if c["tenant_id"] is None else H(c["tenant_id"]),
        row_id=None if c["row_id"] is None else H(c["row_id"]),
    ).with_suite(suite_id)


def _record(results: list[dict], vid: str, ok: bool, reason: str = "") -> None:
    entry = {"id": vid, "status": "pass" if ok else "fail"}
    if not ok and reason:
        entry["reason"] = reason
    results.append(entry)


def check_manifest(results: list[dict]) -> dict:
    manifest = json.loads((VECTORS / "MANIFEST.json").read_text("utf-8"))
    for entry in manifest["files"]:
        got = hashlib.sha256((VECTORS / entry["path"]).read_bytes()).hexdigest()
        _record(results, f"manifest/{entry['path']}", got == entry["sha256"],
                f"sha256 {got} != {entry['sha256']}")
    return manifest


def run_context(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        if v.get("assertion") == "distinct":
            ok = (v["expected"]["tenant_absent"]
                  != v["expected"]["tenant_zero_length"])
        else:
            ctx = _ctx(v)
            ok = (canonical_context(ctx).hex()
                  == v["expected"]["canonical_context"]
                  and ctx.presence == v["expected"]["presence"])
        _record(results, v["id"], ok)


def run_kdf(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        if v.get("assertion") == "distinct":
            ok = v["expected"]["key_a"] != v["expected"]["key_b"]
        elif "tenant_dek" in v:
            got = record_key(H(v["tenant_dek"]), H(v["key_id"]),
                             H(v["msg_seed"]), _ctx(v), 32)
            ok = got.hex() == v["expected"]["record_key"]
        else:
            got = index_key(H(v["tenant_index_key"]), _ctx(v), v["index_id"])
            ok = got.hex() == v["expected"]["index_key"]
        _record(results, v["id"], ok)


def run_commitment(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        if v.get("assertion") == "distinct":
            ok = (v["expected"]["commitment_a"]
                  != v["expected"]["commitment_b"])
        else:
            ok = (commitment(H(v["record_key"])).hex()
                  == v["expected"]["commitment"])
        _record(results, v["id"], ok)


def run_blind_index(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        if v.get("assertion") == "equal":
            ok = v["expected"]["index_a"] == v["expected"]["index_b"]
        else:
            normalized = normalize_nfc_casefold(v["plaintext_utf8"])
            raw = idf_hmac_sha512(H(v["index_key"]), normalized)
            ok = (normalized.hex() == v["expected"]["normalized"]
                  and raw.hex() == v["expected"]["raw"]
                  and truncate(raw, v["b_bits"]).hex()
                  == v["expected"]["blind_index"])
        _record(results, v["id"], ok)


def run_envelope(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        ctx = _ctx(v)
        fs = _client(H(v["key_id"]), H(v["tenant_dek"]), b"\x11" * 32)
        # Direction 1: encrypt with injected materials -> expected envelope.
        got = encrypt_with_materials(fs, H(v["plaintext"]), ctx,
                                     H(v["msg_seed"]), H(v["nonce"]))
        enc_ok = got.hex() == v["expected"]["envelope"]
        # Direction 2: decrypt the expected envelope -> plaintext. docs/08 §4.1
        # requires both; an implementation can pass one and fail the other.
        dec_ok = (fs.decrypt(H(v["expected"]["envelope"]), ctx).hex()
                  == v["plaintext"])
        ctx_ok = (canonical_context(ctx).hex()
                  == v["expected"]["canonical_context"])
        _record(results, v["id"], enc_ok and dec_ok and ctx_ok,
                f"encrypt={enc_ok} decrypt={dec_ok} context={ctx_ok}")


RUNNERS = {
    "context/canonical.json": run_context,
    "kdf/record-key.json": run_kdf,
    "kdf/index-key.json": run_kdf,
    "commitment/ff01.json": run_commitment,
    "blind-index/hmac-sha512.json": run_blind_index,
    "envelope/ff01.json": run_envelope,
}


def run() -> dict:
    results: list[dict] = []
    manifest = check_manifest(results)
    for entry in manifest["files"]:
        path = entry["path"]
        doc = json.loads((VECTORS / path).read_text("utf-8"))
        if doc.get("status") == "held-out":
            raise AssertionError(
                f"{path} is marked held-out but appears in MANIFEST.files")
        RUNNERS[path](doc, results)

    held = [{"path": h["path"], "status": "not-run", "reason": h["reason"]}
            for h in manifest.get("held_out", [])]
    npass = sum(r["status"] == "pass" for r in results)
    nfail = sum(r["status"] == "fail" for r in results)
    return {
        "schema": "fieldseal-conformance/v1",
        "implementation": {"name": "python-core", "version": "0.1.0.dev0",
                           "language": "python"},
        "vector_suite_version": manifest["vector_suite_version"],
        "spec_version": manifest["spec_version"],
        # L0 is claimable only on a green run, and even then this says nothing
        # about a frozen format: the suite is provisional (spec §4.8).
        "claimed_levels": {"L0": nfail == 0},
        "suites_supported": ["0xFF01"],
        "provisional_suites": True,
        "results": results,
        "held_out": held,
        "summary": {"pass": npass, "fail": nfail, "skipped": 0,
                    "held_out": len(held)},
    }


if __name__ == "__main__":
    report = run()
    for r in report["results"]:
        if r["status"] != "pass":
            print(f"  FAIL {r['id']}: {r.get('reason', '')}")
    print(json.dumps(report["summary"]))
    for h in report["held_out"]:
        print(f"  NOT RUN (held out): {h['path']}")
    raise SystemExit(1 if report["summary"]["fail"] else 0)
