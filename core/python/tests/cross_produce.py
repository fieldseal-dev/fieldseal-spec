"""Cross-implementation producer (docs/08 §4.7, docs/14 §3).

Encrypts every case in `vectors/cross/corpus.json` through the REAL
production path -- runtime CSPRNG for `msg_seed` and nonce, no test-mode
injection; `fieldseal.testing` is never imported here -- resolving `key_ref`
against `vectors/keys/test-keys.json`, and writes a cross file whose
envelopes every other implementation must decrypt.

`index_cases` are the other half of the same claim and the more valuable
one: a blind index derived here must be derived byte-identically
everywhere, because a mismatched index is a **silent lookup miss** rather
than an error -- nothing raises, the row simply stops being findable.

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

from fieldseal import (  # noqa: E402
    CardinalityOverride,
    FieldContext,
    Fieldseal,
    IndexDeclaration,
)
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


def _value_of(case: dict) -> str | bytes:
    """The operand a case derives from.

    Exactly one of `value_text` / `value_bytes` / `value_marker` is present per
    docs/08 §4.7. A case violating that gets a named error rather than a bare
    `KeyError` -- and the corpus is generated, so what this guards against is a
    *generator* change, which is exactly the kind that should say what it
    broke. Mirrors `cross_consume.py` and the TypeScript producer: the sides of
    one contract should read the same (raised in the #103 review).
    """
    if "value_text" in case:
        return case["value_text"]
    if "value_bytes" in case:
        return H(case["value_bytes"])
    raise ValueError(
        f"{case['case']}: no value_text, value_bytes or value_marker "
        "(docs/08 §4.7)")


def decl_of(case: dict) -> IndexDeclaration:
    """The corpus's declaration block, as the core's registry wants it.

    It travels with the case because a cross producer derives through a
    *constructed client*, not through primitives: spec §7.4's truncation band
    and §7.6's cardinality gate run at construction, so a consumer that cannot
    rebuild the declaration cannot build the client that re-derives the value.
    `projected_population` and `on_unindexable` affect no derived byte and gate
    construction absolutely.
    """
    d, ctx = case["declaration"], case["context"]
    override = d.get("unindexable_override")
    return IndexDeclaration(
        table_uuid=H(ctx["table_uuid"]),
        column_uuid=H(ctx["column_uuid"]),
        index_id=d["index_id"],
        idf=d["idf"],
        normalize=d["normalize"],
        truncate_bits=d["truncate_bits"],
        projected_population=d["projected_population"],
        on_unindexable=d["on_unindexable"],
        unindexable_override=None if override is None else CardinalityOverride(
            reason=override["reason"], approved_by=override["approved_by"],
            date=override["date"]),
    )


def client_for(key: dict, indexes: list | None = None) -> Fieldseal:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FieldsealWarning)
        return Fieldseal(
            key_provider=StaticKeyProvider(
                H(key["key_id"]), H(key["tenant_dek"]),
                H(key["tenant_index_key"])),
            allowed_suites={int(key["suite_id"], 16)},
            write_suite=int(key["suite_id"], 16),
            indexes=indexes or [],
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
    index_cases_in = corpus.get("index_cases", [])

    # One client per key_ref, carrying every declaration that ref's index cases
    # need, deduplicated on the registry's own key (table + column + index_id).
    # The corpus asserts that two cases sharing one key share one declaration,
    # so a duplicate here is the same object and a *conflict* would have failed
    # generation rather than construction.
    def decls_for(ref: str) -> list:
        seen: dict = {}
        for c in index_cases_in:
            if c["key_ref"] != ref:
                continue
            ctx = c["context"]
            seen[(ctx["table_uuid"], ctx["column_uuid"],
                  c["declaration"]["index_id"])] = decl_of(c)
        return list(seen.values())

    clients = {ref: client_for(k, decls_for(ref)) for ref, k in keys.items()}

    index_cases = []
    for c in index_cases_in:
        client, ctx = clients[c["key_ref"]], ctx_from(c["context"])
        if c.get("value_marker"):
            # A derivation with no plaintext: the bucketed column's reserved
            # index value, which an adapter derives for every value the
            # normalizer refuses. Its own operation, not `blind_index`.
            index = client.unindexable_marker(ctx)
        else:
            # Text as text, never its encoding (spec §7.1 / G16 part A): a
            # producer that encoded first would have collapsed two distinct
            # values into one before the core saw them, which is the false
            # match the text path exists to prevent. `value_bytes` is only for
            # an `identity` column, where the bytes *are* the value.
            value = _value_of(c)
            index = client.blind_index(value, ctx)
        entry = {
            "id": f"cross/python/index/{c['case']}",
            "key_ref": c["key_ref"],
            "declaration": c["declaration"],
            "context": c["context"],
        }
        for k_ in ("value_text", "value_bytes", "value_marker"):
            if k_ in c:
                entry[k_] = c[k_]
        entry["index"] = index.hex()
        index_cases.append(entry)

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
        "schema": ("fieldseal-vectors/cross/v2" if index_cases
                   else "fieldseal-vectors/cross/v1"),
        "producer": {
            "implementation": "python", "version": "0.1.0.dev0",
            "commit": _commit(),
            "produced_at": datetime.datetime.now(
                datetime.timezone.utc).isoformat(timespec="seconds"),
        },
        "suite_id": corpus["suite_id"],
        "index_cases": index_cases,
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
          f"{len(doc['index_cases'])} index cases, "
          f"producer python@{doc['producer']['commit'][:12]})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
