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

from fieldseal import (  # noqa: E402
    CardinalityOverride,
    FieldContext,
    Fieldseal,
    IndexDeclaration,
)
from fieldseal.errors import FieldsealWarning  # noqa: E402
from fieldseal.keyprovider import StaticKeyProvider  # noqa: E402

H = bytes.fromhex


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
            # Decrypt needs no §4.8 arming; strict mode so a non-envelope
            # producer value fails loudly instead of passing through.
        )


#: The producer-document schemas this consumer understands.
#:
#: **Read, not assumed.** Until 2026-08-31 neither consumer looked at
#: `doc["schema"]` at all: it wrote one into its own verdict and ignored the
#: producer's. That was harmless while there was one schema and becomes the
#: exact failure this family exists to catch the moment there are two -- a
#: consumer that did not understand `cross/v2` would decrypt the envelopes,
#: report `fail: 0`, and never touch the index half. A green run that skipped
#: the more valuable assertion is worse than a red one.
#:
#: `v2` adds `index_cases` beside `cases`; `v1` documents stay valid and are
#: recorded as carrying no index half rather than silently counting as if they
#: had one.
SCHEMAS = {"fieldseal-vectors/cross/v1", "fieldseal-vectors/cross/v2"}


def _value_of(case: dict) -> str | bytes:
    """The operand a case derives from -- exactly one of `value_text` /
    `value_bytes` / `value_marker` per docs/08 §4.7, named rather than left to
    a bare `KeyError`. The same helper the producers carry."""
    if "value_text" in case:
        return case["value_text"]
    if "value_bytes" in case:
        return H(case["value_bytes"])
    raise ValueError(
        f"{case['id']}: no value_text, value_bytes or value_marker "
        "(docs/08 §4.7)")


def decl_of(case: dict) -> IndexDeclaration:
    """The producer's declaration block, as this core's registry wants it."""
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
        schema = doc.get("schema")
        if schema not in SCHEMAS:
            # Fail closed. An unrecognised schema may carry assertions this
            # consumer cannot make, and silently checking only the half it
            # understands is how a matrix reports green on a claim nobody
            # tested.
            pairs.append({"id": f"{producer}/document", "producer": producer,
                          "kind": "document", "status": "fail",
                          "reason": f"unrecognised producer schema {schema!r}; "
                                    f"this consumer reads {sorted(SCHEMAS)}"})
            continue
        for case in doc["cases"]:
            entry: dict = {"id": case["id"], "producer": producer,
                           "kind": "envelope"}
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

        # The index half. A v1 producer carries none, and that is recorded
        # rather than passed over: "this producer emits no index cases" and
        # "this consumer did not check them" must not look the same.
        index_cases = doc.get("index_cases", [])
        if not index_cases:
            # v1 means "this producer carries no index half" and is a pass.
            # v2 means "this producer carries one" -- so v2 with an empty array
            # is a producer that lost its index cases to a bug, and passing it
            # would be precisely the silent skip this half exists to close.
            v1 = schema == "fieldseal-vectors/cross/v1"
            pairs.append({
                "id": f"{producer}/index-half", "producer": producer,
                "kind": "document", "status": "pass" if v1 else "fail",
                "reason": (f"producer emits {schema}, which carries no index "
                           "cases") if v1 else
                          (f"producer emits {schema}, which declares an index "
                           "half, but `index_cases` is empty")})
            continue
        for case in index_cases:
            entry = {"id": case["id"], "producer": producer, "kind": "index"}
            try:
                # docs/08 §4.7, normative: the derivation string comes from
                # `purpose` and the registry lookup from `index_id`, so a
                # producer that disagreed with itself would derive against one
                # and register under the other. It fails either way -- but as
                # "no blind index is declared", which names neither the case
                # nor the disagreement. Checked here so the reason is the
                # cause.
                want = f"index:{case['declaration']['index_id']}"
                if case["context"]["purpose"] != want:
                    raise ValueError(
                        f"purpose {case['context']['purpose']!r} disagrees "
                        f"with index_id {case['declaration']['index_id']!r} "
                        f"(docs/08 §4.7)")
                # A client per case, carrying that case's declaration.
                # Construction is where §7.4's band and §7.6's gate run, so a
                # declaration the producer could build and this core refuses is
                # itself a divergence worth failing on -- named, rather than
                # surfacing as a mismatch.
                client = client_for(keys[case["key_ref"]], [decl_of(case)])
                ctx = ctx_from(case["context"])
                if case.get("value_marker"):
                    got = client.unindexable_marker(ctx)
                else:
                    got = client.blind_index(_value_of(case), ctx)
                if got.hex() == case["index"]:
                    entry["status"] = "pass"
                else:
                    entry["status"] = "fail"
                    entry["reason"] = (f"index differs: derived {got.hex()}, "
                                       f"producer said {case['index']}")
            except Exception as exc:  # noqa: BLE001 - a verdict reports, not raises
                entry["status"] = "fail"
                entry["reason"] = repr(exc)
            pairs.append(entry)

    npass = sum(p["status"] == "pass" for p in pairs)
    return {
        "schema": "fieldseal-conformance-cross/v2",
        "consumer": "python",
        "producers": producers,
        "pairs": pairs,
        "summary": {
            "pass": npass, "fail": len(pairs) - npass, "skipped": 0,
            # Which half each pair checked. The two fail for different reasons
            # and want different reading: an envelope mismatch is a decrypt
            # problem, an index mismatch is a *silent lookup miss* in
            # production -- nothing would have raised, the row would just have
            # stopped being findable.
            "envelope": sum(p["kind"] == "envelope" for p in pairs),
            "index": sum(p["kind"] == "index" for p in pairs),
            # A document-level pair checked neither half -- an unreadable
            # schema, or an index half a producer declared and did not deliver.
            # Counting it as either would report a check that never ran.
            "document": sum(p["kind"] == "document" for p in pairs),
        },
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
