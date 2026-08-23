"""Vector harness (docs/08 §5) and conformance report (docs/14 §4).

Runnable two ways: directly, writing the docs/14 §4 JSON report to stdout
(and nothing else -- prose goes to stderr, so the redirect in
`.github/workflows/conformance.yml` yields a file that parses), and via
pytest through `test_vectors.py`.

The manifest is the authority on what the suite contains. This harness iterates
`files` and never `held_out`: a held-out family is reported as `not-run` so its
absence is visible rather than silent. A manifest hash mismatch aborts the run
before any vector is consulted (docs/08 §5 item 1): a suite that does not match
its own manifest is not a suite this report can be about.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import platform
import subprocess
import sys
import unicodedata
from pathlib import Path

os.environ.setdefault("FIELDSEAL_TEST_MODE", "1")

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "vectors"
sys.path.insert(0, str(REPO / "core" / "python" / "src"))

import fieldseal                                                   # noqa: E402
from fieldseal import Fieldseal, FieldContext                      # noqa: E402
from fieldseal.api import PROVISIONAL_ENV                          # noqa: E402
from fieldseal.blindindex import (NORMALIZERS, idf_hmac_sha512,    # noqa: E402
                                  truncate)
from fieldseal.context import aad, canonical_context               # noqa: E402
from fieldseal.envelope import MAX_PLAINTEXT, serialize_header     # noqa: E402
from fieldseal.errors import LengthExceeded                        # noqa: E402
from fieldseal.kdf import commitment, index_key, record_key        # noqa: E402
from fieldseal.keyprovider import StaticKeyProvider                # noqa: E402
from fieldseal.testing import encrypt_with_materials               # noqa: E402

H = bytes.fromhex

# docs/08 §4.4 names the normalizer `nfc-casefold-v1` (via docs/09 §7); the
# shipped vectors say `nfc-casefold`. Mapped here, explicitly, and recorded in
# the report (docs/18 D-07). The core ships only the versioned identifier.
VECTOR_NORMALIZER_ALIASES = {"nfc-casefold": "nfc-casefold-v1"}

# Spec §9 (G5), docs/14 §4: what this core pinned where the specification is
# open or silent, in one place, so the Python and TypeScript reports can be
# diffed key by key. Each key names the docs/18 entry that records the gap.
PINNED_DECISIONS = {
    "decrypt-order": (
        "recognition (len<1 | fmt_ver≠0x01 | len<51 | suite unregistered | "
        "len<suite minimum → NOT_CIPHERTEXT in strict, pass-through in "
        "permissive/readonly; fmt_ver=0x02 with len≥111 → "
        "UNKNOWN_FORMAT_VERSION in every mode) → LENGTH_EXCEEDED (§3.5 "
        "decrypt side) → SUITE_NOT_ALLOWED → KEY_UNAVAILABLE (provider "
        "returned no candidate) → per candidate: HKDF record key, "
        "constant-time commitment verify, then AEAD open; open failure after "
        "a verified commitment → TAG_INVALID; no candidate's commitment "
        "verifies → COMMITMENT_INVALID  [docs/09 §3.2; D-02, D-11]"),
    "aad-mismatch": (
        "AAD_MISMATCH is never raised on the 0xFF01 decrypt path: under §6.3 "
        "dual binding a context mismatch changes the record key and is "
        "indistinguishable from key confusion at the commitment check (G5). "
        "The optional diagnostic re-derivation docs/09 §3.2 describes is not "
        "implemented.  [D-02]"),
    "unknown-format-version-set": (
        "reserved-known-future fmt_ver values = {0x02}; plausible length = "
        "the global minimum registered envelope length (111 bytes); all other "
        "non-0x01 first bytes are NOT_CIPHERTEXT (docs/09 §3.2 footnote; "
        "docs/08 §4.6)  [D-03]"),
    "api-boundary-order": (
        "encrypt/rotate: MODE_VIOLATION → SUITE_PROVISIONAL → LENGTH_EXCEEDED "
        "→ context validation (INVALID_ARGUMENT, non-§9); all before key "
        "acquisition  [D-04]"),
    "provisional-arming": (
        f"constructor argument arm_provisional_suites=True or environment "
        f"variable {PROVISIONAL_ENV}=1; read at construction; a keyword on "
        "the constructor because Python has no separate config object  "
        "[D-14]"),
    "unimplemented-registered-suite": (
        "0xFF02 is registered (is_ciphertext → True) but refused at "
        "construction if allow-listed or set as write_suite "
        "(CONFIGURATION_ERROR naming G7); no §9 code is reachable for it "
        "because no client can be built that accepts it  [D-12]"),
    "commitment-construction": (
        "HKDF-SHA-512(ikm = record_key, salt = \"\", info = "
        "\"fieldseal-commit-v1\", 32) -- from the G1 issue draft's proposed "
        "direction; spec §4.6 itself states no formula  [D-01]"),
    "rotate-in-permissive": (
        "rotate() on non-envelope input in permissive mode encrypts the "
        "pass-through value (decrypt ∘ encrypt, literally composed)  [D-13]"),
    "normalizer-text-over-bytes": (
        "nfc-casefold-v1 over bytes decodes strict UTF-8 first; invalid UTF-8 "
        "is refused with INVALID_ARGUMENT rather than folded through "
        "replacement characters; no NFC pass after folding; Unicode version "
        "is the interpreter's (environment.unicode_platform)  [D-10]"),
}


def _client(key_id: bytes, dek: bytes, index_key_material: bytes) -> Fieldseal:
    return Fieldseal(
        key_provider=StaticKeyProvider(key_id, dek, index_key_material),
        allowed_suites={0xFF01}, write_suite=0xFF01,
        # Spec §4.8: the suite is provisional, so even a harness must say so
        # explicitly to write. A harness that did not need to would be evidence
        # the gate does not work -- and `encrypt_with_materials` runs the
        # same boundary as `encrypt`, so the gate does apply here.
        arm_provisional_suites=True,
    )


def _ctx(v: dict, suite_id: int = 0xFF01) -> FieldContext:
    c = v["context"]
    return FieldContext(
        table_uuid=H(c["table_uuid"]), column_uuid=H(c["column_uuid"]),
        purpose=c["purpose"],
        tenant_id=None if c["tenant_id"] is None else H(c["tenant_id"]),
        row_id=None if c["row_id"] is None else H(c["row_id"]),
    ).with_suite(suite_id)


def _record(results: list[dict], vid: str, ok: bool, reason: str = "",
            **details: object) -> None:
    entry: dict = {"id": vid, "status": "pass" if ok else "fail"}
    if not ok and reason:
        entry["reason"] = reason
    if details:
        entry["details"] = details
    results.append(entry)


def _suite_id(v: dict, default: int = 0xFF01) -> int:
    return int(v["suite_id"], 16) if "suite_id" in v else default


# -- families -----------------------------------------------------------------

def run_context(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        if v.get("assertion") == "distinct":
            ok = (v["expected"]["tenant_absent"]
                  != v["expected"]["tenant_zero_length"])
            _record(results, v["id"], ok, reproducible=False)
            continue
        # The family carries no suite_id (docs/18 D-05); 0xFF01 is assumed.
        ctx = _ctx(v, _suite_id(v))
        ok = (canonical_context(ctx).hex()
              == v["expected"]["canonical_context"]
              and ctx.presence == v["expected"]["presence"])
        _record(results, v["id"], ok, assumed_suite_id="0xFF01")


def run_kdf(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        if v.get("assertion") == "distinct":
            ok = v["expected"]["key_a"] != v["expected"]["key_b"]
            _record(results, v["id"], ok, reproducible=False)
        elif "tenant_dek" in v:
            got = record_key(H(v["tenant_dek"]), H(v["key_id"]),
                             H(v["msg_seed"]), _ctx(v, _suite_id(v)), 32)
            _record(results, v["id"], got.hex() == v["expected"]["record_key"])
        else:
            # The vector carries purpose "encrypt" plus a separate index_id;
            # the spec's "index:<id>" purpose is constructed from both
            # (docs/18 D-06).
            ctx = _ctx(v, _suite_id(v))
            got = index_key(H(v["tenant_index_key"]), ctx, v["index_id"])
            ok = (got.hex() == v["expected"]["index_key"]
                  and canonical_context(ctx.for_index(v["index_id"])).hex()
                  == v["expected"]["info"])
            _record(results, v["id"], ok)


def run_commitment(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        if v.get("assertion") == "distinct":
            ok = (v["expected"]["commitment_a"]
                  != v["expected"]["commitment_b"])
            _record(results, v["id"], ok, reproducible=False)
        else:
            ok = (commitment(H(v["record_key"])).hex()
                  == v["expected"]["commitment"])
            _record(results, v["id"], ok)


def _index_key_origins() -> dict[str, tuple[bytes, dict]]:
    """index_key hex -> (tenant_index_key, kdf/index-key vector). Lets a
    blind-index vector, which carries only the derived key, be run end to end
    through `Fieldseal.blind_index` with a provider holding the tenant key."""
    doc = json.loads((VECTORS / "kdf" / "index-key.json").read_text("utf-8"))
    return {v["expected"]["index_key"]: (H(v["tenant_index_key"]), v)
            for v in doc["vectors"] if "tenant_index_key" in v}


def run_blind_index(doc: dict, results: list[dict]) -> None:
    origins = _index_key_origins()
    for v in doc["vectors"]:
        if v.get("assertion") == "equal":
            ok = v["expected"]["index_a"] == v["expected"]["index_b"]
            _record(results, v["id"], ok, reproducible=False)
            continue
        name = VECTOR_NORMALIZER_ALIASES.get(v["normalizer"], v["normalizer"])
        normalized = NORMALIZERS[name](v["plaintext_utf8"])
        raw = idf_hmac_sha512(H(v["index_key"]), normalized)
        stored = truncate(raw, v["b_bits"])
        ok = (normalized.hex() == v["expected"]["normalized"]
              and raw.hex() == v["expected"]["raw"]
              and stored.hex() == v["expected"]["blind_index"]
              and stored.hex() == v["expected"]["stored"]
              and len(stored) == v["expected"]["stored_bytes"])
        _record(results, v["id"], ok, normalizer_mapped_to=name)
        # End to end through the public API, with the tenant index key the
        # kdf/index-key family says produced this vector's index_key.
        origin = origins.get(v["index_key"])
        if origin is None:
            _record(results, v["id"] + "#pipeline", False,
                    "no kdf/index-key vector produces this index_key")
            continue
        tenant_index_key, kv = origin
        fs = _client(bytes(16), b"\x22" * 32, tenant_index_key)
        got = fs.blind_index(v["plaintext_utf8"], _ctx(kv, _suite_id(v)),
                             index_id=v["index_id"], b_bits=v["b_bits"],
                             idf="hmac-sha512", normalizer=name)
        # Bytes in must equal text in (the core is bytes-in/bytes-out).
        got_b = fs.blind_index(v["plaintext_utf8"].encode("utf-8"),
                               _ctx(kv, _suite_id(v)), index_id=v["index_id"],
                               b_bits=v["b_bits"], idf="hmac-sha512",
                               normalizer=name)
        _record(results, v["id"] + "#pipeline",
                got.hex() == v["expected"]["stored"] and got == got_b,
                f"got {got.hex()} (bytes-in {got_b.hex()})")


def run_envelope(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        sid = _suite_id(v)
        ctx = _ctx(v, sid)
        fs = _client(H(v["key_id"]), H(v["tenant_dek"]), b"\x11" * 32)
        exp = v["expected"]
        # Direction 1: encrypt with injected materials -> expected envelope,
        # plus every intermediate the vector states.
        got = encrypt_with_materials(fs, H(v["plaintext"]), ctx,
                                     H(v["msg_seed"]), H(v["nonce"]))
        checks = {
            "envelope": got.hex() == exp["envelope"],
            "envelope_bytes": len(got) == exp["envelope_bytes"],
            "canonical_context": canonical_context(ctx).hex()
            == exp["canonical_context"],
            "aad": aad(serialize_header(sid, H(v["key_id"]),
                                        H(v["msg_seed"]))[0],
                       H(v["key_id"]), H(v["msg_seed"]), ctx).hex()
            == exp["aad"],
        }
        if "intermediates" in v:
            rk = record_key(H(v["tenant_dek"]), H(v["key_id"]),
                            H(v["msg_seed"]), ctx, 32)
            checks["record_key"] = rk.hex() == v["intermediates"]["record_key"]
            checks["commitment"] = (commitment(rk).hex()
                                    == v["intermediates"]["commitment"])
        _record(results, v["id"], all(checks.values()),
                " ".join(f"{k}={ok}" for k, ok in checks.items()))
        # Direction 2: decrypt the expected envelope -> plaintext. docs/08 §4.1
        # requires both; an implementation can pass one and fail the other.
        try:
            pt = fs.decrypt(H(exp["envelope"]), ctx)
            _record(results, v["id"] + "#decrypt", pt.hex() == v["plaintext"],
                    "plaintext differs")
        except Exception as exc:  # noqa: BLE001 - a harness reports, not raises
            _record(results, v["id"] + "#decrypt", False, repr(exc))


RUNNERS = {
    "context/canonical.json": run_context,
    "kdf/record-key.json": run_kdf,
    "kdf/index-key.json": run_kdf,
    "commitment/ff01.json": run_commitment,
    "blind-index/hmac-sha512.json": run_blind_index,
    "envelope/ff01.json": run_envelope,
}


# -- out of band (docs/08 §5 item 8; docs/14 §4) -------------------------------

def run_out_of_band() -> list[dict]:
    """Spec §3.5 has no vector: a 2 GiB input is not a repository artifact.
    Both sides are exercised here, on operands the runtime allocates lazily
    (zero pages are never touched), and the exact code is asserted."""
    fs = _client(bytes(16), b"\x22" * 32, b"\x33" * 32)
    ctx = FieldContext(table_uuid=bytes(16), column_uuid=bytes(16))
    out = []

    def attempt(vid: str, method: str, fn) -> None:
        try:
            fn()
            out.append({"id": vid, "status": "fail", "method": method,
                        "reason": "no error raised"})
        except LengthExceeded:
            out.append({"id": vid, "status": "pass", "method": method})
        except MemoryError as exc:
            out.append({"id": vid, "status": "not-run", "method": method,
                        "reason": f"runtime could not allocate: {exc!r}"})
        except Exception as exc:  # noqa: BLE001
            out.append({"id": vid, "status": "fail", "method": method,
                        "reason": f"wrong error: {exc!r}"})

    attempt("spec/3.5/length-bound",
            "a 2^31-byte plaintext is refused with LENGTH_EXCEEDED before key "
            "acquisition (the provider is never called)",
            lambda: fs.encrypt(bytes(MAX_PLAINTEXT + 1), ctx))

    def oversize_decrypt() -> None:
        # An anonymous mapping is zero without being touched on every
        # platform; bytearray(n) would memset 2 GiB into residency on Linux.
        blob = mmap.mmap(-1, 111 + MAX_PLAINTEXT + 1)
        mv = memoryview(blob)
        try:
            blob[:51] = serialize_header(0xFF01, bytes(16), bytes(32))
            fs.decrypt(mv, ctx)
        finally:
            # Release the export before the mapping closes; a traceback
            # holding `mv` would otherwise turn the close into BufferError.
            mv.release()
            blob.close()
    attempt("spec/3.5/length-bound#decrypt",
            "an envelope whose implied plaintext length is 2^31 bytes is "
            "refused with LENGTH_EXCEEDED before allocation or key lookup",
            oversize_decrypt)
    return out


# -- report ---------------------------------------------------------------------

def _commit() -> str:
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                              capture_output=True, text=True, check=True,
                              timeout=10).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _environment() -> dict:
    from cryptography.hazmat.backends.openssl import backend as ossl
    import cryptography
    return {
        "runtime": f"{platform.python_implementation()} "
                   f"{platform.python_version()}",
        "os": f"{sys.platform} {platform.machine()}",
        "crypto_backend": f"{ossl.openssl_version_text()} via "
                          f"pyca/cryptography {cryptography.__version__}",
        "unicode_platform": f"CPython unicodedata {unicodedata.unidata_version}"
                            " (NFC, str.casefold)",
        "unicode_casefold_table": "interpreter's (not vendored)",
    }


def check_manifest() -> dict:
    manifest = json.loads((VECTORS / "MANIFEST.json").read_text("utf-8"))
    bad = []
    for entry in manifest["files"]:
        got = hashlib.sha256((VECTORS / entry["path"]).read_bytes()).hexdigest()
        if got != entry["sha256"]:
            bad.append(f"{entry['path']}: sha256 {got} != {entry['sha256']}")
    if bad:
        raise AssertionError("vector suite does not match MANIFEST.json:\n  "
                             + "\n  ".join(bad))
    return manifest


def run() -> dict:
    manifest = check_manifest()
    results: list[dict] = []
    for entry in manifest["files"]:
        path = entry["path"]
        doc = json.loads((VECTORS / path).read_text("utf-8"))
        if doc.get("status") != "pinned":
            raise AssertionError(
                f"{path} is in MANIFEST.files but status={doc.get('status')!r}")
        RUNNERS[path](doc, results)
    results.sort(key=lambda r: r["id"])

    held = [{"path": h["path"], "status": "not-run", "reason": h["reason"]}
            for h in manifest.get("held_out", [])]
    oob = run_out_of_band()
    npass = sum(r["status"] == "pass" for r in results)
    nfail = sum(r["status"] == "fail" for r in results)
    green = nfail == 0 and all(o["status"] == "pass" for o in oob)
    return {
        "schema": "fieldseal-conformance/v1",
        "implementation": {"name": "python-core",
                           "version": fieldseal.__version__,
                           "commit": _commit(), "language": "python"},
        "vector_suite_version": manifest["vector_suite_version"],
        "spec_version": manifest["spec_version"],
        # L0 is claimable only on a green run, and even then this says nothing
        # about a frozen format: the suite is provisional (spec §4.8).
        "claimed_levels": {"L0": green, "L1": False, "L2": False,
                           "L3": False, "L4": False},
        "suites_supported": ["0xFF01"],
        "provisional_suites": True,
        "environment": _environment(),
        "pinned_decisions": PINNED_DECISIONS,
        "harness_notes": [
            "docs/08 §5 item 2 (JSON-Schema validation) could not be "
            "performed: vectors/schema/ is empty in this checkout. The harness "
            "validates each vector's shape as it consumes it and fails loudly "
            "on a missing field.",
            "MANIFEST.json hashes are verified before any vector is run; a "
            "mismatch aborts the harness rather than appearing in `results`, "
            "so `summary` counts vectors only.",
            "Envelope vectors are reported twice: '<id>' is the encrypt "
            "direction (envelope, envelope_bytes, canonical_context, aad, and "
            "the stated intermediates) and '<id>#decrypt' is the decrypt "
            "direction.",
            "'<id>#pipeline' results run blind-index vectors through "
            "Fieldseal.blind_index() end to end, text-in and bytes-in, using "
            "the tenant index key recovered from the kdf/index-key vector that "
            "produced the vector's index_key.",
            "Assertion vectors (assertion: distinct|equal) carry no inputs; "
            "only the literal relation between their expected values is "
            "checked (details.reproducible = false).",
            "The context family carries no suite_id; 0xFF01 was assumed. The "
            "kdf/index-key family carries purpose 'encrypt' plus a separate "
            "index_id; the spec's purpose 'index:<id>' was constructed from "
            "both. The blind-index family names normalizer 'nfc-casefold'; it "
            "was mapped to the shipped 'nfc-casefold-v1'. See docs/18 D-05 to "
            "D-08.",
            "blind-index/argon2id.json is held out (MANIFEST.held_out) and was "
            "not iterated; it is reported as not-run. Nothing about Argon2id "
            "contributes to this report's summary.",
        ],
        "results": results,
        "held_out": held,
        "out_of_band": oob,
        "async_companions": False,
        "summary": {"pass": npass, "fail": nfail, "skipped": 0,
                    "held_out": len(held)},
    }


def main() -> int:
    report = run()
    sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    err = sys.stderr
    for r in report["results"]:
        if r["status"] != "pass":
            err.write(f"  FAIL {r['id']}: {r.get('reason', '')}\n")
    for o in report["out_of_band"]:
        if o["status"] != "pass":
            err.write(f"  OUT-OF-BAND {o['status'].upper()} {o['id']}: "
                      f"{o.get('reason', '')}\n")
    for h in report["held_out"]:
        err.write(f"  NOT RUN (held out): {h['path']}\n")
    err.write(json.dumps(report["summary"]) + "\n")
    ok = (report["summary"]["fail"] == 0
          and all(o["status"] == "pass" for o in report["out_of_band"]))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
