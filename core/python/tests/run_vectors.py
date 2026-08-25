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
import warnings
from pathlib import Path

os.environ.setdefault("FIELDSEAL_TEST_MODE", "1")

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "vectors"
sys.path.insert(0, str(REPO / "core" / "python" / "src"))

import fieldseal  # noqa: E402
from fieldseal import FieldContext, Fieldseal  # noqa: E402
from fieldseal import unicode as fs_unicode  # noqa: E402
from fieldseal.blindindex import (  # noqa: E402
    NORMALIZERS,
    CardinalityOverride,
    IndexDeclaration,
    idf_hmac_sha512,
    truncate,
)
from fieldseal.context import aad, canonical_context  # noqa: E402
from fieldseal.envelope import MAX_PLAINTEXT, serialize_header  # noqa: E402
from fieldseal.errors import (  # noqa: E402
    FieldsealError,
    InvalidArgument,
    LengthExceeded,
)
from fieldseal.kdf import commitment, index_key, record_key  # noqa: E402
from fieldseal.keyprovider import StaticKeyProvider  # noqa: E402
from fieldseal.testing import encrypt_with_materials  # noqa: E402

H = bytes.fromhex

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
    "api-boundary-order": (
        "encrypt/rotate: MODE_VIOLATION → SUITE_PROVISIONAL → LENGTH_EXCEEDED "
        "→ context validation (INVALID_ARGUMENT, non-§9); all before key "
        "acquisition  [D-04]"),
    "unimplemented-registered-suite": (
        "0xFF02 is registered (is_ciphertext → True) but refused at "
        "construction if allow-listed or set as write_suite "
        "(CONFIGURATION_ERROR naming G7); no §9 code is reachable for it "
        "because no client can be built that accepts it  [D-12]"),
    "commitment-construction": (
        "HKDF-SHA-512(ikm = record_key, salt = \"\", info = "
        "\"fieldseal-commit-v1\", 32), verified constant-time before AEAD "
        "open -- spec §4.6's provisional construction (written 2026-08-23 "
        "from the G1 draft; G1 stays open)  [D-01]"),
}
# Retired 2026-08-24 when issue #48 (G15) closed and the specification took
# these over: `unknown-format-version-set` → spec §3.1/§3.4/§9/§10.3,
# `rotate-in-permissive` → §11.1, `provisional-arming` → §4.8,
# `normalizer-text-over-bytes` → docs/09 §7. A pinned decision records where
# a core had to choose without text behind it; once the text exists there is
# nothing left to declare.


def _client(key_id: bytes, dek: bytes, index_key_material: bytes,
            indexes: tuple[IndexDeclaration, ...] = ()) -> Fieldseal:
    return Fieldseal(
        key_provider=StaticKeyProvider(key_id, dek, index_key_material),
        allowed_suites={0xFF01}, write_suite=0xFF01, indexes=indexes,
        # Spec §4.8: the suite is provisional, so even a harness must say so
        # explicitly to write. A harness that did not need to would be evidence
        # the gate does not work -- and `encrypt_with_materials` runs the
        # same boundary as `encrypt`, so the gate does apply here.
        arm_provisional_suites=True,
    )


def _ctx(v: dict, suite_id: int) -> FieldContext:
    return _ctx_from(v["context"], suite_id)


# The vectors pin an index's IDF, normalizer and truncation length, but carry
# no projected population -- P is a property of the deployment, not of the
# derivation the vector fixes. The harness supplies one inside the §7.4 band
# for any b >= 2: P*2^-b == 2 exactly, and sqrt(P) > 2.
def _population_for(b_bits: int) -> int:
    return 2 ** (b_bits + 1)


_HARNESS_OVERRIDE = CardinalityOverride(
    reason="vector harness", approved_by="vectors", date="2026-08-25")


def _index_decl(inp: dict, ctx: FieldContext,
                on_unindexable: str = "refuse") -> IndexDeclaration:
    return IndexDeclaration(
        table_uuid=ctx.table_uuid, column_uuid=ctx.column_uuid,
        index_id=inp["index_id"], idf=inp["idf"],
        normalize=inp["normalize"], truncate_bits=inp["truncate_bits"],
        projected_population=_population_for(inp["truncate_bits"]),
        on_unindexable=on_unindexable,
        unindexable_override=(_HARNESS_OVERRIDE
                              if on_unindexable == "bucket" else None))


def _record(results: list[dict], vid: str, ok: bool, reason: str = "",
            **details: object) -> None:
    entry: dict = {"id": vid, "status": "pass" if ok else "fail"}
    if not ok and reason:
        entry["reason"] = reason
    if details:
        entry["details"] = details
    results.append(entry)


def _suite_id(v: dict) -> int:
    return int(v["suite_id"], 16)


def _ctx_from(c: dict, suite_id: int) -> FieldContext:
    return FieldContext(
        table_uuid=H(c["table_uuid"]), column_uuid=H(c["column_uuid"]),
        purpose=c["purpose"],
        tenant_id=None if c["tenant_id"] is None else H(c["tenant_id"]),
        row_id=None if c["row_id"] is None else H(c["row_id"]),
    ).with_suite(suite_id)


# -- families -----------------------------------------------------------------

def run_context(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        sid = _suite_id(v)
        if v.get("assertion") == "distinct":
            # Suite 0.2.0 carries both inputs (docs/18 D-08): reproduce each
            # side, then check the relation.
            a = canonical_context(_ctx_from(v["inputs"]["context_a"], sid))
            b = canonical_context(_ctx_from(v["inputs"]["context_b"], sid))
            ok = (a.hex() == v["expected"]["tenant_absent"]
                  and b.hex() == v["expected"]["tenant_zero_length"]
                  and (a == b) == v["expected"]["must_be_equal"])
            _record(results, v["id"], ok)
            continue
        ctx = _ctx(v, sid)
        encoded = canonical_context(ctx)
        ok = (encoded.hex() == v["expected"]["canonical_context"]
              and ctx.presence == v["expected"]["presence"]
              and len(encoded) == v["expected"]["length"])
        _record(results, v["id"], ok)


def _index_key_from(tenant_index_key: bytes, ictx: FieldContext) -> bytes:
    """The core's index_key takes the caller's context and the index-id and
    retargets the purpose itself; a vector context already carries
    `index:<id>`. Split it back so the core does the retargeting."""
    assert ictx.purpose.startswith("index:"), ictx.purpose
    return index_key(tenant_index_key, ictx, ictx.purpose[len("index:"):])


def run_kdf(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        sid = _suite_id(v)
        if v.get("assertion") == "distinct":
            i = v["inputs"]
            if "msg_seed_a" in i:
                ctx = _ctx_from(i["context"], sid)
                a = record_key(H(i["tenant_dek"]), H(i["key_id"]),
                               H(i["msg_seed_a"]), ctx, 32)
                b = record_key(H(i["tenant_dek"]), H(i["key_id"]),
                               H(i["msg_seed_b"]), ctx, 32)
            else:
                a = _index_key_from(H(i["tenant_index_key"]),
                                    _ctx_from(i["context_a"], sid))
                b = _index_key_from(H(i["tenant_index_key"]),
                                    _ctx_from(i["context_b"], sid))
            ok = (a.hex() == v["expected"]["key_a"]
                  and b.hex() == v["expected"]["key_b"]
                  and (a == b) == v["expected"]["must_be_equal"])
            _record(results, v["id"], ok)
        elif "tenant_dek" in v:
            got = record_key(H(v["tenant_dek"]), H(v["key_id"]),
                             H(v["msg_seed"]), _ctx(v, sid), 32)
            _record(results, v["id"], got.hex() == v["expected"]["record_key"])
        else:
            # Suite 0.2.0: the context carries the index purpose itself
            # (docs/18 D-06), so it is used exactly as given.
            ctx = _ctx(v, sid)
            got = _index_key_from(H(v["tenant_index_key"]), ctx)
            ok = (got.hex() == v["expected"]["index_key"]
                  and canonical_context(ctx).hex() == v["expected"]["info"])
            _record(results, v["id"], ok)


def run_commitment(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        if v.get("assertion") == "distinct":
            a = commitment(H(v["inputs"]["record_key_a"]))
            b = commitment(H(v["inputs"]["record_key_b"]))
            ok = (a.hex() == v["expected"]["commitment_a"]
                  and b.hex() == v["expected"]["commitment_b"]
                  and (a == b) == v["expected"]["must_be_equal"])
            _record(results, v["id"], ok)
        else:
            ok = (commitment(H(v["record_key"])).hex()
                  == v["expected"]["commitment"])
            _record(results, v["id"], ok)


def _blind_index_primitive(idf: str, index_key_bytes: bytes,
                           normalized: bytes, b_bits: int) -> tuple[bytes, bytes]:
    if idf != "hmac-sha512":
        raise ValueError(f"harness runs hmac-sha512 only; got {idf}")
    raw = idf_hmac_sha512(index_key_bytes, normalized)
    return raw, truncate(raw, b_bits)


def run_blind_index(doc: dict, results: list[dict]) -> None:
    for v in doc["vectors"]:
        sid = _suite_id(v)
        if v.get("assertion") == "equal":
            i = v["inputs"]
            norm = NORMALIZERS[i["normalize"]]
            _, a = _blind_index_primitive(i["idf"], H(i["index_key"]),
                                          norm(i["plaintext_preimage_a"]),
                                          i["truncate_bits"])
            _, b = _blind_index_primitive(i["idf"], H(i["index_key"]),
                                          norm(i["plaintext_preimage_b"]),
                                          i["truncate_bits"])
            ok = (a.hex() == v["expected"]["index_a"]
                  and b.hex() == v["expected"]["index_b"]
                  and (a == b) == v["expected"]["must_be_equal"])
            _record(results, v["id"], ok)
            continue
        if v.get("assertion") == "unindexable-marker":
            # docs/09 §7.2: the reserved marker's bytes, not merely its
            # behaviour. Two cores that disagree on this value put their
            # unindexable rows in two different buckets, and a lookup across
            # them silently returns nothing.
            i = v["inputs"]
            _, got = _blind_index_primitive(i["idf"], H(i["index_key"]),
                                            H(i["reserved_preimage"]),
                                            i["truncate_bits"])
            ctx = _ctx_from(i["context"], sid)
            caller = FieldContext(
                table_uuid=ctx.table_uuid, column_uuid=ctx.column_uuid,
                purpose=f"index:{i['index_id']}", tenant_id=ctx.tenant_id)
            fs = _client(bytes(16), b"\x22" * 32, H(i["tenant_index_key"]),
                         (_index_decl(i, ctx, "bucket"),))
            api = fs.unindexable_marker(caller)
            _record(results, v["id"],
                    got.hex() == v["expected"]["index"] and api == got,
                    f"primitive {got.hex()}, api {api.hex()}, "
                    f"want {v['expected']['index']}")
            continue
        if v.get("assertion") == "unindexable-bucket":
            # ...and that a refused value actually lands in it, while the
            # default still refuses. Both halves matter: `bucket` that never
            # fires is useless, and `refuse` that stopped refusing would be a
            # silent policy change.
            i = v["inputs"]
            ctx = _ctx_from(i["context"], sid)
            caller = FieldContext(
                table_uuid=ctx.table_uuid, column_uuid=ctx.column_uuid,
                purpose=f"index:{i['index_id']}", tenant_id=ctx.tenant_id)
            key = H(i["tenant_index_key"])
            # `on_unindexable` is a property of the column (docs/09 §7.2), so
            # the two policies are two declarations, not two calls.
            bucket_fs = _client(bytes(16), b"\x22" * 32, key,
                                (_index_decl(i, ctx, "bucket"),))
            refuse_fs = _client(bytes(16), b"\x22" * 32, key,
                                (_index_decl(i, ctx, "refuse"),))
            bucketed = bucket_fs.blind_index(i["plaintext_preimage"], caller)
            try:
                refuse_fs.blind_index(i["plaintext_preimage"], caller)
                refused = "NONE"
            except InvalidArgument:
                refused = "INVALID_ARGUMENT"
            _record(results, v["id"],
                    bucketed.hex() == v["expected"]["index"]
                    and refused == v["expected"]["on_unindexable_refuse"],
                    f"bucketed {bucketed.hex()} want {v['expected']['index']}; "
                    f"refuse gave {refused}")
            continue
        # Primitive level: the vector's normalized plaintext is the normative
        # input (docs/08 §4.4); the preimage checks the shipped normalizer.
        normalized = NORMALIZERS[v["normalize"]](v["plaintext_preimage"])
        raw, stored = _blind_index_primitive(v["idf"], H(v["index_key"]),
                                             H(v["plaintext"]),
                                             v["truncate_bits"])
        exp = v["expected"]
        checks = {
            "normalizer": normalized.hex() == v["plaintext"],
            "raw": raw.hex() == exp["raw"],
            "index": stored.hex() == exp["index"],
            "stored.binary": stored.hex() == exp["stored"]["binary"],
            "stored.hex": stored.hex() == exp["stored"]["hex"],
            "stored.octets": len(stored) == exp["stored"]["octets"],
        }
        _record(results, v["id"], all(checks.values()),
                " ".join(f"{k}={ok}" for k, ok in checks.items()))
        # End to end through the public API with the tenant index key the
        # vector carries, text-in and bytes-in. Both are accepted at this
        # boundary and must agree: docs/09 §7.1 requires an index API to take
        # text, and widening the type must not fork the function.
        ctx = _ctx(v, sid)
        caller_ctx = FieldContext(
            table_uuid=ctx.table_uuid, column_uuid=ctx.column_uuid,
            purpose=f"index:{v['index_id']}", tenant_id=ctx.tenant_id,
            row_id=None)
        fs = _client(bytes(16), b"\x22" * 32, H(v["tenant_index_key"]),
                     (_index_decl(v, ctx),))
        got = fs.blind_index(v["plaintext_preimage"], caller_ctx)
        got_b = fs.blind_index(v["plaintext_preimage"].encode("utf-8"),
                               caller_ctx)
        _record(results, v["id"] + "#pipeline",
                got.hex() == exp["stored"]["binary"] and got == got_b,
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


def _errors_client(v: dict) -> Fieldseal:
    c = v["config"]
    indexes: tuple[IndexDeclaration, ...] = ()
    if "index_declaration" in v:
        d = v["index_declaration"]
        ctx = _ctx(v, _suite_id(v))
        indexes = (IndexDeclaration(
            table_uuid=ctx.table_uuid, column_uuid=ctx.column_uuid,
            index_id=d["index_id"], idf=d["idf"], normalize=d["normalize"],
            truncate_bits=d["truncate_bits"],
            projected_population=_population_for(d["truncate_bits"])),)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")     # §10.3 warns in permissive/readonly
        return Fieldseal(
            key_provider=StaticKeyProvider(
                H(v["key_id"]), H(v["tenant_dek"]),
                H(v["tenant_index_key"]) if "tenant_index_key" in v
                else b"\x22" * 32),
            allowed_suites={int(x, 16) for x in c["allowed_suites"]},
            write_suite=int(c["write_suite"], 16),
            read_mode=c["read_mode"], indexes=indexes,
            arm_provisional_suites=c["arm_provisional_suites"],
        )


def run_errors(doc: dict, results: list[dict]) -> None:
    """docs/08 §4.6. `input` is literal; `expected` is one of
    {error}, {value} (pass-through), {plaintext}, {is_ciphertext}, {index}."""
    for v in doc["vectors"]:
        op = v.get("operation", "decrypt")
        exp = v["expected"]
        try:
            fs = _errors_client(v)
            data = H(v["input"])
            ctx = _ctx(v, _suite_id(v)) if "context" in v else None
            if op == "decrypt":
                got: object = fs.decrypt(data, ctx)
            elif op == "rotate":
                got = fs.rotate(data, ctx)
            elif op == "encrypt":
                got = fs.encrypt(data, ctx)
            elif op == "is_ciphertext":
                got = fs.is_ciphertext(data)
            elif op == "blind_index":
                d = v["index_declaration"]
                got = fs.blind_index(data, ctx.for_index(d["index_id"]))
            else:
                raise ValueError(f"unknown operation {op!r}")
        except FieldsealError as exc:
            ok = exp.get("error") == exc.code
            _record(results, v["id"], ok,
                    f"expected {exp}, raised {exc.code}", raised=exc.code)
            continue
        except Exception as exc:  # noqa: BLE001
            _record(results, v["id"], False,
                    f"expected {exp}, raised non-Fieldseal {exc!r}")
            continue
        if "error" in exp:
            ok, detail = False, f"expected {exp['error']}, no error raised"
        elif "is_ciphertext" in exp:
            ok, detail = got == exp["is_ciphertext"], f"got {got!r}"
        elif "value" in exp:
            ok = (isinstance(got, (bytes, bytearray, memoryview))
                  and bytes(got).hex() == exp["value"])
            detail = "pass-through value differs"
        elif "plaintext" in exp:
            ok, detail = bytes(got).hex() == exp["plaintext"], "plaintext differs"
        elif "index" in exp:
            ok, detail = bytes(got).hex() == exp["index"], f"got {bytes(got).hex()}"
        else:
            ok, detail = False, f"unrecognized expectation {exp}"
        _record(results, v["id"], ok, detail)


RUNNERS = {
    "context/canonical.json": run_context,
    "kdf/record-key.json": run_kdf,
    "kdf/index-key.json": run_kdf,
    "commitment/ff01.json": run_commitment,
    "blind-index/hmac-sha512.json": run_blind_index,
    "envelope/ff01.json": run_envelope,
    "errors/format.json": run_errors,
    "errors/policy.json": run_errors,
    "errors/crypto.json": run_errors,
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

    # docs/09 §7.1 (G16 part A): the index boundary takes text, and refuses an
    # unpaired surrogate *distinguishably*.
    #
    # This cannot be a vector. `blind-index/` keys its input as hex bytes and
    # an unpaired surrogate has no UTF-8 encoding, so the case is
    # inexpressible in the family's shape; widening that field to text would
    # not help either, since Go string literals may not hold a surrogate value
    # and Rust's `String` is UTF-8 by invariant, so two of the five target
    # languages cannot carry the operand at all. A core in either records
    # `not-run` here rather than `pass`.
    idx_fs = _client(bytes(16), b"\x22" * 32, b"\x33" * 32, (IndexDeclaration(
        table_uuid=bytes(16), column_uuid=bytes(16), index_id="exact",
        idf="hmac-sha512", normalize="nfc-casefold-v1", truncate_bits=15,
        projected_population=_population_for(15)),))
    idx_ctx = FieldContext(table_uuid=bytes(16), column_uuid=bytes(16),
                           purpose="index:exact")

    def refuse(value: str) -> tuple[str, str]:
        try:
            idx_fs.blind_index(value, idx_ctx)
        except InvalidArgument as exc:
            return "INVALID_ARGUMENT", str(exc)
        except Exception as exc:  # noqa: BLE001
            return type(exc).__name__, str(exc)
        return "NONE", ""

    oob_id = "docs/09/7.1/lone-surrogate-refusal"
    oob_method = ("two distinct unpaired surrogates passed as text to "
                  "blind_index are both refused, with messages that name "
                  "different code points")
    high_code, high_msg = refuse("a\ud800b")
    low_code, low_msg = refuse("a\udc00b")
    if high_code != "INVALID_ARGUMENT" or low_code != "INVALID_ARGUMENT":
        out.append({"id": oob_id, "status": "fail", "method": oob_method,
                    "reason": f"expected INVALID_ARGUMENT for both, got "
                              f"{high_code} and {low_code}"})
    elif high_msg == low_msg:
        # Same outcome is not enough: an identical diagnosis leaves the two
        # values indistinguishable to the caller, which is the property the
        # refusal exists to deny them.
        out.append({"id": oob_id, "status": "fail", "method": oob_method,
                    "reason": "both surrogates produced the same message; "
                              "the refusal does not distinguish them"})
    else:
        out.append({"id": oob_id, "status": "pass", "method": oob_method})
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
    import cryptography
    from cryptography.hazmat.backends.openssl import backend as ossl
    return {
        "runtime": f"{platform.python_implementation()} "
                   f"{platform.python_version()}",
        "os": f"{sys.platform} {platform.machine()}",
        "crypto_backend": f"{ossl.openssl_version_text()} via "
                          f"pyca/cryptography {cryptography.__version__}",
        # Reported for information only: since the G15 closure
        # `nfc-casefold-v1` reads vendored tables for both normalization and
        # folding, so this core's index values do not depend on which Unicode
        # the interpreter shipped with (docs/09 §7).
        "unicode_platform": f"CPython unicodedata "
                            f"{unicodedata.unidata_version} "
                            "(not used for nfc-casefold-v1)",
        "unicode_tables": f"vendored UCD {fs_unicode.UNICODE_VERSION} "
                          "(NFC + CaseFolding C+F)",
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
            "Assertion vectors (assertion: distinct|equal) carry their inputs "
            "since suite 0.2.0; both sides are reproduced and the relation "
            "checked.",
            "errors/ vectors run each operation against a client built from "
            "the vector's config; a raised FieldsealError is matched by code, "
            "a non-Fieldseal exception is a failure. The blind_index cases "
            "pass the preimage bytes and the vector's index_declaration.",
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
