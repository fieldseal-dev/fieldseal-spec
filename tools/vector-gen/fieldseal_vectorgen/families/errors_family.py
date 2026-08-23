"""`errors/format.json`, `errors/policy.json`, `errors/crypto.json` --
the negative family of docs/08 §4.6.

Every expected outcome here is taken from the documents: spec §3.4 (recognition),
§9 (the error set), §10.3 (read modes), §4.8 (arming), and the decrypt-path
order of docs/09 §3.2 that both shipped cores declare in their conformance
reports (`pinned_decisions.decrypt-order`). Where an outcome depends on a gap
that is still open the vector says so in `provisional_on`, and the file's
`withheld` list names the cases deliberately not authored because two readings
of the text are both defensible today.

`input` is always literal bytes. `derived_from` and `mutation` are for the
reader; a harness never computes a mutation.
"""

from __future__ import annotations

from .. import inputs as I
from ..context import FieldContext, aad
from ..envelope import FMT_VER, SUITES, commitment, seal
from ..gcm import salamander
from ..keys import record_key
from ._common import ctx_json, suite_str, wrapper
from .blind_index_family import NORMALIZER, normalize_nfc_casefold_v1
from .envelope_family import generate as generate_envelopes

SUITE = 0xFF01
REGISTERED = [suite_str(0xFF01), suite_str(0xFF02)]
MIN_FF01 = 111   # 1 + 2 + 16 + 32 + 12 + 16 + 32
MIN_FF02 = 123   # 24-byte nonce
MODES = ("strict", "permissive", "readonly")


def _ctx(**kw) -> FieldContext:
    base = dict(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                column_uuid=I.COLUMN_UUID, purpose="encrypt",
                tenant_id=I.TENANT_ID)
    base.update(kw)
    return FieldContext(**base)


def _config(mode: str = "strict", *, allowed=(0xFF01,), armed: bool = True) -> dict:
    return {
        "allowed_suites": [suite_str(s) for s in allowed],
        "write_suite": suite_str(SUITE),
        "read_mode": mode,
        "registered_suites": REGISTERED,
        "arm_provisional_suites": armed,
    }


class _Basis:
    """The envelope vectors the negative cases are cut from, by id, so the
    bytes here are exactly the bytes in envelope/ff01.json."""

    def __init__(self) -> None:
        self.by_id = {v["id"]: v for v in generate_envelopes()["vectors"]}

    def envelope(self, slug: str) -> bytes:
        return bytes.fromhex(self.by_id[f"envelope/ff01/{slug}"]["expected"]["envelope"])

    def plaintext(self, slug: str) -> bytes:
        return bytes.fromhex(self.by_id[f"envelope/ff01/{slug}"]["plaintext"])

    def context(self, slug: str) -> dict:
        return self.by_id[f"envelope/ff01/{slug}"]["context"]


def _vec(group: str, slug: str, description: str, *, spec_ref: str,
         operation: str = "decrypt", config: dict, expected: dict,
         input_bytes: bytes | None = None, context: dict | None = None,
         key_id: bytes = I.KEY_ID, tenant_dek: bytes = I.TENANT_DEK,
         derived_from: str | None = None, mutation: str | None = None,
         provisional_on: list[str] | None = None, **extra) -> dict:
    vec = {
        "id": f"errors/{group}/{slug}",
        "description": description,
        "spec_ref": spec_ref,
        "suite_id": suite_str(SUITE),
        "operation": operation,
        "config": config,
        "key_id": key_id.hex(),
        "tenant_dek": tenant_dek.hex(),
    }
    if context is not None:
        vec["context"] = context
    if input_bytes is not None:
        vec["input"] = input_bytes.hex()
    if derived_from:
        vec["derived_from"] = derived_from
    if mutation:
        vec["mutation"] = mutation
    vec.update(extra)
    vec["expected"] = expected
    if provisional_on:
        vec["provisional_on"] = provisional_on
    return vec


def _flip(data: bytes, offset: int, bit: int = 0) -> bytes:
    out = bytearray(data)
    out[offset] ^= 1 << bit
    return bytes(out)


def _with_first_byte(data: bytes, b: int) -> bytes:
    return bytes([b]) + data[1:]


def _with_suite(data: bytes, suite_id: int) -> bytes:
    return data[:1] + suite_id.to_bytes(2, "big") + data[3:]


# --------------------------------------------------------------------------
# errors/format.json -- recognition (§3.4), read modes on non-envelope input
# (§10.3), and the reserved version byte (G15 part A).
# --------------------------------------------------------------------------

def generate_format() -> dict:
    basis = _Basis()
    basic = basis.envelope("basic-roundtrip")
    ctx = basis.context("basic-roundtrip")
    ref = "envelope/ff01/basic-roundtrip"
    vectors: list[dict] = []

    def not_envelope(slug: str, description: str, data: bytes, *,
                     mutation: str | None = None, derived: str | None = None,
                     modes=MODES, provisional_on=None, spec_ref="§3.4, §9, §10.3"):
        """One vector per read mode: NOT_CIPHERTEXT in strict, the literal
        input back in permissive and readonly."""
        for mode in modes:
            suffix = "" if mode == "strict" else f"-{mode}"
            expected = ({"error": "NOT_CIPHERTEXT"} if mode == "strict"
                        else {"value": data.hex()})
            vectors.append(_vec(
                "format", slug + suffix,
                description + (f" ({mode}: returned as-is, §10.3)"
                               if mode != "strict" else ""),
                spec_ref=spec_ref, config=_config(mode), expected=expected,
                input_bytes=data, context=ctx, derived_from=derived,
                mutation=mutation, provisional_on=provisional_on))

    not_envelope("empty-input", "zero-length input", b"")
    not_envelope("one-byte", "a single byte", b"A", modes=("strict",))
    not_envelope("ascii-plaintext",
                 "an unmigrated ASCII value presented as ciphertext -- the "
                 "migration-accident case", b"123-45-6789")
    not_envelope("header-only", "exactly the 51-byte header, nothing after",
                 basic[:51], derived=ref, mutation="truncate to 51 bytes",
                 modes=("strict",))

    # Truncation at every field boundary of a 120-byte envelope (docs/08 §4.6).
    for slug, length, where in [
        ("truncated-mid-key-id", 10, "mid key_id"),
        ("truncated-mid-msg-seed", 30, "mid msg_seed"),
        ("truncated-mid-nonce", 55, "mid nonce"),
        ("truncated-mid-ciphertext", 70, "mid ciphertext"),
        ("truncated-mid-tag", 85, "mid tag"),
        ("truncated-mid-commitment", 100, "mid commitment"),
        ("one-under-minimum", MIN_FF01 - 1,
         "one byte under the 111-byte 0xFF01 minimum"),
    ]:
        not_envelope(slug, f"basic-roundtrip truncated {where} "
                     f"({length} bytes, under the 0xFF01 minimum of 111)",
                     basic[:length], derived=ref,
                     mutation=f"truncate to {length} bytes",
                     modes=("strict",) if length != MIN_FF01 - 1 else MODES)

    # Truncation that recognition cannot see. A long envelope shortened by a
    # byte is still >= 111 bytes with a registered suite: it parses, and the
    # last 32 bytes -- now the tag's final byte plus 31 bytes of the real
    # commitment -- fail the commitment check. This is the honest statement
    # of what §3.4 recognition does and does not detect.
    one_kib = basis.envelope("one-kib")
    vectors.append(_vec(
        "format", "truncated-beyond-minimum",
        "one-kib envelope minus its last byte: still structurally an "
        "envelope (1134 >= 111, suite registered), so recognition passes and "
        "the damage surfaces at the commitment check, not as NOT_CIPHERTEXT",
        spec_ref="§3.4, §4.6, §9", config=_config(), input_bytes=one_kib[:-1],
        context=basis.context("one-kib"), derived_from="envelope/ff01/one-kib",
        mutation="drop the last byte",
        expected={"error": "COMMITMENT_INVALID"}))

    # fmt_ver. §3.4: an unrecognized version is not an envelope. Which bytes
    # are "reserved for a future version" rather than merely unrecognized is
    # G15 part A; the {0x02} set and the 111-byte plausibility floor are what
    # both cores declare.
    for b in (0x00, 0x03, 0xFF):
        not_envelope(f"fmt-ver-{b:02x}",
                     f"fmt_ver = 0x{b:02x} on an otherwise valid envelope -- "
                     "not a recognized version (§3.4)",
                     _with_first_byte(basic, b), derived=ref,
                     mutation=f"set byte 0 to 0x{b:02x}",
                     modes=("strict", "permissive"))
    for mode in MODES:
        suffix = "" if mode == "strict" else f"-{mode}"
        vectors.append(_vec(
            "format", "fmt-ver-02-reserved" + suffix,
            "fmt_ver = 0x02, the reserved-known-future version, at a "
            "plausible length (>= 111): UNKNOWN_FORMAT_VERSION in every read "
            "mode -- data from a newer implementation is never handed to the "
            f"application as plaintext ({mode})",
            spec_ref="§3.4, §9, §10.3", config=_config(mode),
            input_bytes=_with_first_byte(basic, 0x02), context=ctx,
            derived_from=ref, mutation="set byte 0 to 0x02",
            expected={"error": "UNKNOWN_FORMAT_VERSION"},
            provisional_on=["G15"]))
    not_envelope("fmt-ver-02-under-minimum",
                 "fmt_ver = 0x02 on a 110-byte blob: below the plausibility "
                 "floor, so not 'a newer envelope' but non-envelope input",
                 _with_first_byte(basic[:MIN_FF01 - 1], 0x02), derived=ref,
                 mutation="truncate to 110 bytes, set byte 0 to 0x02",
                 modes=("strict", "permissive"), provisional_on=["G15"])

    # suite_id: unregistered, and reserved-but-unassigned (§4.2).
    not_envelope("suite-unregistered",
                 "suite_id = 0x00FF, not in the registry -- recognition fails "
                 "(§3.4); this is not SUITE_NOT_ALLOWED",
                 _with_suite(basic, 0x00FF), derived=ref,
                 mutation="set bytes 1-2 to 00 ff", modes=("strict", "permissive"))
    not_envelope("suite-reserved-unassigned",
                 "suite_id = 0x0001, reserved but unassigned until Gate 0b "
                 "(§4.2) -- not a registered suite today",
                 _with_suite(basic, 0x0001), derived=ref,
                 mutation="set bytes 1-2 to 00 01", modes=("strict",))

    # Per-suite minimum length (docs/18 D-11): a 0xFF02-tagged blob of 115
    # bytes clears the global 111-byte floor but not 0xFF02's own 123.
    ff02_short = _with_suite(basic[:115], 0xFF02)
    not_envelope("suite-ff02-under-its-minimum",
                 "suite_id = 0xFF02 on a 115-byte blob: above the global "
                 "minimum (111) but below 0xFF02's own (123, 24-byte nonce) "
                 "-- recognition is per-suite, so not an envelope",
                 ff02_short, derived=ref,
                 mutation="truncate to 115 bytes, set bytes 1-2 to ff 02",
                 modes=("strict", "permissive"), provisional_on=["D-11"])

    # is_ciphertext, the predicate behind all of the above (§3.4).
    for slug, description, data, result, prov in [
        ("is-ciphertext-valid", "a valid envelope", basic, True, None),
        ("is-ciphertext-under-minimum", "110 bytes", basic[:MIN_FF01 - 1],
         False, None),
        ("is-ciphertext-fmt-ver-03", "fmt_ver 0x03", _with_first_byte(basic, 3),
         False, None),
        ("is-ciphertext-fmt-ver-02",
         "fmt_ver 0x02 at plausible length: false -- a future version need "
         "not keep suite_id at bytes 1-2, so the check that makes recognition "
         "trustworthy cannot run; decrypt raises UNKNOWN_FORMAT_VERSION "
         "instead (G15 part A)", _with_first_byte(basic, 2), False, ["G15"]),
        ("is-ciphertext-suite-unregistered", "suite 0x00FF",
         _with_suite(basic, 0x00FF), False, None),
        ("is-ciphertext-suite-ff02-plausible",
         "suite 0xFF02 at >= 123 bytes: registered, so true -- recognition "
         "is independent of the allow-list (§3.4)",
         _with_suite(basic + b"\x00" * 12, 0xFF02), True, None),
        ("is-ciphertext-suite-ff02-under-its-minimum",
         "suite 0xFF02 at 115 bytes: false (per-suite minimum)", ff02_short,
         False, ["D-11"]),
    ]:
        vectors.append(_vec(
            "format", slug, f"is_ciphertext over {description}",
            spec_ref="§3.4", operation="is_ciphertext", config=_config(),
            input_bytes=data, derived_from=ref,
            expected={"is_ciphertext": result}, provisional_on=prov))

    out = wrapper("errors", vectors)
    out["pinned_order"] = _PINNED_ORDER
    out["withheld"] = [
        {"case": "LENGTH_EXCEEDED on decrypt (implied plaintext over 2^31-1)",
         "why": "spec §3.5/§12 exempt it from the literal-bytes rule; "
                "docs/14 §4 out_of_band carries the substitute assertion"},
    ]
    return out


# --------------------------------------------------------------------------
# errors/policy.json -- allow-list (§4.3), key resolution (§8), read modes on
# ciphertext-producing operations (§10.3), and the arming gate (§4.8).
# --------------------------------------------------------------------------

def generate_policy() -> dict:
    basis = _Basis()
    basic = basis.envelope("basic-roundtrip")
    pt = basis.plaintext("basic-roundtrip")
    ctx = basis.context("basic-roundtrip")
    ref = "envelope/ff01/basic-roundtrip"
    vectors: list[dict] = []

    # SUITE_NOT_ALLOWED: a 0xFF02-shaped blob (24-byte nonce) of 132 bytes.
    # No real 0xFF02 envelope exists (G7), and none is needed: recognition is
    # structural, and the allow-list is consulted before any key is touched.
    ff02_shaped = (bytes([FMT_VER]) + (0xFF02).to_bytes(2, "big") + basic[3:51]
                   + bytes(range(24)) + basic[63:])
    assert len(ff02_shaped) == 51 + 24 + 9 + 16 + 32
    for mode in ("strict", "permissive"):
        suffix = "" if mode == "strict" else f"-{mode}"
        vectors.append(_vec(
            "policy", "suite-not-allowed" + suffix,
            "a recognized 0xFF02 envelope shape against a client allowing "
            "only 0xFF01: SUITE_NOT_ALLOWED -- recognition succeeded, so "
            f"there is no pass-through in {mode} (§3.4 decoupling)",
            spec_ref="§3.4, §4.3, §9", config=_config(mode),
            input_bytes=ff02_shaped, context=ctx, derived_from=ref,
            mutation="suite_id ff02, 24-byte nonce spliced in",
            expected={"error": "SUITE_NOT_ALLOWED"}))

    # KEY_UNAVAILABLE: the header names a key the provider does not have.
    # The AAD would also mismatch, but no key means nothing can be derived;
    # the pinned order puts key resolution before any cryptography.
    vectors.append(_vec(
        "policy", "key-unavailable",
        "key_id altered to one the provider cannot resolve: KEY_UNAVAILABLE "
        "before any derivation (docs/09 §3.2 step 5)",
        spec_ref="§8, §9", config=_config(), input_bytes=_flip(basic, 3),
        context=ctx, derived_from=ref, mutation="flip bit 0 of key_id byte 0",
        expected={"error": "KEY_UNAVAILABLE"}))

    # readonly: writes refused, reads and index computation permitted (G6).
    ro = _config("readonly")
    vectors.append(_vec(
        "policy", "encrypt-in-readonly",
        "encrypt() on a readonly client: MODE_VIOLATION at the API boundary",
        spec_ref="§9, §10.3", operation="encrypt", config=ro, input_bytes=pt,
        context=ctx, expected={"error": "MODE_VIOLATION"}))
    vectors.append(_vec(
        "policy", "rotate-in-readonly",
        "rotate() on a readonly client: MODE_VIOLATION, before the decrypt "
        "inside it runs (docs/09 §3.5)",
        spec_ref="§9, §10.3", operation="rotate", config=ro,
        input_bytes=basic, context=ctx, derived_from=ref,
        expected={"error": "MODE_VIOLATION"}))
    vectors.append(_vec(
        "policy", "decrypt-in-readonly",
        "decrypt() of a valid envelope on a readonly client succeeds -- the "
        "mode refuses writes, not reads (positive control)",
        spec_ref="§10.3", config=ro, input_bytes=basic, context=ctx,
        derived_from=ref, expected={"plaintext": pt.hex()}))
    vectors.append(_vec(
        "policy", "non-envelope-in-readonly",
        "non-envelope input on a readonly client is returned as-is: readonly "
        "takes permissive's pass-through (G6)",
        spec_ref="§10.3", config=ro, input_bytes=b"123-45-6789", context=ctx,
        expected={"value": b"123-45-6789".hex()}))

    # blind_index in readonly, and unarmed: both permitted. Expected value
    # is the one blind-index/hmac-sha512.json pins for the same inputs.
    preimage = "alice@example.com"
    index_decl = {"index_id": "email-eq", "idf": "hmac-sha512",
                  "normalize": NORMALIZER, "truncate_bits": 15}
    from ..blindindex import idf_hmac
    from ..keys import index_key
    from ..primitives import truncate
    ik = index_key(I.TENANT_INDEX_KEY, _ctx(), "email-eq")
    idx = truncate(idf_hmac(ik, normalize_nfc_casefold_v1(preimage)), 15)
    for slug, cfg, why in [
        ("blind-index-in-readonly", ro,
         "readonly: computing an index for a WHERE clause is not a write (G6)"),
        ("blind-index-unarmed", _config(armed=False),
         "unarmed: §4.8 gates encrypt and rotate only"),
    ]:
        vectors.append(_vec(
            "policy", slug,
            f"blind_index() succeeds {why} (positive control)",
            spec_ref="§4.8, §10.3, §7.2", operation="blind_index", config=cfg,
            input_bytes=preimage.encode(), context=ctx,
            tenant_index_key=I.TENANT_INDEX_KEY.hex(),
            index_declaration=index_decl,
            expected={"index": idx.hex()}))

    # §4.8: the arming gate.
    unarmed = _config(armed=False)
    vectors.append(_vec(
        "policy", "encrypt-unarmed",
        "encrypt() under a provisional write suite without arming: "
        "SUITE_PROVISIONAL at the API boundary, before key acquisition",
        spec_ref="§4.8, §9", operation="encrypt", config=unarmed,
        input_bytes=pt, context=ctx, expected={"error": "SUITE_PROVISIONAL"}))
    vectors.append(_vec(
        "policy", "rotate-unarmed",
        "rotate() produces ciphertext and is an encrypt for this purpose: "
        "SUITE_PROVISIONAL without arming",
        spec_ref="§4.8, §9", operation="rotate", config=unarmed,
        input_bytes=basic, context=ctx, derived_from=ref,
        expected={"error": "SUITE_PROVISIONAL"}))
    vectors.append(_vec(
        "policy", "decrypt-unarmed",
        "decrypt() needs no arming -- reading data one has already written is "
        "not what the gate exists to prevent (positive control)",
        spec_ref="§4.8", config=unarmed, input_bytes=basic, context=ctx,
        derived_from=ref, expected={"plaintext": pt.hex()}))
    vectors.append(_vec(
        "policy", "encrypt-readonly-and-unarmed",
        "encrypt() on a client that is both readonly and unarmed: "
        "MODE_VIOLATION -- the mode check precedes the arming check at the "
        "API boundary (docs/18 D-04; both cores declare this order)",
        spec_ref="§4.8, §9, §10.3", operation="encrypt",
        config=_config("readonly", armed=False), input_bytes=pt, context=ctx,
        expected={"error": "MODE_VIOLATION"}, provisional_on=["D-04"]))

    out = wrapper("errors", vectors)
    out["pinned_order"] = _PINNED_ORDER
    out["withheld"] = [
        {"case": "rotate() on non-envelope input in permissive mode",
         "why": "G15 part B: both cores encrypt it today; the issue proposes "
                "NOT_CIPHERTEXT. Authored when the issue settles, either way"},
        {"case": "a client allow-listing a registered suite it cannot perform "
                 "(0xFF02)",
         "why": "construction-time CONFIGURATION_ERROR, outside the §9 "
                "taxonomy (docs/18 D-12; G7)"},
    ]
    return out


# --------------------------------------------------------------------------
# errors/crypto.json -- the cryptographic layer: tag, commitment, context
# binding, and the salamander (§4.6).
# --------------------------------------------------------------------------

def generate_crypto() -> dict:
    basis = _Basis()
    basic = basis.envelope("basic-roundtrip")
    ctx_obj = _ctx()
    ctx = basis.context("basic-roundtrip")
    ref = "envelope/ff01/basic-roundtrip"
    vectors: list[dict] = []
    n_len = SUITES[SUITE]["nonce_len"]
    ct_start, ct_end = 51 + n_len, 51 + n_len + len(basis.plaintext("basic-roundtrip"))
    tag_start, commit_start = ct_end, ct_end + 16

    # Damage that the commitment check cannot see and the AEAD does.
    for slug, off, where in [
        ("ciphertext-bit-flip", ct_start, "ciphertext byte 0"),
        ("tag-bit-flip", tag_start, "tag byte 0"),
        ("nonce-bit-flip", 51, "nonce byte 0"),
    ]:
        vectors.append(_vec(
            "crypto", slug,
            f"bit 0 of {where} flipped: the record key and its commitment are "
            "untouched, so the commitment verifies and the AEAD open fails "
            "-- TAG_INVALID (docs/09 §3.2 step 6)",
            spec_ref="§9, §4.6", config=_config(), input_bytes=_flip(basic, off),
            context=ctx, derived_from=ref, mutation=f"flip bit 0 of {where}",
            expected={"error": "TAG_INVALID"}))

    # Damage the commitment check sees first.
    vectors.append(_vec(
        "crypto", "commitment-bit-flip",
        "bit 0 of commitment byte 0 flipped: COMMITMENT_INVALID, and the AEAD "
        "is never opened with this key",
        spec_ref="§9, §4.6", config=_config(),
        input_bytes=_flip(basic, commit_start), context=ctx, derived_from=ref,
        mutation="flip bit 0 of commitment byte 0",
        expected={"error": "COMMITMENT_INVALID"}))
    vectors.append(_vec(
        "crypto", "msg-seed-bit-flip",
        "bit 0 of msg_seed byte 0 flipped: the derived record key changes, so "
        "its commitment no longer matches -- COMMITMENT_INVALID under the "
        "pinned order (the seed is self-authenticating, §3.2; which code "
        "reports it is G5's)",
        spec_ref="§3.2, §5.3, §9", config=_config(),
        input_bytes=_flip(basic, 19), context=ctx, derived_from=ref,
        mutation="flip bit 0 of msg_seed byte 0",
        expected={"error": "COMMITMENT_INVALID"}, provisional_on=["G5"]))

    # Context mismatch. Under dual binding (§6.3) the wrong context derives
    # the wrong record key, which fails at the commitment check exactly as a
    # wrong key would. §9 cannot promise AAD_MISMATCH here; G5 owns the
    # classification, and both cores declare COMMITMENT_INVALID.
    row_env = basis.envelope("row-id-present")
    for slug, description, wrong, env, derived in [
        ("context-wrong-tenant", "decrypt under a different tenant_id",
         _ctx(tenant_id=b"tenant-0002"), basic, ref),
        ("context-wrong-column", "decrypt under a different column_uuid",
         _ctx(column_uuid=I.COLUMN_UUID_B), basic, ref),
        ("context-wrong-table", "decrypt under a different table_uuid",
         _ctx(table_uuid=I.COLUMN_UUID), basic, ref),
        ("context-row-id-added",
         "envelope written with row_id absent, decrypted with one present",
         _ctx(row_id=I.ROW_ID), basic, ref),
        ("context-row-id-dropped",
         "envelope written with row_id present, decrypted without it",
         _ctx(), row_env, "envelope/ff01/row-id-present"),
    ]:
        vectors.append(_vec(
            "crypto", slug,
            f"{description}: the record key re-derived under the wrong "
            "context does not commit to the envelope's commitment -- "
            "COMMITMENT_INVALID, indistinguishable from key confusion (G5)",
            spec_ref="§6.3, §9, §4.6", config=_config(), input_bytes=env,
            context=ctx_json(wrong), derived_from=derived,
            mutation="context altered on the decrypt side only",
            expected={"error": "COMMITMENT_INVALID"}, provisional_on=["G5"]))

    # The invisible salamander (Len-Grubbs-Ristenpart, USENIX Security '21):
    # one ciphertext and tag that AES-GCM accepts under two record keys. The
    # envelope commits to the first key; a provider holding the second key
    # derives a record key whose commitment does not match, and the decrypt
    # is refused before the AEAD -- which would otherwise have succeeded and
    # returned bytes that were never the plaintext. This is the vector that
    # shows §4.6 doing its job (docs/08 §4.6).
    vid = "errors/crypto/salamander-second-key"
    seed = I.msg_seed_for(vid)
    nonce = I.nonce_for(vid, n_len)
    rk1 = record_key(I.TENANT_DEK, I.KEY_ID, seed, ctx_obj, 32)
    rk2 = record_key(I.TENANT_DEK_B, I.KEY_ID, seed, ctx_obj, 32)
    a = aad(FMT_VER, I.KEY_ID, seed, ctx_obj)
    ct, t = salamander(rk1, rk2, nonce, a, b"SALAMANDER-BLOCK")
    env = (bytes([FMT_VER]) + SUITE.to_bytes(2, "big") + I.KEY_ID + seed
           + nonce + ct + t + commitment(rk1))
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pt_under_1 = AESGCM(rk1).decrypt(nonce, ct + t, a)
    pt_under_2 = AESGCM(rk2).decrypt(nonce, ct + t, a)   # opens -- that is the point
    assert pt_under_1[:16] == b"SALAMANDER-BLOCK" and pt_under_2 != pt_under_1
    salamander_inputs = {
        "msg_seed": seed.hex(), "nonce": nonce.hex(),
        "record_key_under_tenant_dek": rk1.hex(),
        "record_key_under_tenant_dek_b": rk2.hex(),
        "aead_output_under_second_key": pt_under_2.hex(),
    }
    vectors.append(_vec(
        "crypto", "salamander-second-key",
        "a ciphertext and tag AES-GCM accepts under two record keys; the "
        "envelope's commitment is to the first. A provider resolving the "
        "same key_id to a second tenant DEK derives the second key, its "
        "commitment does not match, and the decrypt is refused -- "
        "COMMITMENT_INVALID. Without §4.6 the AEAD would have opened and "
        "returned aead_output_under_second_key",
        spec_ref="§4.6, §9", config=_config(), input_bytes=env, context=ctx,
        tenant_dek=I.TENANT_DEK_B, mutation="constructed, not mutated: see "
        "tools/vector-gen gcm.py", salamander=salamander_inputs,
        expected={"error": "COMMITMENT_INVALID"}))
    vectors.append(_vec(
        "crypto", "salamander-committed-key",
        "the same envelope under the key it commits to decrypts (positive "
        "control); the second block is whatever the solved ciphertext block "
        "decrypts to under this key",
        spec_ref="§4.6", config=_config(), input_bytes=env, context=ctx,
        mutation="constructed: see salamander-second-key",
        salamander=salamander_inputs,
        expected={"plaintext": pt_under_1.hex()}))

    out = wrapper("errors", vectors)
    out["pinned_order"] = _PINNED_ORDER
    out["withheld"] = [
        {"case": "AAD_MISMATCH on any 0xFF01 input",
         "why": "not raisable under §6.3 dual binding: a context mismatch "
                "changes the record key and fails at the commitment check. "
                "Both cores declare this (pinned_decisions.aad-mismatch); "
                "G5 owns whether the code survives"},
        {"case": "decrypt with a wrong purpose",
         "why": "spec §5.3 constrains record-key derivation to "
                "purpose = \"encrypt\"; a decrypt under an index purpose is "
                "an API-boundary argument error, not a §9 outcome"},
    ]
    return out


_PINNED_ORDER = (
    "Expected outcomes follow the decrypt-path order of docs/09 §3.2 as "
    "declared by both shipped cores (docs/14 §4 pinned_decisions."
    "decrypt-order, 2026-08-23): recognition -> LENGTH_EXCEEDED -> "
    "SUITE_NOT_ALLOWED -> KEY_UNAVAILABLE -> per candidate: record key, "
    "constant-time commitment verify, AEAD open (TAG_INVALID) -> "
    "COMMITMENT_INVALID. Spec §9 marks the order [PROVISIONAL - G5]; vectors "
    "whose outcome depends on it carry provisional_on and regenerate if the "
    "order changes at Gate 0b."
)
