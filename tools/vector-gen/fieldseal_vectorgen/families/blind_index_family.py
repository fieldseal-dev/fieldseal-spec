"""`blind-index/hmac-sha512.json` and `blind-index/argon2id.json` (spec §7)."""

from __future__ import annotations

import unicodedata

from .. import inputs as I
from ..blindindex import (ARGON2_MEMORY_KIB, ARGON2_OUTPUT_LEN,
                          ARGON2_PARALLELISM, ARGON2_TIME_COST, ARGON2_VERSION,
                          argon2_salt, idf_argon2id, idf_hmac)
from ..context import FieldContext
from ..keys import index_key
from ..primitives import truncate
from ._common import suite_str, wrapper

SUITE = 0xFF01


def normalize_nfc_casefold(value: str) -> bytes:
    """A declared normalizer (spec §7.2). Declared per column, immutable after
    writes begin."""
    return unicodedata.normalize("NFC", value).casefold().encode("utf-8")


# b values: 15 bits exercises the non-byte-aligned path that G3 pinned.
CASES = [
    ("ascii-email", "alice@example.com", "nfc-casefold", 15),
    ("mixed-case-email", "Alice@Example.COM", "nfc-casefold", 15),
    ("non-ascii", "gr\u00fc\u00dfe@example.com", "nfc-casefold", 15),
    ("byte-aligned-16", "alice@example.com", "nfc-casefold", 16),
]


def _vectors(index_id: str, idf_name: str, idf) -> list[dict]:
    ctx = FieldContext(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                       column_uuid=I.COLUMN_UUID, purpose="encrypt",
                       tenant_id=I.TENANT_ID)
    ik = index_key(I.TENANT_INDEX_KEY, ctx, index_id)
    out = []
    for slug, value, normalizer, b_bits in CASES:
        normalized = normalize_nfc_casefold(value)
        raw = idf(ik, normalized)
        idx = truncate(raw, b_bits)
        vec = {
            "id": f"blind-index/{idf_name}/{slug}-b{b_bits}",
            "description": f"{idf_name} index over {value!r} truncated to "
                           f"{b_bits} bits",
            "spec_ref": "§7.2, §7.3, §7.4, §7.11",
            "suite_id": suite_str(SUITE),
            "index_key": ik.hex(),
            "index_id": index_id,
            "plaintext_utf8": value,
            "normalizer": normalizer,
            "b_bits": b_bits,
            "expected": {
                "normalized": normalized.hex(),
                "raw": raw.hex(),
                "blind_index": idx.hex(),
                # spec §7.11: raw ceil(b/8) bytes in a binary column is the
                # MUST; declared-per-column lowercase hex is the only MAY.
                "stored": idx.hex(),
                "stored_bytes": len(idx),
            },
        }
        if idf_name == "argon2id":
            vec["argon2_params"] = {
                "version": ARGON2_VERSION, "t": ARGON2_TIME_COST,
                "m_kib": ARGON2_MEMORY_KIB, "p": ARGON2_PARALLELISM,
                "output_len": ARGON2_OUTPUT_LEN,
            }
            # Asserted separately so an HKDF-step bug and an Argon2-step bug
            # are distinguishable at the point of failure.
            vec["expected"]["salt"] = argon2_salt(ik).hex()
        out.append(vec)

    # Case folding is the point of declaring a normalizer: these two inputs
    # must collide, or equality lookup does not work.
    a = truncate(idf(ik, normalize_nfc_casefold("alice@example.com")), 15)
    b = truncate(idf(ik, normalize_nfc_casefold("Alice@Example.COM")), 15)
    assert a == b
    out.append({
        "id": f"blind-index/{idf_name}/normalizer-collapses-case",
        "description": "values differing only by case MUST produce the same "
                       "index under the nfc-casefold normalizer",
        "spec_ref": "§7.2",
        "assertion": "equal",
        "expected": {"index_a": a.hex(), "index_b": b.hex(),
                     "must_be_equal": True},
    })
    return out


def generate_hmac() -> dict:
    return wrapper("blind-index", _vectors("email-eq", "hmac-sha512", idf_hmac))


ARGON2ID_HELD_OUT = (
    "The Argon2id primitive has not been checked against any external "
    "known-answer source. RFC 9106 §5.3's vector supplies a nonzero secret (K) "
    "and associated data (X), both forbidden by spec §7.3 and unsuppliable "
    "from Python, so it cannot serve as that check. These values are this "
    "generator's output and nothing has corroborated them."
)


def generate_argon2id() -> dict:
    return wrapper("blind-index",
                   _vectors("ssn-eq", "argon2id", idf_argon2id),
                   held_out_reason=ARGON2ID_HELD_OUT)
