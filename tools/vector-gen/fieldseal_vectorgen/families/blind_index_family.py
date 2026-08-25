"""`blind-index/hmac-sha512.json` and `blind-index/argon2id.json` (spec §7).

File shape per docs/08 §4.4; normalizer identifiers per docs/09 §7.
"""

from __future__ import annotations

from .. import inputs as I
from ..blindindex import (ARGON2_MEMORY_KIB, ARGON2_OUTPUT_LEN,
                          ARGON2_PARALLELISM, ARGON2_TIME_COST, ARGON2_VERSION,
                          argon2_salt, idf_argon2id, idf_hmac)
from ..context import FieldContext
from ..keys import index_key
from ..normalizer import UNINDEXABLE_PREIMAGE, normalize_nfc_casefold_v1
from ..primitives import truncate
from ._common import ctx_json, suite_str, wrapper

SUITE = 0xFF01
NORMALIZER = "nfc-casefold-v1"   # docs/09 §7's versioned identifier


# (slug, preimage, truncate_bits, provisional_on)
# Spec §12 / docs/08 §4.4: at least three b mod 8 != 0 values plus one
# multiple-of-8 control. 15 is the value G3 was pinned on; 12, 21 and 30 are
# the examples docs/08 gives.
CASES = [
    ("ascii-email", "alice@example.com", 15, None),
    ("mixed-case-email", "Alice@Example.COM", 15, None),
    ("non-ascii", "grüße@example.com", 21, None),
    ("byte-aligned-16", "alice@example.com", 16, None),
    ("short-b12", "alice@example.com", 12, None),
    ("b30", "bob@example.org", 30, None),
    # U+01F0 (LATIN SMALL LETTER J WITH CARON) folds to U+006A U+030C, which
    # the second NFC recomposes to U+01F0. Pins that a normalization DOES
    # follow the fold: the stored bytes are c7 b0, not 6a cc 8c.
    ("fold-nfc-stable", "ǰ@example.com", 15, None),
    # U+A7D2 (LATIN CAPITAL LETTER DOUBLE THORN) gained its folding in
    # Unicode 17.0.0; a core folding with 16.0 tables leaves it unchanged.
    # Pins the version of the folding table.
    ("folding-added-in-17", "꟒@example.com", 15, None),
    # U+16EA0 is a Beria Erfe capital, assigned in 17.0.0. A core pinned to
    # 16.0.0 would refuse it; one pinned to 17.0.0 must index it.
    ("assigned-in-17", "\U00016ea0@example.com", 15, None),
    # U+1AD9 is a combining mark assigned in 17.0.0 with a non-zero combining
    # class, so it participates in canonical ordering. Pins NFC at 17.0.0.
    ("nfc-reordering-17", "a᫙̖@example.com", 15, None),
    # U+FFFD is an ordinary assigned character and MUST index normally. This
    # pins the alternative declined in G16 part A: a core that rejected the
    # replacement character as a data-quality signal would refuse a value
    # every other core indexes, which is a silent cross-implementation split
    # in the direction of the unfindable row.
    ("replacement-char-is-text", "a�b@example.com", 15, None),
]

# Inputs that MUST collide, or equality lookup does not work. The Greek pairs
# are the reason `nfc-casefold-v1` normalizes again after folding: folding a
# precomposed character can yield a decomposed sequence, so without the
# second pass one letter in two cases lands on two index values.
COLLISION_PAIRS = [
    ("normalizer-collapses-case", "alice@example.com", "Alice@Example.COM",
     "values differing only by case"),
    ("normalizer-collapses-fold-nfc", "ΐ@example.com", "Ϊ́@example.com",
     "U+0390 and its uppercase spelling U+03AA U+0301"),
    ("normalizer-collapses-fold-nfc-upsilon", "ΰ@example.com", "Ϋ́@example.com",
     "U+03B0 and its uppercase spelling U+03AB U+0301"),
    ("normalizer-collapses-precomposed", "ǰ@example.com", "ǰ@example.com",
     "U+01F0 and the decomposed j + U+030C"),
    ("normalizer-collapses-sharp-s", "straße@example.com", "STRASSE@example.com",
     "ß and SS under full case folding"),
]


def _vectors(index_id: str, idf_name: str, idf) -> list[dict]:
    ctx = FieldContext(suite_id=SUITE, table_uuid=I.TABLE_UUID,
                       column_uuid=I.COLUMN_UUID, purpose="encrypt",
                       tenant_id=I.TENANT_ID)
    ik = index_key(I.TENANT_INDEX_KEY, ctx, index_id)
    out = []
    for slug, preimage, b_bits, provisional_on in CASES:
        normalized = normalize_nfc_casefold_v1(preimage)
        raw = idf(ik, normalized)
        idx = truncate(raw, b_bits)
        vec = {
            "id": f"blind-index/{idf_name}/{slug}-b{b_bits}",
            "description": f"{idf_name} index over {preimage!r} truncated to "
                           f"{b_bits} bits",
            "spec_ref": "§7.2, §7.3, §7.4, §7.11",
            "suite_id": suite_str(SUITE),
            "idf": idf_name,
            "idf_params": {},
            # The normative input is index_key. tenant_index_key and context
            # are its provenance (spec §7.2), carried so a harness can run
            # the public blind_index operation end to end from this vector
            # alone instead of recovering the tenant key from kdf/.
            "index_key": ik.hex(),
            "tenant_index_key": I.TENANT_INDEX_KEY.hex(),
            "index_id": index_id,
            "context": ctx_json(ctx.for_index(index_id)),
            "normalize": NORMALIZER,
            "plaintext": normalized.hex(),
            "plaintext_preimage": preimage,
            "truncate_bits": b_bits,
            "expected": {
                "raw": raw.hex(),
                "index": idx.hex(),
                # spec §7.11: raw ceil(b/8) bytes in a binary column is the
                # MUST; declared-per-column lowercase hex is the only MAY.
                "stored": {"binary": idx.hex(), "hex": idx.hex(),
                           "octets": len(idx)},
            },
        }
        if idf_name == "argon2id":
            vec["idf_params"] = {
                "version": ARGON2_VERSION, "time_cost": ARGON2_TIME_COST,
                "memory_kib": ARGON2_MEMORY_KIB,
                "parallelism": ARGON2_PARALLELISM,
                "output_len": ARGON2_OUTPUT_LEN,
                # Asserted separately so an HKDF-step bug and an Argon2-step
                # bug are distinguishable at the point of failure.
                "salt": argon2_salt(ik).hex(),
            }
            vec["provisional_on"] = ["G2"]
        if provisional_on:
            vec["provisional_on"] = vec.get("provisional_on", []) + [provisional_on]
        out.append(vec)

    # Collision is the point of declaring a normalizer. Inputs carried (D-08).
    for slug, pre_a, pre_b, why in COLLISION_PAIRS:
        a = truncate(idf(ik, normalize_nfc_casefold_v1(pre_a)), 15)
        b = truncate(idf(ik, normalize_nfc_casefold_v1(pre_b)), 15)
        assert a == b, f"{slug}: {pre_a!r} and {pre_b!r} do not collide"
        out.append({
            "id": f"blind-index/{idf_name}/{slug}",
            "description": f"{why} MUST produce the same index under the "
                           f"{NORMALIZER} normalizer",
            "spec_ref": "§7.2",
            "assertion": "equal",
            "suite_id": suite_str(SUITE),
            "inputs": {
                "idf": idf_name,
                "index_key": ik.hex(),
                "normalize": NORMALIZER,
                "plaintext_preimage_a": pre_a,
                "plaintext_preimage_b": pre_b,
                "truncate_bits": 15,
            },
            "expected": {"index_a": a.hex(), "index_b": b.hex(),
                         "must_be_equal": True},
        })

    # docs/09 §7.2: the `on_unindexable = bucket` marker. Two cores that
    # disagree on this value put "unindexable" rows in two different buckets,
    # and a lookup across them silently returns nothing -- the exact failure
    # the setting exists to prevent, reintroduced by the fix. So the bytes are
    # pinned, not merely the behaviour.
    marker = truncate(idf(ik, UNINDEXABLE_PREIMAGE), 15)
    out.append({
        "id": f"blind-index/{idf_name}/unindexable-marker-b15",
        "description": "the docs/09 §7.2 reserved marker: "
                       "truncate(IDF(index_key, 0xFF||'fieldseal-unindexable-v1'), 15)",
        "spec_ref": "§7.2, §7.5; docs/09 §7.2",
        "assertion": "unindexable-marker",
        "suite_id": suite_str(SUITE),
        "inputs": {
            "idf": idf_name,
            "index_key": ik.hex(),
            "tenant_index_key": I.TENANT_INDEX_KEY.hex(),
            "index_id": index_id,
            "context": ctx_json(ctx.for_index(index_id)),
            "normalize": NORMALIZER,
            # Carried as hex because it is deliberately not valid UTF-8 and
            # therefore has no text form a JSON string could hold.
            "reserved_preimage": UNINDEXABLE_PREIMAGE.hex(),
            "truncate_bits": 15,
        },
        "expected": {"index": marker.hex(),
                     "stored": {"binary": marker.hex(), "hex": marker.hex(),
                                "octets": len(marker)}},
    })

    # ...and that a value the pin refuses actually lands in it. U+0378 is
    # unassigned in every Unicode version so far and encodes cleanly as UTF-8,
    # so unlike a lone surrogate it can be carried as a text preimage.
    out.append({
        "id": f"blind-index/{idf_name}/unindexable-bucketed-b15",
        "description": "under on_unindexable=bucket, a value containing a code "
                       "point the pin does not define derives the reserved "
                       "marker instead of raising INVALID_ARGUMENT",
        "spec_ref": "§7.2, §7.5, §10.2; docs/09 §7.2",
        "assertion": "unindexable-bucket",
        "suite_id": suite_str(SUITE),
        "inputs": {
            "idf": idf_name,
            "index_key": ik.hex(),
            "tenant_index_key": I.TENANT_INDEX_KEY.hex(),
            "index_id": index_id,
            "context": ctx_json(ctx.for_index(index_id)),
            "normalize": NORMALIZER,
            "on_unindexable": "bucket",
            "plaintext_preimage": "a͸b@example.com",
            "unassigned_code_point": "U+0378",
            "truncate_bits": 15,
        },
        "expected": {"index": marker.hex(), "equals_marker": True,
                     "on_unindexable_refuse": "INVALID_ARGUMENT"},
    })
    return out


def generate_hmac() -> dict:
    return wrapper("blind-index", _vectors("email-eq", "hmac-sha512", idf_hmac))


ARGON2ID_HELD_OUT = (
    "Held pending a project decision (docs/18 D-15). The generator's Argon2id "
    "primitive is checked against libsodium's seven published known answers "
    "(empty K and X) at every run, and the TypeScript core reproduces these "
    "values through an independent backend; the original ground for the "
    "hold-out is met. Counting the family is the project's call, recorded in "
    "docs/07 §7 and MANIFEST.json, not the generator's."
)


def generate_argon2id() -> dict:
    return wrapper("blind-index",
                   _vectors("ssn-eq", "argon2id", idf_argon2id),
                   held_out_reason=ARGON2ID_HELD_OUT)
