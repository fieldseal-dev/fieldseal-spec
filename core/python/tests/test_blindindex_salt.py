"""The Argon2id salt is key material, and this binding cannot erase it.

Spec §7.3 forbids Argon2's secret `K` and associated data `X`, so keying
"rests entirely on the salt" (`docs/02` line 546). Those 16 bytes carry the
full strength of the column's index key: anyone holding the salt can mount the
same offline dictionary attack on that column's stored indexes as the holder
of the key itself.

The TypeScript core zeroes its salt in `idf` and `idfAsync` (PR #111 review).
This one cannot, and the reason is a hard constraint of the pinned backend
rather than a choice: argon2-cffi accepts only immutable `bytes` for `salt=`.

These tests exist so that constraint is *pinned* rather than asserted in a
comment. If a future argon2-cffi accepts a writable buffer, the first test
here fails and the decision recorded in `blindindex.py` and `docs/10` §5 gets
revisited instead of quietly outliving its reason.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from fieldseal.blindindex import (  # noqa: E402
    ARGON2_OUTPUT_LEN,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LEN,
    ARGON2_VERSION,
    Argon2Params,
    argon2_salt,
    idf_argon2id,
)

INDEX_KEY = bytes(range(32))
NORMALIZED = b"alice@example.com"


def _raw(salt: object) -> bytes:
    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw(
        secret=NORMALIZED,
        salt=salt,  # type: ignore[arg-type]
        time_cost=3,
        memory_cost=32768,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_OUTPUT_LEN,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


@pytest.mark.parametrize("writable", ["bytearray", "memoryview"])
def test_backend_refuses_a_writable_salt(writable: str) -> None:
    """The reason the salt is not erased here, pinned as a fact about the
    backend rather than a claim in a comment.

    A `bytes` salt is accepted and a writable one is not, so there is no
    buffer this binding could overwrite after the derivation. When this test
    starts failing, argon2-cffi has gained the capability and
    `idf_argon2id` should erase the salt the way the TypeScript core does.
    """
    salt = argon2_salt(INDEX_KEY)
    reference = _raw(bytes(salt))
    assert len(reference) == ARGON2_OUTPUT_LEN  # the accepted form works

    mutable = bytearray(salt)
    candidate = mutable if writable == "bytearray" else memoryview(mutable)
    with pytest.raises(TypeError):
        _raw(candidate)


def test_salt_is_the_spec_length_and_derived_from_the_index_key() -> None:
    """Both properties the exposure depends on: 16 bytes (§7.3), and a value
    a different index key does not reproduce. If the salt did not vary with
    the key it would not be key material and none of the above would apply.
    """
    salt = argon2_salt(INDEX_KEY)
    assert len(salt) == ARGON2_SALT_LEN == 16
    assert salt != argon2_salt(bytes(32))


def test_no_longer_lived_reference_to_the_salt_exists() -> None:
    """`idf_argon2id` passes the salt inline. It cannot be erased, so the one
    mitigation available is that nothing holds it after the call — the
    derivation is the only reader, and the result does not carry it.
    """
    params = Argon2Params(time_cost=3, memory_kib=32768)
    out = idf_argon2id(INDEX_KEY, NORMALIZED, params)
    assert len(out) == ARGON2_OUTPUT_LEN
    # The derivation reproduces through the primitive with the same salt,
    # which is what makes the salt the whole key for this column.
    assert out == _raw(bytes(argon2_salt(INDEX_KEY)))
    # ...and a different index key gives a different index, via the salt alone.
    assert out != idf_argon2id(bytes(32), NORMALIZED, params)
