"""Just enough AES-GCM internals to build the invisible-salamander vector.

docs/08 §4.6 asks for "a ciphertext valid under two keys", following
Len-Grubbs-Ristenpart (USENIX Security '21). GCM's tag is linear in the
ciphertext blocks under GHASH, so with two keys fixed and one ciphertext block
left free, the block that makes both tags equal is the solution of one linear
equation in GF(2^128). Nothing here is used by any other family, and nothing
here is a primitive an implementation needs: a core only ever *verifies* the
commitment that makes this attack fail.

Field arithmetic and GHASH follow NIST SP 800-38D §6.3-§6.4 (bit-reflected
representation, R = 0xE1 || 0^120). `cryptography` supplies AES.
"""

from __future__ import annotations

R = 0xE1 << 120
MASK = (1 << 128) - 1


def gf_mul(x: int, y: int) -> int:
    """SP 800-38D Algorithm 1, on 128-bit integers whose bit 127 is the
    block's first bit (the document's bit 0)."""
    z, v = 0, x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if v & 1 else v >> 1
    return z


def gf_pow(x: int, e: int) -> int:
    out, base = 1 << 127, x          # 1 << 127 is the multiplicative identity
    while e:
        if e & 1:
            out = gf_mul(out, base)
        base = gf_mul(base, base)
        e >>= 1
    return out


def gf_inv(x: int) -> int:
    if x == 0:
        raise ZeroDivisionError("no inverse of 0 in GF(2^128)")
    return gf_pow(x, (1 << 128) - 2)


def _blocks(data: bytes) -> list[int]:
    padded = data + b"\x00" * (-len(data) % 16)
    return [int.from_bytes(padded[i:i + 16], "big")
            for i in range(0, len(padded), 16)]


def ghash_blocks(aad: bytes, ct: bytes) -> list[int]:
    """The block sequence GHASH consumes: A padded, C padded, then the
    length block [len(A)]64 || [len(C)]64, lengths in bits."""
    return (_blocks(aad) + _blocks(ct)
            + [(len(aad) * 8) << 64 | (len(ct) * 8)])


def ghash(h: int, blocks: list[int]) -> int:
    y = 0
    for b in blocks:
        y = gf_mul(y ^ b, h)
    return y


def aes_block(key: bytes, block: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def hash_subkey(key: bytes) -> int:
    return int.from_bytes(aes_block(key, b"\x00" * 16), "big")


def j0(nonce: bytes) -> bytes:
    if len(nonce) != 12:
        raise ValueError("96-bit nonces only (spec §4.4)")
    return nonce + b"\x00\x00\x00\x01"


def ek_j0(key: bytes, nonce: bytes) -> int:
    return int.from_bytes(aes_block(key, j0(nonce)), "big")


def keystream(key: bytes, nonce: bytes, n_blocks: int) -> bytes:
    """GCTR keystream blocks for counters 2..n+1 (counter 1 is the tag mask)."""
    out = b""
    ctr = int.from_bytes(j0(nonce), "big")
    for i in range(n_blocks):
        ctr_i = (ctr & ~0xFFFFFFFF) | ((ctr + 1 + i) & 0xFFFFFFFF)
        out += aes_block(key, ctr_i.to_bytes(16, "big"))
    return out


def tag(key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    h = hash_subkey(key)
    t = ghash(h, ghash_blocks(aad, ct)) ^ ek_j0(key, nonce)
    return t.to_bytes(16, "big")


def salamander(key1: bytes, key2: bytes, nonce: bytes, aad: bytes,
               first_block_plaintext_under_key1: bytes) -> tuple[bytes, bytes]:
    """A two-block ciphertext and a tag that verify under both keys.

    Block 1 is chosen so that key1 decrypts it to the given plaintext; block
    2 is solved for. Under key2 both blocks decrypt to unrelated bytes -- but
    they *decrypt*, which is the whole problem a key commitment exists to
    stop (spec §4.6).

    Derivation. With blocks X_1..X_N fed to GHASH (A blocks, C blocks, the
    length block), GHASH_H = sum_j X_j * H^(N+1-j). Tags are equal iff
        GHASH_H1 ^ E_K1(J0) = GHASH_H2 ^ E_K2(J0).
    Every term except the one in the free block C_2 is fixed, so with e the
    exponent of C_2's position,
        C_2 * (H1^e ^ H2^e) = S1 ^ S2 ^ E_K1(J0) ^ E_K2(J0)
    where S_k is GHASH under H_k with C_2 zeroed. Invert and multiply.
    """
    if len(first_block_plaintext_under_key1) != 16:
        raise ValueError("one full block")
    ks1 = keystream(key1, nonce, 1)
    c1 = bytes(a ^ b for a, b in zip(first_block_plaintext_under_key1, ks1))
    h1, h2 = hash_subkey(key1), hash_subkey(key2)

    # GHASH with the free block set to zero; its position's exponent.
    blocks = ghash_blocks(aad, c1 + b"\x00" * 16)
    n = len(blocks)
    free_index = len(_blocks(aad)) + 1          # 0-based index of C_2
    e = n - free_index                          # H^(N+1-j) with j 1-based
    s1 = ghash(h1, blocks)
    s2 = ghash(h2, blocks)
    rhs = s1 ^ s2 ^ ek_j0(key1, nonce) ^ ek_j0(key2, nonce)
    coeff = gf_pow(h1, e) ^ gf_pow(h2, e)
    c2 = gf_mul(rhs, gf_inv(coeff)).to_bytes(16, "big")

    ct = c1 + c2
    t1, t2 = tag(key1, nonce, aad, ct), tag(key2, nonce, aad, ct)
    assert t1 == t2, "salamander construction failed"
    return ct, t1
