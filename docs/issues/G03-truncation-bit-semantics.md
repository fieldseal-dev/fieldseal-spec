# G3 — §7.2/§7.4: `truncate(raw, b bits)` bit-level semantics are undefined

**Labels:** §7.2 · §7.4 · spec-gap · blocks-vectors
**Blocks:** both `blind-index/` vector files (every truncated expected value).
**Status:** RESOLVED in spec 2026-08-08, adopted as proposed — docs/02 §7.2 (definition + justification), §7.4 (cross-reference), §12 (b mod 8 ≠ 0 vector obligation); marker sweep in docs/08 §4.4/§9, docs/09 §3.3, docs/10, docs/11. Close tracker issue [#3](https://github.com/fieldseal-dev/fieldseal-spec/issues/3) when this lands.

## Gap

§7.2 defines `blind_index = truncate(raw, b bits)` and §7.4 constrains how `b` is chosen — but not what `truncate` *does* when `b` is not a multiple of 8. Which bits survive (leading or trailing), how the final partial byte is masked, and the bit-order convention are all unstated. Two implementations disagreeing on any of these write different index values into a shared database.

## Proposed direction (starting point, not a decision)

MSB-first, leading-bits convention:

```
truncate(raw, b) = the first ceil(b/8) bytes of raw,
                   with the trailing (8·ceil(b/8) − b) bits of the final byte set to zero
```

Bits are numbered MSB-first within each byte (bit 0 = 0x80). Example: `truncate(0xAB CD EF…, 12)` = `0xAB C0`.

## Justification

Either endianness convention is cryptographically equivalent — the output of the IDF is uniform, so which `b` bits survive does not affect the §7.4 leakage analysis. The requirement is solely that **all implementations agree bit-for-bit**, which is an interoperability decision of exactly the kind `CONTRIBUTING.md` says must be pinned by vectors ("a normative change without vectors cannot be verified across implementations"). The MSB-first/leading choice is proposed because it makes the stored value a byte-prefix of the untruncated output, which simplifies debugging and matches network byte order used elsewhere in the spec (§3.1 big-endian `suite_id`, §6.2 `u64be`).

## What it breaks

Every stored blind-index value with `b mod 8 ≠ 0`. Nothing exists yet; frozen after first write per §7.8.

## Vector obligations

- `blind-index/` (both files): at least three vectors with `b mod 8 ≠ 0` (e.g., b = 12, 21, 30) pinning the surviving bits and final-byte mask, plus one `b mod 8 = 0` control.
- The vector's expected value stores the full `ceil(b/8)`-byte truncated output. G8 has since closed and made that the stored column form too (spec §7.11), so `expected.index` and `expected.stored.binary` are the same bytes — asserted separately on purpose (docs/08 §4.4).

## Review flag

No cryptographic review required; vectors pin the convention. (A reviewer may still confirm the "either convention is equivalent" claim in passing.)
